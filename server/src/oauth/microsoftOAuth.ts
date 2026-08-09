const MICROSOFT_LOGIN_BASE = "https://login.microsoftonline.com";
const MICROSOFT_COMMON_AUTHORITY = `${MICROSOFT_LOGIN_BASE}/common/oauth2/v2.0`;
const MICROSOFT_GRAPH_BASE = "https://graph.microsoft.com/v1.0";
const MAX_PROVIDER_RESPONSE_BYTES = 64 * 1024;
const TENANT_PATTERN = /^[A-Za-z0-9.-]{1,253}$/;

export const MICROSOFT_AUTHORIZE_ENDPOINT = `${MICROSOFT_COMMON_AUTHORITY}/authorize`;
export const MICROSOFT_TOKEN_ENDPOINT = `${MICROSOFT_COMMON_AUTHORITY}/token`;
export const MICROSOFT_OFFLINE_SCOPE = "offline_access";
export const MICROSOFT_USER_READ_SCOPE = "https://graph.microsoft.com/User.Read";
export const MICROSOFT_MAIL_READWRITE_SCOPE = "https://graph.microsoft.com/Mail.ReadWrite";
export const MICROSOFT_REQUIRED_SCOPES = [
  MICROSOFT_OFFLINE_SCOPE,
  MICROSOFT_USER_READ_SCOPE,
  MICROSOFT_MAIL_READWRITE_SCOPE,
] as const;

export interface MicrosoftTokenResult {
  accessToken: string;
  refreshToken: string;
  grantedScopes: string[];
}

export interface MicrosoftProfile {
  accountId: string;
  label: string;
}

function normalizedScope(scope: string): string {
  const lower = scope.trim().toLowerCase();
  const graphPrefix = "https://graph.microsoft.com/";
  return lower.startsWith(graphPrefix) ? lower.slice(graphPrefix.length) : lower;
}

export function microsoftScopeGranted(grantedScopes: readonly string[], requiredScope: string): boolean {
  const required = normalizedScope(requiredScope);
  return grantedScopes.some((scope) => normalizedScope(scope) === required);
}

function tokenEndpoint(tenantId?: string): string {
  const tenant = tenantId?.trim() || "common";
  if (!TENANT_PATTERN.test(tenant)) throw new Error("Microsoft tenant authority is invalid.");
  return `${MICROSOFT_LOGIN_BASE}/${tenant}/oauth2/v2.0/token`;
}

async function readBoundedText(response: Response, maximumBytes = MAX_PROVIDER_RESPONSE_BYTES): Promise<string> {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > maximumBytes) throw new Error("Microsoft OAuth response was oversized.");
      chunks.push(value);
    }
  } finally {
    await reader.cancel().catch(() => {});
  }

  const combined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(combined);
}

function parsePayload(raw: string): Record<string, unknown> {
  try {
    const value = JSON.parse(raw) as unknown;
    return value && typeof value === "object" ? value as Record<string, unknown> : {};
  } catch {
    return {};
  }
}

function grantedScopes(payload: Record<string, unknown>): string[] {
  return typeof payload.scope === "string"
    ? payload.scope.split(/\s+/).filter(Boolean)
    : [...MICROSOFT_REQUIRED_SCOPES];
}

function validateRequiredScopes(scopes: readonly string[]): void {
  for (const required of MICROSOFT_REQUIRED_SCOPES) {
    if (!microsoftScopeGranted(scopes, required)) {
      throw new Error(`Required Microsoft scope was not granted: ${required}`);
    }
  }
}

async function postToken(
  endpoint: string,
  body: URLSearchParams,
): Promise<{ response: Response; payload: Record<string, unknown> }> {
  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
    redirect: "error",
    signal: AbortSignal.timeout(20_000),
  });
  const payload = parsePayload(await readBoundedText(response));
  return { response, payload };
}

export async function exchangeMicrosoftAuthorizationCode(input: {
  clientId: string;
  code: string;
  codeVerifier: string;
  redirectUri: string;
}): Promise<MicrosoftTokenResult> {
  const body = new URLSearchParams({
    client_id: input.clientId,
    code: input.code,
    code_verifier: input.codeVerifier,
    grant_type: "authorization_code",
    redirect_uri: input.redirectUri,
    scope: MICROSOFT_REQUIRED_SCOPES.join(" "),
  });
  const { response, payload } = await postToken(MICROSOFT_TOKEN_ENDPOINT, body);
  if (!response.ok) throw new Error("Microsoft authorization-code exchange failed.");

  const accessToken = typeof payload.access_token === "string" ? payload.access_token : "";
  const refreshToken = typeof payload.refresh_token === "string" ? payload.refresh_token : "";
  const scopes = grantedScopes(payload);
  if (!accessToken) throw new Error("Microsoft did not return an access token.");
  if (!refreshToken) throw new Error("Microsoft did not return a refresh token. Confirm offline_access is allowed for the public client.");
  validateRequiredScopes(scopes);
  return { accessToken, refreshToken, grantedScopes: scopes };
}

export async function refreshMicrosoftAccessToken(input: {
  clientId: string;
  refreshToken: string;
  clientSecret?: string;
  tenantId?: string;
}): Promise<MicrosoftTokenResult> {
  const body = new URLSearchParams({
    client_id: input.clientId,
    grant_type: "refresh_token",
    refresh_token: input.refreshToken,
    scope: MICROSOFT_REQUIRED_SCOPES.join(" "),
  });
  // Legacy developer credentials may have been issued to a confidential client.
  // Guided Email Shield desktop OAuth never supplies or depends on this field.
  if (input.clientSecret?.trim()) body.set("client_secret", input.clientSecret.trim());

  const { response, payload } = await postToken(tokenEndpoint(input.tenantId), body);
  if (!response.ok) throw new Error("Microsoft refresh-token exchange failed. Reconnect the Outlook account.");

  const accessToken = typeof payload.access_token === "string" ? payload.access_token : "";
  const replacement = typeof payload.refresh_token === "string" && payload.refresh_token
    ? payload.refresh_token
    : input.refreshToken;
  const scopes = grantedScopes(payload);
  if (!accessToken) throw new Error("Microsoft did not return an access token during refresh.");
  validateRequiredScopes(scopes);
  return { accessToken, refreshToken: replacement, grantedScopes: scopes };
}

async function graphGet(accessToken: string, path: string): Promise<Response> {
  return fetch(`${MICROSOFT_GRAPH_BASE}${path}`, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/json",
    },
    redirect: "error",
    signal: AbortSignal.timeout(20_000),
  });
}

export async function validateMicrosoftMailbox(accessToken: string): Promise<MicrosoftProfile> {
  const profileResponse = await graphGet(accessToken, "/me?$select=id,displayName,mail,userPrincipalName");
  if (!profileResponse.ok) throw new Error(`Microsoft Graph profile validation failed: ${profileResponse.status}`);
  const profile = parsePayload(await readBoundedText(profileResponse));
  const accountId = typeof profile.id === "string" ? profile.id.trim() : "";
  if (!accountId) throw new Error("Microsoft Graph did not return a stable account ID.");

  const mail = typeof profile.mail === "string" ? profile.mail.trim() : "";
  const principal = typeof profile.userPrincipalName === "string" ? profile.userPrincipalName.trim() : "";
  const displayName = typeof profile.displayName === "string" ? profile.displayName.trim() : "";
  const label = mail || principal || displayName || "Microsoft Outlook";

  const inboxResponse = await graphGet(accessToken, "/me/mailFolders/inbox?$select=id");
  if (!inboxResponse.ok) throw new Error(`Microsoft Graph mailbox validation failed: ${inboxResponse.status}`);
  const inbox = parsePayload(await readBoundedText(inboxResponse));
  if (typeof inbox.id !== "string" || !inbox.id.trim()) {
    throw new Error("Microsoft Graph did not return the Inbox folder.");
  }

  return { accountId, label };
}
