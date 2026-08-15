import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { createServer as createHttpServer, type Server as HttpServer } from "node:http";
import type { AddressInfo } from "node:net";
import { OAuth2Client } from "google-auth-library";
import { createAdapter, type AdapterConfig } from "../api/adapterConfig.js";
import type { SessionStore } from "../api/sessionStore.js";

const GOOGLE_AUTHORIZE_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
export const GOOGLE_GMAIL_MODIFY_SCOPE = "https://www.googleapis.com/auth/gmail.modify";
const GOOGLE_OIDC_EMAIL_SCOPE = "email";
const GOOGLE_USERINFO_EMAIL_SCOPE = "https://www.googleapis.com/auth/userinfo.email";
const GOOGLE_REQUIRED_SCOPES = ["openid", GOOGLE_OIDC_EMAIL_SCOPE, GOOGLE_GMAIL_MODIFY_SCOPE] as const;
const FLOW_TTL_MS = 5 * 60 * 1_000;
const TERMINAL_RETENTION_MS = 5 * 60 * 1_000;
const MAX_ACTIVE_FLOWS = 4;
const MAX_CALLBACK_URL_LENGTH = 8_192;
const MAX_TOKEN_RESPONSE_BYTES = 64 * 1024;

export interface GoogleOAuthIdentity {
  sub: string;
  email: string | null;
  emailVerified: boolean;
  nonce: string | null;
}

export interface GoogleOAuthTokenResult {
  refreshToken: string;
  idToken: string;
  grantedScopes: string[];
}

export interface GoogleOAuthRuntime {
  exchangeAuthorizationCode(input: {
    clientId: string;
    /** Matching Desktop OAuth client credential; never browser-supplied. */
    clientSecret?: string;
    code: string;
    codeVerifier: string;
    redirectUri: string;
  }): Promise<GoogleOAuthTokenResult>;
  verifyIdToken(input: {
    clientId: string;
    idToken: string;
  }): Promise<GoogleOAuthIdentity>;
}

export type GoogleOAuthPublicStatus =
  | { status: "pending" }
  | { status: "complete"; accountId: string; provider: "gmail"; label: string }
  | { status: "error"; error: string };

type GoogleOAuthFailureStage =
  | "ES-GOOGLE-01"
  | "ES-GOOGLE-02"
  | "ES-GOOGLE-03"
  | "ES-GOOGLE-04";

class GoogleOAuthStageError extends Error {
  constructor(
    readonly stage: GoogleOAuthFailureStage,
    readonly publicMessage: string,
  ) {
    super(stage);
    this.name = "GoogleOAuthStageError";
  }
}

interface PendingFlow {
  id: string;
  state: string;
  nonce: string;
  codeVerifier: string;
  redirectUri: string;
  createdAt: number;
  expiresAt: number;
  server: HttpServer;
  status: GoogleOAuthPublicStatus;
  consumed: boolean;
  cleanupTimer: NodeJS.Timeout;
}

function base64UrlRandom(bytes: number): string {
  return randomBytes(bytes).toString("base64url");
}

export function resolveGoogleClientSecret(explicit?: string): string {
  return explicit?.trim() || process.env.EMAIL_SHIELD_GOOGLE_CLIENT_SECRET?.trim() || "";
}

export function createPkcePair(): { verifier: string; challenge: string } {
  const verifier = base64UrlRandom(64);
  const challenge = createHash("sha256").update(verifier, "ascii").digest("base64url");
  return { verifier, challenge };
}

/** Google may canonicalize the OIDC `email` scope to userinfo.email in grants. */
export function googleScopeGranted(grantedScopes: readonly string[], requiredScope: string): boolean {
  if (requiredScope === GOOGLE_OIDC_EMAIL_SCOPE) {
    return grantedScopes.includes(GOOGLE_OIDC_EMAIL_SCOPE) ||
      grantedScopes.includes(GOOGLE_USERINFO_EMAIL_SCOPE);
  }
  return grantedScopes.includes(requiredScope);
}

export function buildGoogleAuthorizationUrl(input: {
  clientId: string;
  redirectUri: string;
  state: string;
  nonce: string;
  codeChallenge: string;
}): string {
  const url = new URL(GOOGLE_AUTHORIZE_ENDPOINT);
  url.searchParams.set("client_id", input.clientId);
  url.searchParams.set("redirect_uri", input.redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", GOOGLE_REQUIRED_SCOPES.join(" "));
  url.searchParams.set("access_type", "offline");
  url.searchParams.set("prompt", "consent");
  url.searchParams.set("state", input.state);
  url.searchParams.set("nonce", input.nonce);
  url.searchParams.set("code_challenge", input.codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");
  return url.toString();
}

function constantTimeEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left, "utf8");
  const rightBytes = Buffer.from(right, "utf8");
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
}

function normalizeError(error: unknown): string {
  if (error instanceof GoogleOAuthStageError) return error.publicMessage;
  const message = error instanceof Error ? error.message : String(error);
  if (/access[_ -]?denied/i.test(message)) return "Google access was not granted.";
  if (/scope/i.test(message)) return "Google did not grant the permissions Email Shield requires.";
  if (/expired/i.test(message)) return "The Google authorization request expired. Start again.";
  return "Google authorization could not be completed. Start again and review the Google consent screen.";
}

function callbackHtml(success: boolean, message: string): string {
  const safeMessage = message.replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[character]!);
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Email Shield Google authorization</title></head><body><main><h1>${success ? "Google connected" : "Google connection failed"}</h1><p>${safeMessage}</p><p>You can close this tab and return to Email Shield.</p></main></body></html>`;
}

async function readBoundedText(response: Response, maximumBytes: number): Promise<string> {
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
      if (total > maximumBytes) throw new Error("Google token response was oversized.");
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

export class DefaultGoogleOAuthRuntime implements GoogleOAuthRuntime {
  async exchangeAuthorizationCode(input: {
    clientId: string;
    clientSecret?: string;
    code: string;
    codeVerifier: string;
    redirectUri: string;
  }): Promise<GoogleOAuthTokenResult> {
    const clientSecret = resolveGoogleClientSecret(input.clientSecret);
    if (!clientSecret) throw new Error("Google OAuth client secret is not configured.");

    const body = new URLSearchParams({
      client_id: input.clientId,
      client_secret: clientSecret,
      code: input.code,
      code_verifier: input.codeVerifier,
      grant_type: "authorization_code",
      redirect_uri: input.redirectUri,
    });

    const response = await fetch(GOOGLE_TOKEN_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
      redirect: "error",
      signal: AbortSignal.timeout(20_000),
    });
    const raw = await readBoundedText(response, MAX_TOKEN_RESPONSE_BYTES);
    let payload: Record<string, unknown> = {};
    try { payload = JSON.parse(raw) as Record<string, unknown>; } catch {}
    if (!response.ok) throw new Error("Google authorization-code exchange failed.");

    const refreshToken = typeof payload.refresh_token === "string" ? payload.refresh_token : "";
    const idToken = typeof payload.id_token === "string" ? payload.id_token : "";
    const grantedScopes = typeof payload.scope === "string"
      ? payload.scope.split(/\s+/).filter(Boolean)
      : [];
    if (!refreshToken) throw new Error("Google did not return a refresh token.");
    if (!idToken) throw new Error("Google did not return an identity token.");
    for (const required of GOOGLE_REQUIRED_SCOPES) {
      if (!googleScopeGranted(grantedScopes, required)) {
        throw new Error(`Required Google scope was not granted: ${required}`);
      }
    }
    return { refreshToken, idToken, grantedScopes };
  }

  async verifyIdToken(input: { clientId: string; idToken: string }): Promise<GoogleOAuthIdentity> {
    const verifier = new OAuth2Client(input.clientId);
    const ticket = await verifier.verifyIdToken({ idToken: input.idToken, audience: input.clientId });
    const payload = ticket.getPayload();
    const sub = payload?.sub?.trim() ?? "";
    if (!sub) throw new Error("Google identity token did not contain a stable account subject.");
    return {
      sub,
      email: typeof payload?.email === "string" ? payload.email : null,
      emailVerified: payload?.email_verified === true,
      nonce: typeof payload?.nonce === "string" ? payload.nonce : null,
    };
  }
}

async function validateGmailProvider(config: AdapterConfig): Promise<void> {
  const adapter = createAdapter(config);
  const controller = new AbortController();
  const validationTimeout = setTimeout(() => controller.abort(), 35_000);
  try {
    await adapter.connect(controller.signal);
    await adapter.listFolders(controller.signal);
  } finally {
    clearTimeout(validationTimeout);
    await adapter.disconnect();
  }
}

export class GoogleOAuthFlowManager {
  private readonly flows = new Map<string, PendingFlow>();

  constructor(
    private readonly options: {
      clientId: string;
      clientSecret?: string;
      sessionStore: SessionStore;
      runtime?: GoogleOAuthRuntime;
      flowTtlMs?: number;
      /** Tests may replace only the provider validation seam; production uses the real Gmail adapter above. */
      validateProvider?: (config: AdapterConfig) => Promise<void>;
    },
  ) {}

  /** Consumer readiness requires the matching Desktop client pair. */
  configured(): boolean {
    return Boolean(this.options.clientId.trim() && resolveGoogleClientSecret(this.options.clientSecret));
  }

  async start(): Promise<{ flowId: string; authorizationUrl: string }> {
    // Unit/security seams may inject a fake exchange runtime and exercise the
    // loopback protocol without product credentials. The real runtime still
    // requires the matching client secret at token exchange, while the consumer
    // config endpoint stays disabled until both product credentials are present.
    if (!this.options.clientId.trim()) throw new Error("Google OAuth is not configured for this Email Shield build.");
    this.prune();
    const active = [...this.flows.values()].filter((flow) => flow.status.status === "pending").length;
    if (active >= MAX_ACTIVE_FLOWS) throw new Error("Too many Google authorization requests are already active.");

    const flowId = base64UrlRandom(24);
    const state = base64UrlRandom(32);
    const nonce = base64UrlRandom(32);
    const { verifier, challenge } = createPkcePair();
    const server = createHttpServer();

    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => {
        server.off("error", reject);
        resolve();
      });
    });
    server.unref();

    const address = server.address() as AddressInfo | null;
    if (!address || typeof address.port !== "number") {
      server.close();
      throw new Error("Could not allocate a protected Google OAuth callback port.");
    }
    const redirectUri = `http://127.0.0.1:${address.port}`;
    const ttl = this.options.flowTtlMs ?? FLOW_TTL_MS;
    const cleanupTimer = setTimeout(() => {
      const flow = this.flows.get(flowId);
      if (flow && flow.status.status === "pending") {
        flow.status = { status: "error", error: "The Google authorization request expired. Start again." };
        flow.consumed = true;
        flow.server.close();
      }
    }, ttl);
    cleanupTimer.unref();

    const flow: PendingFlow = {
      id: flowId,
      state,
      nonce,
      codeVerifier: verifier,
      redirectUri,
      createdAt: Date.now(),
      expiresAt: Date.now() + ttl,
      server,
      status: { status: "pending" },
      consumed: false,
      cleanupTimer,
    };
    this.flows.set(flowId, flow);

    server.on("request", (request, response) => {
      void this.handleCallback(flow, request.method ?? "", request.url ?? "/", request.headers.host ?? "", response);
    });

    return {
      flowId,
      authorizationUrl: buildGoogleAuthorizationUrl({
        clientId: this.options.clientId.trim(),
        redirectUri,
        state,
        nonce,
        codeChallenge: challenge,
      }),
    };
  }

  status(flowId: string): GoogleOAuthPublicStatus {
    if (!/^[A-Za-z0-9_-]{32}$/.test(flowId)) return { status: "error", error: "Unknown Google authorization request." };
    const flow = this.flows.get(flowId);
    if (!flow) return { status: "error", error: "Unknown Google authorization request." };
    if (flow.status.status === "pending" && Date.now() >= flow.expiresAt) {
      flow.status = { status: "error", error: "The Google authorization request expired. Start again." };
      flow.consumed = true;
      flow.server.close();
    }
    return structuredClone(flow.status);
  }

  close(): void {
    for (const flow of this.flows.values()) {
      clearTimeout(flow.cleanupTimer);
      flow.server.close();
    }
    this.flows.clear();
  }

  private async handleCallback(
    flow: PendingFlow,
    method: string,
    rawUrl: string,
    host: string,
    response: import("node:http").ServerResponse,
  ): Promise<void> {
    const expectedHost = new URL(flow.redirectUri).host;
    if (host !== expectedHost) {
      response.writeHead(421, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" });
      response.end("Misdirected request");
      return;
    }
    if (method !== "GET") {
      response.writeHead(405, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store", Allow: "GET" });
      response.end("Method not allowed");
      return;
    }
    if (rawUrl.length > MAX_CALLBACK_URL_LENGTH) {
      response.writeHead(414, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" });
      response.end("Callback URL is too long");
      return;
    }
    if (flow.consumed || flow.status.status !== "pending") {
      response.writeHead(409, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
      response.end(callbackHtml(false, "This authorization response has already been used."));
      return;
    }

    let callback: URL;
    try { callback = new URL(rawUrl, `${flow.redirectUri}/`); }
    catch {
      response.writeHead(400, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" });
      response.end("Invalid callback URL");
      return;
    }
    if (callback.pathname !== "/") {
      response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" });
      response.end("Not found");
      return;
    }

    const returnedState = callback.searchParams.get("state") ?? "";
    if (!returnedState || !constantTimeEqual(returnedState, flow.state)) {
      response.writeHead(400, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
      response.end(callbackHtml(false, "The authorization state was invalid. Return to Email Shield and start again."));
      return;
    }

    flow.consumed = true;
    clearTimeout(flow.cleanupTimer);
    flow.server.close();

    const providerError = callback.searchParams.get("error");
    const code = callback.searchParams.get("code") ?? "";
    if (providerError || !code) {
      flow.status = { status: "error", error: "Google access was not granted." };
      response.writeHead(400, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
      response.end(callbackHtml(false, flow.status.error));
      return;
    }

    try {
      const runtime = this.options.runtime ?? new DefaultGoogleOAuthRuntime();
      const clientSecret = resolveGoogleClientSecret(this.options.clientSecret);
      let tokens: GoogleOAuthTokenResult;
      try {
        tokens = await runtime.exchangeAuthorizationCode({
          clientId: this.options.clientId.trim(),
          clientSecret: clientSecret || undefined,
          code,
          codeVerifier: flow.codeVerifier,
          redirectUri: flow.redirectUri,
        });
      } catch {
        throw new GoogleOAuthStageError(
          "ES-GOOGLE-01",
          "Google token exchange could not be completed (ES-GOOGLE-01). Confirm the matching Desktop OAuth client ID and client secret are configured, then try again.",
        );
      }

      let identity: GoogleOAuthIdentity;
      try {
        identity = await runtime.verifyIdToken({ clientId: this.options.clientId.trim(), idToken: tokens.idToken });
        if (!identity.nonce || !constantTimeEqual(identity.nonce, flow.nonce)) throw new Error("nonce mismatch");
      } catch {
        throw new GoogleOAuthStageError(
          "ES-GOOGLE-02",
          "Google identity verification could not be completed (ES-GOOGLE-02). Start a fresh Google connection.",
        );
      }

      // The client secret belongs to the Email Shield Google application, not
      // to one mailbox. It is supplied transiently for initial Gmail validation
      // and is deliberately removed by the secure-session layer before the
      // per-mailbox live-connection descriptor is persisted. Restored sessions
      // rehydrate it from process-level application configuration when needed.
      const config: AdapterConfig = {
        provider: "gmail",
        mode: "live",
        credentials: {
          clientId: this.options.clientId.trim(),
          clientSecret: clientSecret || undefined,
          refreshToken: tokens.refreshToken,
          accountSubject: identity.sub,
        },
      };
      const label = identity.emailVerified && identity.email ? identity.email : "Gmail";
      const validateProvider = this.options.validateProvider ?? validateGmailProvider;

      let session;
      try {
        session = await this.options.sessionStore.createSecuredValidated(
          "gmail",
          label,
          config,
          async () => {
            try { await validateProvider(config); }
            catch {
              throw new GoogleOAuthStageError(
                "ES-GOOGLE-03",
                "Google signed in, but Gmail API validation failed (ES-GOOGLE-03). Confirm Gmail API is enabled for this OAuth project and gmail.modify was granted.",
              );
            }
          },
        );
      } catch (error) {
        if (error instanceof GoogleOAuthStageError) throw error;
        throw new GoogleOAuthStageError(
          "ES-GOOGLE-04",
          "Google signed in, but Email Shield could not complete protected local credential setup (ES-GOOGLE-04).",
        );
      }

      flow.status = { status: "complete", accountId: session.id, provider: "gmail", label: session.label };
      response.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
        "Referrer-Policy": "no-referrer",
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'",
      });
      response.end(callbackHtml(true, "Email Shield securely connected your Gmail account."));
    } catch (error) {
      flow.status = { status: "error", error: normalizeError(error) };
      response.writeHead(502, {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
        "Referrer-Policy": "no-referrer",
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'",
      });
      response.end(callbackHtml(false, flow.status.error));
    } finally {
      flow.codeVerifier = "";
      flow.state = "";
      flow.nonce = "";
    }
  }

  private prune(): void {
    const now = Date.now();
    for (const [id, flow] of this.flows) {
      if (flow.status.status !== "pending" && now - flow.createdAt > TERMINAL_RETENTION_MS) {
        clearTimeout(flow.cleanupTimer);
        flow.server.close();
        this.flows.delete(id);
      }
    }
  }
}
