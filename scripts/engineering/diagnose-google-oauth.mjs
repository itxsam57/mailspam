import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";

const clientId = (process.env.EMAIL_SHIELD_GOOGLE_CLIENT_ID ?? "").trim();
if (!clientId) {
  console.error("RESULT=CONFIG_ERROR");
  console.error("DETAIL=EMAIL_SHIELD_GOOGLE_CLIENT_ID is not set in this terminal.");
  process.exit(2);
}

const GOOGLE_AUTHORIZE_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
const REQUIRED_SCOPES = [
  "openid",
  "email",
  "https://www.googleapis.com/auth/gmail.modify",
];
const SAFE_OAUTH_ERRORS = new Set([
  "invalid_request",
  "invalid_client",
  "invalid_grant",
  "unauthorized_client",
  "unsupported_grant_type",
  "invalid_scope",
  "access_denied",
  "admin_policy_enforced",
  "org_internal",
  "invalid_dpop_proof",
  "use_dpop_nonce",
]);
const SAFE_NETWORK_CODES = new Set([
  "ENOTFOUND",
  "EAI_AGAIN",
  "ETIMEDOUT",
  "ECONNRESET",
  "ECONNREFUSED",
  "CERT_HAS_EXPIRED",
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "SELF_SIGNED_CERT_IN_CHAIN",
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
]);
const MAX_RESPONSE_BYTES = 64 * 1024;
const TIMEOUT_MS = 5 * 60 * 1000;

function randomBase64Url(bytes) {
  return randomBytes(bytes).toString("base64url");
}

function constantTimeEqual(left, right) {
  const a = Buffer.from(left, "utf8");
  const b = Buffer.from(right, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

function safeOAuthError(value) {
  return typeof value === "string" && SAFE_OAUTH_ERRORS.has(value)
    ? value
    : "other_google_oauth_error";
}

function safeNetworkCode(error) {
  const code = error?.cause?.code;
  return typeof code === "string" && SAFE_NETWORK_CODES.has(code) ? code : "other_network_error";
}

function finish(server, code = 0) {
  server.close(() => {
    process.exitCode = code;
  });
}

const verifier = randomBase64Url(64);
const challenge = createHash("sha256").update(verifier, "ascii").digest("base64url");
const state = randomBase64Url(32);
const nonce = randomBase64Url(32);

const server = createServer();
server.listen(0, "127.0.0.1", () => {
  const address = server.address();
  if (!address || typeof address === "string") {
    console.error("RESULT=LOCAL_CALLBACK_ERROR");
    finish(server, 2);
    return;
  }

  const redirectUri = `http://127.0.0.1:${address.port}`;
  const authUrl = new URL(GOOGLE_AUTHORIZE_ENDPOINT);
  authUrl.searchParams.set("client_id", clientId);
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("scope", REQUIRED_SCOPES.join(" "));
  authUrl.searchParams.set("access_type", "offline");
  authUrl.searchParams.set("prompt", "consent");
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("nonce", nonce);
  authUrl.searchParams.set("code_challenge", challenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  console.log("RESULT=READY");
  console.log("Open this URL in your browser, approve access, then return to this terminal:");
  console.log(authUrl.toString());
  console.log("The diagnostic never prints or stores the authorization code, PKCE verifier, tokens, email, or Client ID.");
});

const timeout = setTimeout(() => {
  console.error("RESULT=TIMEOUT");
  finish(server, 2);
}, TIMEOUT_MS);
timeout.unref();

server.on("request", async (request, response) => {
  const address = server.address();
  if (!address || typeof address === "string") {
    response.writeHead(500, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" });
    response.end("Diagnostic callback unavailable.");
    return;
  }

  const expectedHost = `127.0.0.1:${address.port}`;
  if (request.headers.host !== expectedHost || request.method !== "GET") {
    response.writeHead(400, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" });
    response.end("Invalid diagnostic callback.");
    return;
  }

  let callback;
  try {
    callback = new URL(request.url ?? "/", `http://${expectedHost}/`);
  } catch {
    response.writeHead(400, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" });
    response.end("Invalid callback URL.");
    return;
  }

  const returnedState = callback.searchParams.get("state") ?? "";
  if (!returnedState || !constantTimeEqual(returnedState, state)) {
    console.error("RESULT=STATE_MISMATCH");
    response.writeHead(400, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" });
    response.end("Diagnostic state check failed. Return to the terminal.");
    clearTimeout(timeout);
    finish(server, 2);
    return;
  }

  const providerError = callback.searchParams.get("error");
  const code = callback.searchParams.get("code") ?? "";
  if (providerError || !code) {
    console.log("RESULT=AUTHORIZATION_REJECTED");
    console.log(`OAUTH_ERROR=${safeOAuthError(providerError)}`);
    response.writeHead(400, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" });
    response.end("Google authorization was not completed. Return to the terminal.");
    clearTimeout(timeout);
    finish(server, 1);
    return;
  }

  response.writeHead(200, {
    "Content-Type": "text/plain; charset=utf-8",
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
  });
  response.end("Google returned to the local diagnostic. Token exchange is being checked. Return to the terminal.");

  const redirectUri = `http://${expectedHost}`;
  const body = new URLSearchParams({
    client_id: clientId,
    code,
    code_verifier: verifier,
    grant_type: "authorization_code",
    redirect_uri: redirectUri,
  });

  try {
    const tokenResponse = await fetch(GOOGLE_TOKEN_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
      redirect: "error",
      signal: AbortSignal.timeout(20_000),
    });

    const raw = await tokenResponse.text();
    if (Buffer.byteLength(raw, "utf8") > MAX_RESPONSE_BYTES) {
      console.log(`TOKEN_HTTP=${tokenResponse.status}`);
      console.log("RESULT=OVERSIZED_TOKEN_RESPONSE");
      clearTimeout(timeout);
      finish(server, 1);
      return;
    }

    let payload = {};
    try {
      payload = JSON.parse(raw);
    } catch {
      console.log(`TOKEN_HTTP=${tokenResponse.status}`);
      console.log("RESULT=NON_JSON_TOKEN_RESPONSE");
      clearTimeout(timeout);
      finish(server, 1);
      return;
    }

    console.log(`TOKEN_HTTP=${tokenResponse.status}`);

    if (!tokenResponse.ok) {
      console.log("RESULT=TOKEN_EXCHANGE_REJECTED");
      console.log(`OAUTH_ERROR=${safeOAuthError(payload?.error)}`);
      clearTimeout(timeout);
      finish(server, 1);
      return;
    }

    const scopes = typeof payload.scope === "string"
      ? payload.scope.split(/\s+/).filter(Boolean)
      : [];
    const emailScopeGranted = scopes.includes("email") || scopes.includes("https://www.googleapis.com/auth/userinfo.email");

    console.log("RESULT=TOKEN_EXCHANGE_SUCCEEDED");
    console.log(`HAS_REFRESH_TOKEN=${typeof payload.refresh_token === "string" && payload.refresh_token.length > 0}`);
    console.log(`HAS_ID_TOKEN=${typeof payload.id_token === "string" && payload.id_token.length > 0}`);
    console.log(`HAS_SCOPE_FIELD=${typeof payload.scope === "string"}`);
    console.log(`OPENID_GRANTED=${scopes.includes("openid")}`);
    console.log(`EMAIL_GRANTED=${emailScopeGranted}`);
    console.log(`GMAIL_MODIFY_GRANTED=${scopes.includes("https://www.googleapis.com/auth/gmail.modify")}`);
    console.log("No returned credential or identity value was printed or persisted.");
    clearTimeout(timeout);
    finish(server, 0);
  } catch (error) {
    console.log("RESULT=TOKEN_NETWORK_FAILURE");
    console.log(`NETWORK_CODE=${safeNetworkCode(error)}`);
    clearTimeout(timeout);
    finish(server, 1);
  }
});
