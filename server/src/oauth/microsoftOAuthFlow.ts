import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { createServer as createHttpServer, type Server as HttpServer } from "node:http";
import type { AddressInfo } from "node:net";
import type { AdapterConfig } from "../api/adapterConfig.js";
import type { SessionStore } from "../api/sessionStore.js";
import {
  exchangeMicrosoftAuthorizationCode,
  MICROSOFT_AUTHORIZE_ENDPOINT,
  MICROSOFT_REQUIRED_SCOPES,
  validateMicrosoftMailbox,
  type MicrosoftProfile,
  type MicrosoftTokenResult,
} from "./microsoftOAuth.js";

const FLOW_TTL_MS = 5 * 60 * 1_000;
const TERMINAL_RETENTION_MS = 5 * 60 * 1_000;
const MAX_ACTIVE_FLOWS = 4;
const MAX_CALLBACK_URL_LENGTH = 8_192;

export interface MicrosoftOAuthRuntime {
  exchangeAuthorizationCode(input: {
    clientId: string;
    code: string;
    codeVerifier: string;
    redirectUri: string;
  }): Promise<MicrosoftTokenResult>;
  validateMailbox(accessToken: string): Promise<MicrosoftProfile>;
}

export type MicrosoftOAuthPublicStatus =
  | { status: "pending" }
  | { status: "complete"; accountId: string; provider: "outlook"; label: string }
  | { status: "error"; error: string };

type MicrosoftOAuthFailureStage = "ES-MICROSOFT-01" | "ES-MICROSOFT-02" | "ES-MICROSOFT-03";

class MicrosoftOAuthStageError extends Error {
  constructor(
    readonly stage: MicrosoftOAuthFailureStage,
    readonly publicMessage: string,
  ) {
    super(stage);
    this.name = "MicrosoftOAuthStageError";
  }
}

interface PendingFlow {
  id: string;
  state: string;
  codeVerifier: string;
  redirectUri: string;
  createdAt: number;
  expiresAt: number;
  server: HttpServer;
  status: MicrosoftOAuthPublicStatus;
  consumed: boolean;
  cleanupTimer: NodeJS.Timeout;
}

function base64UrlRandom(bytes: number): string {
  return randomBytes(bytes).toString("base64url");
}

export function createMicrosoftPkcePair(): { verifier: string; challenge: string } {
  const verifier = base64UrlRandom(64);
  const challenge = createHash("sha256").update(verifier, "ascii").digest("base64url");
  return { verifier, challenge };
}

export function buildMicrosoftAuthorizationUrl(input: {
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge: string;
}): string {
  const url = new URL(MICROSOFT_AUTHORIZE_ENDPOINT);
  url.searchParams.set("client_id", input.clientId);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("redirect_uri", input.redirectUri);
  url.searchParams.set("response_mode", "query");
  url.searchParams.set("scope", MICROSOFT_REQUIRED_SCOPES.join(" "));
  url.searchParams.set("state", input.state);
  url.searchParams.set("code_challenge", input.codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("prompt", "select_account");
  return url.toString();
}

function constantTimeEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left, "utf8");
  const rightBytes = Buffer.from(right, "utf8");
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
}

function normalizeError(error: unknown): string {
  if (error instanceof MicrosoftOAuthStageError) return error.publicMessage;
  const message = error instanceof Error ? error.message : String(error);
  if (/access[_ -]?denied/i.test(message)) return "Microsoft access was not granted.";
  if (/expired/i.test(message)) return "The Microsoft authorization request expired. Start again.";
  return "Microsoft authorization could not be completed. Start again and review the Microsoft consent screen.";
}

function callbackHtml(success: boolean, message: string): string {
  const safeMessage = message.replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[character]!);
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Email Shield Microsoft authorization</title></head><body><main><h1>${success ? "Microsoft connected" : "Microsoft connection failed"}</h1><p>${safeMessage}</p><p>You can close this tab and return to Email Shield.</p></main></body></html>`;
}

class DefaultMicrosoftOAuthRuntime implements MicrosoftOAuthRuntime {
  exchangeAuthorizationCode(input: {
    clientId: string;
    code: string;
    codeVerifier: string;
    redirectUri: string;
  }): Promise<MicrosoftTokenResult> {
    return exchangeMicrosoftAuthorizationCode(input);
  }

  validateMailbox(accessToken: string): Promise<MicrosoftProfile> {
    return validateMicrosoftMailbox(accessToken);
  }
}

export class MicrosoftOAuthFlowManager {
  private readonly flows = new Map<string, PendingFlow>();

  constructor(
    private readonly options: {
      clientId: string;
      sessionStore: SessionStore;
      runtime?: MicrosoftOAuthRuntime;
      flowTtlMs?: number;
    },
  ) {}

  configured(): boolean {
    return Boolean(this.options.clientId.trim());
  }

  async start(): Promise<{ flowId: string; authorizationUrl: string }> {
    if (!this.configured()) throw new Error("Microsoft OAuth is not configured for this Email Shield build.");
    this.prune();
    const active = [...this.flows.values()].filter((flow) => flow.status.status === "pending").length;
    if (active >= MAX_ACTIVE_FLOWS) throw new Error("Too many Microsoft authorization requests are already active.");

    const flowId = base64UrlRandom(24);
    const state = base64UrlRandom(32);
    const { verifier, challenge } = createMicrosoftPkcePair();
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
      throw new Error("Could not allocate a protected Microsoft OAuth callback port.");
    }

    // Microsoft treats localhost ports as equivalent for native loopback
    // redirects. The app registration therefore needs only http://localhost.
    const redirectUri = `http://localhost:${address.port}`;
    const ttl = this.options.flowTtlMs ?? FLOW_TTL_MS;
    const cleanupTimer = setTimeout(() => {
      const flow = this.flows.get(flowId);
      if (flow && flow.status.status === "pending") {
        flow.status = { status: "error", error: "The Microsoft authorization request expired. Start again." };
        flow.consumed = true;
        flow.server.close();
      }
    }, ttl);
    cleanupTimer.unref();

    const flow: PendingFlow = {
      id: flowId,
      state,
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
      authorizationUrl: buildMicrosoftAuthorizationUrl({
        clientId: this.options.clientId.trim(),
        redirectUri,
        state,
        codeChallenge: challenge,
      }),
    };
  }

  status(flowId: string): MicrosoftOAuthPublicStatus {
    if (!/^[A-Za-z0-9_-]{32}$/.test(flowId)) return { status: "error", error: "Unknown Microsoft authorization request." };
    const flow = this.flows.get(flowId);
    if (!flow) return { status: "error", error: "Unknown Microsoft authorization request." };
    if (flow.status.status === "pending" && Date.now() >= flow.expiresAt) {
      flow.status = { status: "error", error: "The Microsoft authorization request expired. Start again." };
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
    if (host.toLowerCase() !== expectedHost.toLowerCase()) {
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
      response.end(callbackHtml(false, "The Microsoft authorization response could not be verified."));
      return;
    }

    const providerError = callback.searchParams.get("error");
    if (providerError) {
      flow.consumed = true;
      flow.status = { status: "error", error: providerError === "access_denied" ? "Microsoft access was not granted." : "Microsoft authorization failed." };
      flow.server.close();
      response.writeHead(400, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
      response.end(callbackHtml(false, flow.status.error));
      return;
    }

    const code = callback.searchParams.get("code") ?? "";
    if (!code) {
      response.writeHead(400, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
      response.end(callbackHtml(false, "Microsoft did not return an authorization code."));
      return;
    }

    // Consume before any asynchronous provider work so concurrent replay cannot
    // redeem the same authorization code twice.
    flow.consumed = true;
    flow.server.close();

    try {
      const runtime = this.options.runtime ?? new DefaultMicrosoftOAuthRuntime();
      let tokens: MicrosoftTokenResult;
      try {
        tokens = await runtime.exchangeAuthorizationCode({
          clientId: this.options.clientId.trim(),
          code,
          codeVerifier: flow.codeVerifier,
          redirectUri: flow.redirectUri,
        });
      } catch {
        throw new MicrosoftOAuthStageError(
          "ES-MICROSOFT-01",
          "Microsoft token exchange could not be completed (ES-MICROSOFT-01). Confirm this is a public desktop/mobile app registration with http://localhost configured, then try again.",
        );
      }

      let profile: MicrosoftProfile;
      try {
        profile = await runtime.validateMailbox(tokens.accessToken);
      } catch {
        throw new MicrosoftOAuthStageError(
          "ES-MICROSOFT-02",
          "Microsoft signed in, but Outlook mailbox validation failed (ES-MICROSOFT-02). Confirm Microsoft Graph User.Read and Mail.ReadWrite are granted.",
        );
      }

      const config: AdapterConfig = {
        provider: "outlook",
        mode: "live",
        credentials: {
          clientId: this.options.clientId.trim(),
          refreshToken: tokens.refreshToken,
          accountId: profile.accountId,
        },
      };

      let session;
      try {
        session = await this.options.sessionStore.createSecured("outlook", profile.label, config);
      } catch {
        throw new MicrosoftOAuthStageError(
          "ES-MICROSOFT-03",
          "Microsoft signed in, but Email Shield could not establish protected local credential custody (ES-MICROSOFT-03).",
        );
      }

      flow.status = { status: "complete", accountId: session.id, provider: "outlook", label: session.label };
      response.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
      response.end(callbackHtml(true, "Microsoft Outlook is connected to Email Shield."));
    } catch (error) {
      const publicError = normalizeError(error);
      flow.status = { status: "error", error: publicError };
      response.writeHead(502, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
      response.end(callbackHtml(false, publicError));
    }
  }

  private prune(): void {
    const cutoff = Date.now() - TERMINAL_RETENTION_MS;
    for (const [id, flow] of this.flows) {
      if (flow.status.status !== "pending" && flow.createdAt < cutoff) {
        clearTimeout(flow.cleanupTimer);
        flow.server.close();
        this.flows.delete(id);
      }
    }
  }
}
