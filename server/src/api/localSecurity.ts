import { randomBytes, timingSafeEqual } from "node:crypto";
import type { Request, RequestHandler, Response } from "express";

const COOKIE_NAME = "email_shield_local_session";
const SESSION_IDLE_TTL_MS = 60 * 60 * 1_000;
const SESSION_ABSOLUTE_TTL_MS = 8 * 60 * 60 * 1_000;
const NONCE_TTL_MS = 60_000;
const MAX_LIVE_NONCES = 256;
const DEFAULT_MUTATION_LIMIT = 90;
const RATE_WINDOW_MS = 60_000;

interface LocalSession {
  id: string;
  csrfToken: string;
  createdAt: number;
  lastSeenAt: number;
  nonces: Map<string, number>;
  usedActionTokens: Set<string>;
  rateEvents: Map<string, number[]>;
}

export interface DashboardSecurityContext {
  csrfToken: string;
  cspNonce: string;
}

function opaqueToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

function parseCookies(header: string | undefined): Map<string, string> {
  const parsed = new Map<string, string>();
  for (const part of String(header ?? "").split(";")) {
    const separator = part.indexOf("=");
    if (separator <= 0) continue;
    const name = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();
    if (name) parsed.set(name, value);
  }
  return parsed;
}

function constantTimeEqual(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

function isLoopbackHostname(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  return normalized === "127.0.0.1" || normalized === "localhost" || normalized === "::1";
}

function expectedOrigin(req: Request): string {
  return `${req.protocol}://${req.get("host")}`;
}

function requestOrigin(req: Request): string | null {
  const origin = req.get("origin");
  if (origin) return origin;
  const referer = req.get("referer");
  if (!referer) return null;
  try { return new URL(referer).origin; }
  catch { return null; }
}

export function redactSensitiveText(value: unknown, exactSecrets: readonly string[] = []): string {
  let text = value instanceof Error ? value.message : String(value ?? "");
  for (const secret of exactSecrets) {
    if (secret && secret.length >= 4) text = text.split(secret).join("[REDACTED]");
  }
  return text
    .replace(/\bBearer\s+[A-Za-z0-9._~+\/-]+=*/gi, "Bearer [REDACTED]")
    .replace(/\b(?:access[_-]?token|refresh[_-]?token|client[_-]?secret|app[_-]?password|password|authorization|oauth[_-]?code|code)\b\s*[:=]\s*["']?[^\s,"'&}]+/gi, (match) => `${match.split(/[:=]/, 1)[0]}=[REDACTED]`)
    .replace(/([?&](?:code|access_token|refresh_token|client_secret)=)[^&#\s]+/gi, "$1[REDACTED]")
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, "[REDACTED_JWT]");
}

export class LocalSecurityManager {
  private readonly sessions = new Map<string, LocalSession>();

  validateLoopbackRequest: RequestHandler = (req, res, next) => {
    try {
      if (req.get("x-forwarded-host") || req.get("x-forwarded-proto") || req.get("x-forwarded-for")) {
        throw new Error("Forwarded requests are not accepted by the local Email Shield server.");
      }
      const host = req.get("host");
      if (!host || /[\s,@]/.test(host)) throw new Error("A valid local Host header is required.");
      const parsed = new URL(`http://${host}`);
      if (!isLoopbackHostname(parsed.hostname)) throw new Error("Email Shield accepts only loopback Host names.");
      next();
    } catch (error) {
      res.status(421).json({ error: redactSensitiveText(error) });
    }
  };

  securityHeaders: RequestHandler = (_req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()");
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
    res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
    next();
  };

  openDashboard(req: Request, res: Response): DashboardSecurityContext {
    const now = Date.now();
    this.pruneSessions(now);
    const requestedId = parseCookies(req.get("cookie")).get(COOKIE_NAME);
    let session = requestedId ? this.sessions.get(requestedId) : undefined;
    if (!session || this.isExpired(session, now)) {
      if (requestedId) this.sessions.delete(requestedId);
      session = {
        id: opaqueToken(),
        csrfToken: opaqueToken(),
        createdAt: now,
        lastSeenAt: now,
        nonces: new Map(),
        usedActionTokens: new Set(),
        rateEvents: new Map(),
      };
      this.sessions.set(session.id, session);
    } else {
      session.lastSeenAt = now;
    }

    res.setHeader("Set-Cookie", `${COOKIE_NAME}=${session.id}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_ABSOLUTE_TTL_MS / 1000}; Priority=High`);
    res.setHeader("Cache-Control", "no-store, max-age=0");
    return { csrfToken: session.csrfToken, cspNonce: opaqueToken(24) };
  }

  requireProtectedRead(): RequestHandler {
    return (req, res, next) => {
      const session = this.requireSession(req, res);
      if (!session) return;
      const csrf = req.get("x-email-shield-csrf") ?? "";
      if (!constantTimeEqual(csrf, session.csrfToken)) {
        res.status(403).json({ error: "The local Email Shield CSRF token is missing or invalid. Reload the dashboard." });
        return;
      }
      next();
    };
  }

  requireSameOrigin(): RequestHandler {
    return (req, res, next) => {
      const fetchSite = req.get("sec-fetch-site");
      if (fetchSite && !["same-origin", "none"].includes(fetchSite)) {
        res.status(403).json({ error: "Cross-origin local requests are not permitted." });
        return;
      }
      const supplied = requestOrigin(req);
      if (!supplied || supplied !== expectedOrigin(req)) {
        res.status(403).json({ error: "The request did not originate from this Email Shield dashboard." });
        return;
      }
      next();
    };
  }

  requireScanSource(): RequestHandler {
    return (req, res, next) => {
      const session = this.requireSession(req, res);
      if (!session) return;
      const supplied = requestOrigin(req);
      if (!supplied || supplied !== expectedOrigin(req)) {
        res.status(403).json({ error: "The scan stream must be opened by this Email Shield dashboard." });
        return;
      }
      try {
        this.enforceRate(session, "scan-start", 30);
        next();
      } catch (error) {
        res.status(429).json({ error: redactSensitiveText(error) });
      }
    };
  }

  issueMutationNonce(req: Request, res: Response): void {
    const session = this.requireSession(req, res);
    if (!session) return;
    const csrf = req.get("x-email-shield-csrf") ?? "";
    if (!constantTimeEqual(csrf, session.csrfToken)) {
      res.status(403).json({ error: "The local Email Shield CSRF token is missing or invalid. Reload the dashboard." });
      return;
    }
    const supplied = requestOrigin(req);
    if (!supplied || supplied !== expectedOrigin(req)) {
      res.status(403).json({ error: "Mutation authorization can only be issued to this dashboard." });
      return;
    }
    try {
      this.enforceRate(session, "nonce-issue", 120);
      this.pruneNonces(session);
      if (session.nonces.size >= MAX_LIVE_NONCES) throw new Error("Too many unused local mutation authorizations are active.");
      const nonce = opaqueToken();
      session.nonces.set(nonce, Date.now() + NONCE_TTL_MS);
      res.setHeader("Cache-Control", "no-store");
      res.json({ nonce, expiresInMs: NONCE_TTL_MS });
    } catch (error) {
      res.status(429).json({ error: redactSensitiveText(error) });
    }
  }

  requireMutation(): RequestHandler {
    return (req, res, next) => {
      const session = this.requireSession(req, res);
      if (!session) return;
      const supplied = requestOrigin(req);
      if (!supplied || supplied !== expectedOrigin(req)) {
        res.status(403).json({ error: "The mutation did not originate from this Email Shield dashboard." });
        return;
      }
      const csrf = req.get("x-email-shield-csrf") ?? "";
      if (!constantTimeEqual(csrf, session.csrfToken)) {
        res.status(403).json({ error: "The local Email Shield CSRF token is missing or invalid. Reload the dashboard." });
        return;
      }
      const nonce = req.get("x-email-shield-nonce") ?? "";
      this.pruneNonces(session);
      const expiry = session.nonces.get(nonce);
      if (!expiry || expiry < Date.now()) {
        res.status(409).json({ error: "The local mutation authorization is missing, expired, or already used." });
        return;
      }
      session.nonces.delete(nonce);

      const actionToken = typeof req.body?.token === "string" ? req.body.token : null;
      if (actionToken && session.usedActionTokens.has(actionToken)) {
        res.status(409).json({ error: "This message action has already been used. Rescan before performing another action." });
        return;
      }

      try {
        this.enforceRate(session, "mutation", DEFAULT_MUTATION_LIMIT);
        const pathKey = req.path.split("/").slice(0, 5).join("/");
        this.enforceRate(session, `mutation:${req.method}:${pathKey}`, 30);
      } catch (error) {
        res.status(429).json({ error: redactSensitiveText(error) });
        return;
      }

      if (actionToken) {
        const originalJson = res.json.bind(res);
        res.json = ((body: unknown) => {
          const locallyApplied = Boolean(body && typeof body === "object" && "localProtected" in body && (body as { localProtected?: unknown }).localProtected === true);
          if (res.statusCode < 400 || locallyApplied) session.usedActionTokens.add(actionToken);
          return originalJson(body);
        }) as typeof res.json;
      }
      next();
    };
  }

  enforceRouteLimit(req: Request, res: Response, key: string, limit: number): boolean {
    const session = this.requireSession(req, res);
    if (!session) return false;
    try {
      this.enforceRate(session, key, limit);
      return true;
    } catch (error) {
      res.status(429).json({ error: redactSensitiveText(error) });
      return false;
    }
  }

  redactResponses(): RequestHandler {
    return (req, res, next) => {
      const exactSecrets = this.extractRequestSecrets(req.body);
      const originalJson = res.json.bind(res);
      res.json = ((body: unknown) => {
        if (res.statusCode >= 400 && body && typeof body === "object" && "error" in body) {
          const record = body as Record<string, unknown>;
          return originalJson({ ...record, error: redactSensitiveText(record.error, exactSecrets) });
        }
        return originalJson(body);
      }) as typeof res.json;

      const originalWrite = res.write.bind(res);
      res.write = ((chunk: unknown, ...args: unknown[]) => {
        const safeChunk = typeof chunk === "string" ? redactSensitiveText(chunk, exactSecrets) : chunk;
        return originalWrite(safeChunk as never, ...(args as never[]));
      }) as typeof res.write;
      next();
    };
  }

  private requireSession(req: Request, res: Response): LocalSession | null {
    const id = parseCookies(req.get("cookie")).get(COOKIE_NAME);
    const session = id ? this.sessions.get(id) : undefined;
    const now = Date.now();
    if (!session || this.isExpired(session, now)) {
      if (id) this.sessions.delete(id);
      res.status(401).json({ error: "The local Email Shield session is missing or expired. Reload the dashboard." });
      return null;
    }
    session.lastSeenAt = now;
    return session;
  }

  private isExpired(session: LocalSession, now: number): boolean {
    return now - session.lastSeenAt > SESSION_IDLE_TTL_MS || now - session.createdAt > SESSION_ABSOLUTE_TTL_MS;
  }

  private pruneSessions(now = Date.now()): void {
    for (const [id, session] of this.sessions) if (this.isExpired(session, now)) this.sessions.delete(id);
  }

  private pruneNonces(session: LocalSession): void {
    const now = Date.now();
    for (const [nonce, expiry] of session.nonces) if (expiry < now) session.nonces.delete(nonce);
  }

  private enforceRate(session: LocalSession, key: string, limit: number): void {
    const now = Date.now();
    const active = (session.rateEvents.get(key) ?? []).filter((time) => now - time < RATE_WINDOW_MS);
    if (active.length >= limit) throw new Error("The local security rate limit was reached. Wait briefly and retry.");
    active.push(now);
    session.rateEvents.set(key, active);
  }

  private extractRequestSecrets(body: unknown): string[] {
    if (!body || typeof body !== "object") return [];
    const values: string[] = [];
    const walk = (value: unknown, key = "") => {
      if (typeof value === "string" && /password|secret|token|authorization|code/i.test(key)) values.push(value);
      else if (value && typeof value === "object") {
        for (const [nestedKey, nestedValue] of Object.entries(value as Record<string, unknown>)) walk(nestedValue, nestedKey);
      }
    };
    walk(body);
    return values;
  }
}

export const localSecurity = new LocalSecurityManager();
