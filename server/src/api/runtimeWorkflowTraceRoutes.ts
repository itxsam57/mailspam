import express, { Router, type Express } from "express";
import type { RuntimeWorkflowTraceRecorder } from "../diagnostics/runtimeWorkflowTrace.js";
import { runtimeWorkflowTrace } from "../diagnostics/runtimeWorkflowTrace.js";
import type { LocalSecurityManager } from "./localSecurity.js";

export function createRuntimeWorkflowTraceRouter(options: {
  recorder: RuntimeWorkflowTraceRecorder;
}): Router {
  const router = Router();
  const recorder = options.recorder;

  router.get("/config", (_req, res) => {
    if (!recorder.enabled) {
      res.status(404).json({ error: "Runtime workflow tracing is disabled." });
      return;
    }
    res.json({
      enabled: true,
      runId: recorder.runId,
      localAuthoritative: true,
    });
  });

  router.post("/events", (req, res) => {
    if (!recorder.enabled) {
      res.status(404).json({ error: "Runtime workflow tracing is disabled." });
      return;
    }
    if (!recorder.record(req.body as Record<string, unknown>)) {
      res.status(400).json({ accepted: false, error: "Trace event did not match the privacy-safe diagnostic contract." });
      return;
    }
    res.status(202).json({ accepted: true });
  });

  router.get("/current", (req, res) => {
    if (!recorder.enabled) {
      res.status(404).json({ error: "Runtime workflow tracing is disabled." });
      return;
    }
    const rawLimit = typeof req.query.limit === "string" ? Number(req.query.limit) : 200;
    const limit = Number.isSafeInteger(rawLimit) && rawLimit > 0 ? Math.min(rawLimit, 2_000) : 200;
    res.json({
      enabled: true,
      runId: recorder.runId,
      events: recorder.readCurrent(limit),
    });
  });

  return router;
}

/**
 * The browser trace sink is developer diagnostics, not a mailbox mutation.
 * It therefore uses the protected-read boundary (session + same-origin + CSRF)
 * instead of consuming a one-time mutation nonce. The recorder itself performs
 * the second strict allowlist validation before anything reaches disk.
 */
export function registerRuntimeWorkflowTraceRoutes(app: Express, options: {
  security: LocalSecurityManager;
  recorder?: RuntimeWorkflowTraceRecorder | null;
}): void {
  const recorder = options.recorder ?? runtimeWorkflowTrace();
  if (!recorder?.enabled) return;
  app.use(
    "/api/dev/runtime-trace",
    options.security.validateLoopbackRequest,
    options.security.securityHeaders,
    options.security.redactResponses(),
    express.json({ limit: "16kb", strict: true }),
    options.security.requireProtectedRead(),
    createRuntimeWorkflowTraceRouter({ recorder }),
  );
}
