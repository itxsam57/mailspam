import express, { Router, type Express } from "express";
import type { RuntimeWorkflowTraceRecorder } from "../diagnostics/runtimeWorkflowTrace.js";
import { runtimeWorkflowTrace } from "../diagnostics/runtimeWorkflowTrace.js";
import {
  createTechnicalTelemetryFromEnvironment,
  type TechnicalTelemetry,
} from "../telemetry/technicalTelemetry.js";
import type { LocalSecurityManager } from "./localSecurity.js";

export function createRuntimeWorkflowTraceRouter(options: {
  recorder: RuntimeWorkflowTraceRecorder | null;
  telemetry?: Pick<TechnicalTelemetry, "captureWorkflowTrace">;
}): Router {
  const router = Router();
  const recorder = options.recorder;

  router.get("/config", (_req, res) => {
    if (!recorder?.enabled) {
      res.json({ enabled: false, localAuthoritative: true });
      return;
    }
    res.json({
      enabled: true,
      runId: recorder.runId,
      localAuthoritative: true,
    });
  });

  router.post("/events", (req, res) => {
    if (!recorder?.enabled) {
      res.status(404).json({ error: "Runtime workflow tracing is disabled." });
      return;
    }
    if (!recorder.record(req.body as Record<string, unknown>)) {
      res.status(400).json({ accepted: false, error: "Trace event did not match the privacy-safe diagnostic contract." });
      return;
    }
    const latest = recorder.readCurrent(1)[0];
    if (latest && options.telemetry) {
      void options.telemetry.captureWorkflowTrace(latest);
    }
    res.status(202).json({ accepted: true });
  });

  router.get("/current", (req, res) => {
    if (!recorder?.enabled) {
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
 * the second strict allowlist validation before anything reaches disk. The
 * optional remote mirror revalidates the record independently and remains
 * controlled by the existing EMAIL_SHIELD_TELEMETRY opt-in.
 *
 * The protected config route remains mounted when tracing is disabled. That is
 * an availability probe only: events/current stay unavailable, while a normal
 * consumer browser can learn once that diagnostics are off and avoid a 404/429
 * request loop. Explicit null preserves this fail-soft disabled state in tests.
 */
export function registerRuntimeWorkflowTraceRoutes(app: Express, options: {
  security: LocalSecurityManager;
  recorder?: RuntimeWorkflowTraceRecorder | null;
  telemetry?: Pick<TechnicalTelemetry, "captureWorkflowTrace">;
}): void {
  const recorder = options.recorder === undefined ? runtimeWorkflowTrace() : options.recorder;
  const telemetry = recorder?.enabled
    ? (options.telemetry ?? createTechnicalTelemetryFromEnvironment())
    : undefined;
  app.use(
    "/api/dev/runtime-trace",
    options.security.validateLoopbackRequest,
    options.security.securityHeaders,
    options.security.redactResponses(),
    express.json({ limit: "16kb", strict: true }),
    options.security.requireProtectedRead(),
    createRuntimeWorkflowTraceRouter({ recorder, telemetry }),
  );
}
