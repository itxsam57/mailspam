import express from "express";
import type { VisualTextExtractor } from "../consumer/scamCheckInputs.js";
import type { MediaAuthenticityPort } from "../consumer/mediaAuthenticity.js";
import type { ExposureLookupPort } from "../consumer/identityExposure.js";
import { createRuntimeTraceHttpMiddleware } from "../diagnostics/runtimeTraceHttp.js";
import type { AccountLifecycleService } from "../platform/accountLifecycleService.js";
import { communityNetwork } from "../community/network.js";
import { registerAccountLifecycleRoutes } from "./accountLifecycleRoutes.js";
import { registerConsumerCatchTrashRoutes } from "./consumerCatchTrashRoutes.js";
import { registerConsumerProtectionRoutes } from "./consumerProtectionRoutes.js";
import { createBackgroundProtectionCoordinator } from "./backgroundProtection.js";
import { registerConsumerUnsubscribeActivityRoutes } from "./consumerUnsubscribeActivityRoutes.js";
import { registerFamilyGuardianPreferenceRoutes } from "./familyGuardianPreferenceRoutes.js";
import { registerLinkAnalysisActionRoutes } from "./linkAnalysisActions.js";
import { registerMediaAuthenticityRoute } from "./mediaAuthenticityRoute.js";
import { createLocalDesktopServer } from "./localDesktopServer.js";
import { localSecurity } from "./localSecurity.js";
import { registerRuntimeWorkflowTraceRoutes } from "./runtimeWorkflowTraceRoutes.js";
import { registerScamCheckRoutes } from "./scamCheckRoutes.js";
import { registerShoppingSafetyRoute } from "./shoppingSafetyRoute.js";

type LocalDesktopOptions = NonNullable<Parameters<typeof createLocalDesktopServer>[0]>;

export type ConsumerDesktopServerOptions = LocalDesktopOptions & {
  visualTextExtractor?: VisualTextExtractor;
  accountLifecycle?: AccountLifecycleService;
  mediaAuthenticityDetector?: MediaAuthenticityPort;
  exposureLookup?: ExposureLookupPort;
};

/**
 * Canonical user-facing desktop composition.
 *
 * Large/binary consumer analyzers are mounted before the legacy desktop API's
 * global JSON parser. The entire /api/consumer namespace still inherits the
 * same loopback/session/origin/CSRF/one-use mutation security boundary; only
 * the body parser differs per bounded input type. Message Analyze Links is also
 * mounted before the legacy endpoint so consumer execution accepts only the
 * opaque scan action token and never a browser-supplied envelope/URL list.
 */
export function createConsumerDesktopServer(options: ConsumerDesktopServerOptions = {}) {
  const {
    visualTextExtractor,
    accountLifecycle,
    mediaAuthenticityDetector,
    exposureLookup,
    ...localOptions
  } = options;
  const security = localOptions.security ?? localSecurity;
  const community = localOptions.community ?? communityNetwork;
  const backgroundProtection = localOptions.backgroundProtection
    ?? createBackgroundProtectionCoordinator(community, localOptions.accountPlatform);
  const app = express();

  // Correlation is diagnostic-only and fail-closed. It runs before route
  // composition so every protected consumer route sees one AsyncLocalStorage
  // context, but it neither authenticates requests nor reads request bodies.
  app.use(createRuntimeTraceHttpMiddleware());

  registerRuntimeWorkflowTraceRoutes(app, { security });

  registerScamCheckRoutes(app, {
    security,
    community,
    visualTextExtractor,
    destinationAnalyzer: localOptions.destinationAnalyzer,
  });

  registerLinkAnalysisActionRoutes(app, {
    security,
    destinationAnalyzer: localOptions.destinationAnalyzer,
  });

  if (accountLifecycle) {
    if (!localOptions.deviceIdentity) {
      throw new Error("Account lifecycle routes require the initialized desktop device identity.");
    }
    registerAccountLifecycleRoutes(app, {
      security,
      lifecycle: accountLifecycle,
      deviceIdentity: localOptions.deviceIdentity,
    });
  }

  app.use(
    "/api/consumer",
    security.validateLoopbackRequest,
    security.securityHeaders,
    security.redactResponses(),
    (req, res, next) => {
      if (req.method === "GET" || req.method === "HEAD") {
        security.requireProtectedRead()(req, res, next);
        return;
      }
      security.requireMutation()(req, res, next);
    },
  );

  registerMediaAuthenticityRoute(app, {
    security,
    detector: mediaAuthenticityDetector,
  });

  // The binary media route above consumes application/octet-stream itself.
  // Remaining consumer API operations are small, strictly bounded JSON.
  app.use("/api/consumer", express.json({ limit: "64kb", strict: true }));
  registerShoppingSafetyRoute(app);
  registerConsumerUnsubscribeActivityRoutes(app);
  registerConsumerCatchTrashRoutes(app);
  registerConsumerProtectionRoutes(app, {
    accountPlatform: localOptions.accountPlatform,
    deviceIdentity: localOptions.deviceIdentity,
    community,
    destinationAnalyzer: localOptions.destinationAnalyzer,
    exposureLookup,
    backgroundProtection,
  });
  if (localOptions.accountPlatform && localOptions.deviceIdentity) {
    registerFamilyGuardianPreferenceRoutes(app, {
      accountPlatform: localOptions.accountPlatform,
      deviceIdentity: localOptions.deviceIdentity,
    });
  }

  // Aggregate provider/runtime operations are an internal engineering surface.
  // The reusable local desktop server retains the privacy-safe implementation,
  // but the canonical consumer composition does not advertise that contract at
  // all unless this process was explicitly started with development entitlement.
  if (localOptions.developmentEntitlementsEnabled !== true) {
    app.use(
      "/api/operations/v1/snapshot",
      security.validateLoopbackRequest,
      security.securityHeaders,
      (_req, res) => {
        res.status(404).json({ error: "Not found." });
      },
    );
  }

  app.use(createLocalDesktopServer({
    ...localOptions,
    security,
    community,
    backgroundProtection,
  }));
  return app;
}
