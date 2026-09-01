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
import { sessionStore, type AccountSession } from "./sessionStore.js";

type LocalDesktopOptions = NonNullable<Parameters<typeof createLocalDesktopServer>[0]>;

export type ConsumerDesktopServerOptions = LocalDesktopOptions & {
  visualTextExtractor?: VisualTextExtractor;
  accountLifecycle?: AccountLifecycleService;
  mediaAuthenticityDetector?: MediaAuthenticityPort;
  exposureLookup?: ExposureLookupPort;
  accountAutomaticProtection?: (session: AccountSession) => unknown;
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
    accountAutomaticProtection,
    ...localOptions
  } = options;
  const security = localOptions.security ?? localSecurity;
  const community = localOptions.community ?? communityNetwork;
  const backgroundProtection = localOptions.backgroundProtection
    ?? createBackgroundProtectionCoordinator(community, localOptions.accountPlatform);
  const app = express();
  app.disable("x-powered-by");

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

  // The canonical consumer GET enriches the persisted schedule record with the
  // automatic provider-change runtime state. It is mounted before the reusable
  // legacy desktop server so consumers see one Continuous Protection contract;
  // direct createLocalDesktopServer consumers retain their original API shape.
  if (accountAutomaticProtection) {
    app.get(
      "/api/accounts/:id/background-protection",
      security.validateLoopbackRequest,
      security.securityHeaders,
      security.redactResponses(),
      security.requireProtectedRead(),
      (req, res) => {
        const session = sessionStore.getCanonical(req.params.id!);
        if (!session) return res.status(404).json({ error: "Unknown account" });
        try {
          res.setHeader("Cache-Control", "no-store");
          res.json({
            ...backgroundProtection.status(session.policyAccountKey),
            automaticProtection: accountAutomaticProtection(session),
          });
        } catch (error) {
          res.status(500).json({
            error: `Continuous protection status could not be read: ${error instanceof Error ? error.message : String(error)}`,
          });
        }
      },
    );
  }

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
