import express from "express";
import type { VisualTextExtractor } from "../consumer/scamCheckInputs.js";
import type { MediaAuthenticityPort } from "../consumer/mediaAuthenticity.js";
import type { ExposureLookupPort } from "../consumer/identityExposure.js";
import type { AccountLifecycleService } from "../platform/accountLifecycleService.js";
import { communityNetwork } from "../community/network.js";
import { registerAccountLifecycleRoutes } from "./accountLifecycleRoutes.js";
import { registerConsumerProtectionRoutes } from "./consumerProtectionRoutes.js";
import { registerMediaAuthenticityRoute } from "./mediaAuthenticityRoute.js";
import { createLocalDesktopServer } from "./localDesktopServer.js";
import { localSecurity } from "./localSecurity.js";
import { registerScamCheckRoutes } from "./scamCheckRoutes.js";

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
 * the body parser differs per bounded input type.
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
  const app = express();

  registerScamCheckRoutes(app, {
    security,
    community,
    visualTextExtractor,
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
  registerConsumerProtectionRoutes(app, {
    accountPlatform: localOptions.accountPlatform,
    deviceIdentity: localOptions.deviceIdentity,
    community,
    destinationAnalyzer: localOptions.destinationAnalyzer,
    exposureLookup,
  });

  app.use(createLocalDesktopServer({
    ...localOptions,
    security,
    community,
  }));
  return app;
}
