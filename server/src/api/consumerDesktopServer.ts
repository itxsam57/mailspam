import express from "express";
import type { VisualTextExtractor } from "../consumer/scamCheckInputs.js";
import type { AccountLifecycleService } from "../platform/accountLifecycleService.js";
import { communityNetwork } from "../community/network.js";
import { registerAccountLifecycleRoutes } from "./accountLifecycleRoutes.js";
import { createLocalDesktopServer } from "./localDesktopServer.js";
import { localSecurity } from "./localSecurity.js";
import { registerScamCheckRoutes } from "./scamCheckRoutes.js";

type LocalDesktopOptions = NonNullable<Parameters<typeof createLocalDesktopServer>[0]>;

export type ConsumerDesktopServerOptions = LocalDesktopOptions & {
  visualTextExtractor?: VisualTextExtractor;
  accountLifecycle?: AccountLifecycleService;
};

/**
 * Canonical user-facing desktop composition.
 *
 * Scam Check owns larger type-specific parsers and destructive profile deletion
 * owns a tiny confirmation parser, so those routes are mounted before the
 * legacy desktop API's global JSON parser. Each pre-parser surface repeats the
 * same loopback/session/origin/mutation protections explicitly.
 */
export function createConsumerDesktopServer(options: ConsumerDesktopServerOptions = {}) {
  const { visualTextExtractor, accountLifecycle, ...localOptions } = options;
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

  app.use(createLocalDesktopServer({
    ...localOptions,
    security,
    community,
  }));
  return app;
}
