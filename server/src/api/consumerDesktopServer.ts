import express from "express";
import type { VisualTextExtractor } from "../consumer/scamCheckInputs.js";
import { communityNetwork } from "../community/network.js";
import { createLocalDesktopServer } from "./localDesktopServer.js";
import { localSecurity } from "./localSecurity.js";
import { registerScamCheckRoutes } from "./scamCheckRoutes.js";

type LocalDesktopOptions = NonNullable<Parameters<typeof createLocalDesktopServer>[0]>;

export type ConsumerDesktopServerOptions = LocalDesktopOptions & {
  visualTextExtractor?: VisualTextExtractor;
};

/**
 * Canonical user-facing desktop composition.
 *
 * Scam Check owns larger type-specific parsers and therefore must be mounted
 * before the legacy desktop API's 64 KiB JSON parser. All other routes pass
 * through untouched to createLocalDesktopServer.
 */
export function createConsumerDesktopServer(options: ConsumerDesktopServerOptions = {}) {
  const { visualTextExtractor, ...localOptions } = options;
  const security = localOptions.security ?? localSecurity;
  const community = localOptions.community ?? communityNetwork;
  const app = express();

  registerScamCheckRoutes(app, {
    security,
    community,
    visualTextExtractor,
  });
  app.use(createLocalDesktopServer({
    ...localOptions,
    security,
    community,
  }));
  return app;
}
