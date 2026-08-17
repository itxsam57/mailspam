import type { RequestHandler } from "express";
import type { CommunityNetwork } from "../community/network.js";
import type { AccountPlatformService } from "../platform/accountFamilyService.js";
import { mergeVerifiedAndFamilyIntelligence } from "../platform/familyThreatFeedAdapter.js";
import {
  createResumeScanStreamHandler,
  createScanStreamHandler,
} from "./scanStream.js";
import { sessionStore } from "./sessionStore.js";

function accountScopedCommunityView(
  community: CommunityNetwork,
  service: AccountPlatformService,
  mailboxAccountKey: string,
): CommunityNetwork {
  // scanStream uses only these three members. Keep the object per-request so
  // Family A and Family B can scan concurrently without mutating a singleton
  // community feed or leaking private-circle campaign state.
  return {
    remoteUrl: community.remoteUrl,
    getVerifiedEntries: () => mergeVerifiedAndFamilyIntelligence(
      community.getVerifiedEntries(),
      service.familyThreatSnapshot(mailboxAccountKey),
    ),
    refreshFeed: () => community.refreshFeed(),
  } as unknown as CommunityNetwork;
}

function familyAwareHandler(options: {
  community: CommunityNetwork;
  accountPlatform: AccountPlatformService;
  resume: boolean;
}): RequestHandler {
  return (req, res, next) => {
    const session = sessionStore.getCanonical(req.params.id!);
    const community = session
      ? accountScopedCommunityView(options.community, options.accountPlatform, session.policyAccountKey)
      : options.community;
    const handler = options.resume
      ? createResumeScanStreamHandler({ community })
      : createScanStreamHandler({ community });
    return handler(req, res, next);
  };
}

export function createFamilyAwareScanStreamHandler(options: {
  community: CommunityNetwork;
  accountPlatform: AccountPlatformService;
}): RequestHandler {
  return familyAwareHandler({ ...options, resume: false });
}

export function createFamilyAwareResumeScanStreamHandler(options: {
  community: CommunityNetwork;
  accountPlatform: AccountPlatformService;
}): RequestHandler {
  return familyAwareHandler({ ...options, resume: true });
}
