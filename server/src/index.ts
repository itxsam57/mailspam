import { initializeDefaultPersonalPolicyRepository } from "./api/defaultPolicyRepository.js";
import { initializeDefaultScanStateRepository } from "./api/defaultScanStateRepository.js";
import { initializeDefaultRelationshipHistoryRepository } from "./api/defaultRelationshipHistoryRepository.js";
import { initializeDefaultBackgroundProtectionRepository } from "./api/defaultBackgroundProtectionRepository.js";
import {
  BackgroundProtectionCoordinator,
  WorkerBackgroundProtectionExecutor,
} from "./api/backgroundProtection.js";
import { createConsumerDesktopServer } from "./api/consumerDesktopServer.js";
import { createDefaultLiveConnectionPersistence } from "./api/liveConnectionPersistence.js";
import { communityNetwork } from "./community/network.js";
import { ensureManagedDataDirectory } from "./security/managedDataDirectory.js";
import { getRuntimeCredentialVault } from "./security/credentialVaultFactory.js";
import { defaultEmailShieldDataDirectory } from "./security/dataDirectory.js";
import { FileFixtureConnectionPersistence } from "./api/fixtureConnectionPersistence.js";
import { sessionStore } from "./api/sessionStore.js";
import {
  getAccountLifecycleService,
  getAccountPlatformService,
  getDesktopDeviceIdentity,
  initializeDefaultAccountPlatform,
} from "./platform/defaultAccountPlatform.js";
import { createDefaultInboundEventStateRepository } from "./realtime/inboundEventPersistence.js";
import { RealtimeProtectionProcessor } from "./realtime/realtimeProtectionProcessor.js";
import { RealtimeProtectionService } from "./realtime/realtimeProtectionService.js";
import { SerialProtectionExecutor } from "./realtime/serialProtectionExecutor.js";

const PORT = Number(process.env.PORT ?? 4173);
const HOST = process.env.HOST ?? "127.0.0.1";

if (!["127.0.0.1", "localhost", "::1"].includes(HOST)) {
  throw new Error("The Email Shield desktop server may bind only to a loopback host.");
}

const dataDirectory = defaultEmailShieldDataDirectory();
ensureManagedDataDirectory(dataDirectory);

// Resolve or migrate protected local encryption keys before the desktop API
// becomes reachable. One native runtime vault is shared across every protected
// repository and provider session so Windows initializes its trusted helper
// once instead of recompiling it for each credential operation.
const credentialVault = getRuntimeCredentialVault();
await initializeDefaultPersonalPolicyRepository({ credentialVault });
await initializeDefaultScanStateRepository({ credentialVault });
await initializeDefaultRelationshipHistoryRepository({ credentialVault });
await initializeDefaultBackgroundProtectionRepository({ credentialVault });
await initializeDefaultAccountPlatform({ credentialVault, dataDirectory });
const inboundEventRepository = await createDefaultInboundEventStateRepository({
  credentialVault,
  dataDirectory,
});
const liveConnections = await createDefaultLiveConnectionPersistence({
  credentialVault,
  dataDirectory,
});

const accountPlatform = getAccountPlatformService();
const accountLifecycle = getAccountLifecycleService();
const deviceIdentity = getDesktopDeviceIdentity();

// Consumer mailbox authorization is one-time by default. The encrypted local
// registry contains only provider identity/config metadata and OS-vault handles;
// refresh tokens/app passwords remain in the native vault. Restore live sessions
// before either scheduled or realtime protection starts so restart does not
// create an unprotected gap. If the platform cannot persist vault-backed state,
// Email Shield still starts for Scam Check but refuses new durable live connects.
sessionStore.configureLiveConnectionPersistence(liveConnections, { required: true });
sessionStore.restoreLiveConnections();

const fixtureConnections = new FileFixtureConnectionPersistence(dataDirectory);
fixtureConnections.restore(sessionStore);

// Scheduled and realtime protection deliberately share both one underlying
// Worker implementation and one fail-fast execution gate. This keeps bounded
// Quick scanning, relationship history, personal policy, Family Shield and
// verified community intelligence on one path without creating a hidden queue.
const workerProtectionExecutor = new WorkerBackgroundProtectionExecutor(communityNetwork, accountPlatform);
const protectionExecutor = new SerialProtectionExecutor(workerProtectionExecutor);
const backgroundProtection = new BackgroundProtectionCoordinator({
  sessions: sessionStore,
  executor: protectionExecutor,
});
backgroundProtection.start();

const realtimeProcessor = new RealtimeProtectionProcessor(sessionStore, protectionExecutor);
const realtimeProtection = new RealtimeProtectionService({
  sessions: sessionStore,
  repository: inboundEventRepository,
  processor: realtimeProcessor,
});
realtimeProtection.start();

const app = createConsumerDesktopServer({
  backgroundProtection,
  fixtureConnections,
  accountPlatform,
  accountLifecycle,
  deviceIdentity,
  developmentEntitlementsEnabled: process.env.EMAIL_SHIELD_ENABLE_DEVELOPMENT_ENTITLEMENTS === "1",
});
app.listen(PORT, HOST, () => {
  console.log(`Email Shield listening on http://${HOST}:${PORT}`);
});
