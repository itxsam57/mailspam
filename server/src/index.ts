import { initializeDefaultPersonalPolicyRepository } from "./api/defaultPolicyRepository.js";
import { initializeDefaultScanStateRepository } from "./api/defaultScanStateRepository.js";
import { initializeDefaultRelationshipHistoryRepository } from "./api/defaultRelationshipHistoryRepository.js";
import { initializeDefaultBackgroundProtectionRepository } from "./api/defaultBackgroundProtectionRepository.js";
import { createBackgroundProtectionCoordinator } from "./api/backgroundProtection.js";
import { createLocalDesktopServer } from "./api/localDesktopServer.js";
import { communityNetwork } from "./community/network.js";
import { ensureManagedDataDirectory } from "./security/managedDataDirectory.js";
import { getRuntimeCredentialVault } from "./security/credentialVaultFactory.js";
import { defaultEmailShieldDataDirectory } from "./security/dataDirectory.js";
import { FileFixtureConnectionPersistence } from "./api/fixtureConnectionPersistence.js";
import { sessionStore } from "./api/sessionStore.js";
import {
  getAccountPlatformService,
  getDesktopDeviceIdentity,
  initializeDefaultAccountPlatform,
} from "./platform/defaultAccountPlatform.js";

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

const accountPlatform = getAccountPlatformService();
const deviceIdentity = getDesktopDeviceIdentity();
const fixtureConnections = new FileFixtureConnectionPersistence(dataDirectory);
fixtureConnections.restore(sessionStore);

const backgroundProtection = createBackgroundProtectionCoordinator(communityNetwork);
backgroundProtection.start();
const app = createLocalDesktopServer({
  backgroundProtection,
  fixtureConnections,
  accountPlatform,
  deviceIdentity,
  developmentEntitlementsEnabled: process.env.EMAIL_SHIELD_ENABLE_DEVELOPMENT_ENTITLEMENTS === "1",
});
app.listen(PORT, HOST, () => {
  console.log(`Email Shield listening on http://${HOST}:${PORT}`);
});
