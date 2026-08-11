import { initializeDefaultPersonalPolicyRepository } from "./api/defaultPolicyRepository.js";
import { initializeDefaultScanStateRepository } from "./api/defaultScanStateRepository.js";
import { initializeDefaultRelationshipHistoryRepository } from "./api/defaultRelationshipHistoryRepository.js";
import { initializeDefaultBackgroundProtectionRepository } from "./api/defaultBackgroundProtectionRepository.js";
import { createBackgroundProtectionCoordinator } from "./api/backgroundProtection.js";
import { createLocalDesktopServer } from "./api/localDesktopServer.js";
import { communityNetwork } from "./community/network.js";
import { ensureManagedDataDirectory } from "./security/managedDataDirectory.js";
import { homedir } from "node:os";
import { join } from "node:path";

const PORT = Number(process.env.PORT ?? 4173);
const HOST = process.env.HOST ?? "127.0.0.1";

if (!["127.0.0.1", "localhost", "::1"].includes(HOST)) {
  throw new Error("The Email Shield desktop server may bind only to a loopback host.");
}

ensureManagedDataDirectory(process.env.EMAIL_SHIELD_DATA_DIR?.trim() || join(homedir(), ".email-shield"));

// Resolve or migrate protected local encryption keys before the desktop API
// becomes reachable. Native-vault failures therefore stop startup instead of
// silently recreating plaintext keys or discarding encrypted local state.
await initializeDefaultPersonalPolicyRepository();
await initializeDefaultScanStateRepository();
await initializeDefaultRelationshipHistoryRepository();
await initializeDefaultBackgroundProtectionRepository();

const backgroundProtection = createBackgroundProtectionCoordinator(communityNetwork);
backgroundProtection.start();
const app = createLocalDesktopServer({ backgroundProtection });
app.listen(PORT, HOST, () => {
  console.log(`Email Shield listening on http://${HOST}:${PORT}`);
});
