import { initializeDefaultPersonalPolicyRepository } from "./api/defaultPolicyRepository.js";
import { initializeDefaultScanStateRepository } from "./api/defaultScanStateRepository.js";
import { createLocalDesktopServer } from "./api/localDesktopServer.js";

const PORT = Number(process.env.PORT ?? 4173);
const HOST = process.env.HOST ?? "127.0.0.1";

if (!["127.0.0.1", "localhost", "::1"].includes(HOST)) {
  throw new Error("The Email Shield desktop server may bind only to a loopback host.");
}

// Resolve or migrate protected local encryption keys before the desktop API
// becomes reachable. Native-vault failures therefore stop startup instead of
// silently recreating plaintext keys or discarding encrypted local state.
await initializeDefaultPersonalPolicyRepository();
await initializeDefaultScanStateRepository();

const app = createLocalDesktopServer();
app.listen(PORT, HOST, () => {
  console.log(`Email Shield listening on http://${HOST}:${PORT}`);
});
