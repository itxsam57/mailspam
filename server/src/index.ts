import { initializeDefaultPersonalPolicyRepository } from "./api/defaultPolicyRepository.js";
import { createLocalDesktopServer } from "./api/localDesktopServer.js";

const PORT = Number(process.env.PORT ?? 4173);
const HOST = process.env.HOST ?? "127.0.0.1";

if (!["127.0.0.1", "localhost", "::1"].includes(HOST)) {
  throw new Error("The Email Shield desktop server may bind only to a loopback host.");
}

// Resolve or migrate the AES policy key before the desktop API becomes
// reachable. Windows Credential Manager failures therefore stop startup instead
// of silently recreating a plaintext key file or running with non-durable state.
await initializeDefaultPersonalPolicyRepository();

const app = createLocalDesktopServer();
app.listen(PORT, HOST, () => {
  console.log(`Email Shield listening on http://${HOST}:${PORT}`);
});
