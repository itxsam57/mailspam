import { createCommunityServiceServer } from "./community/server.js";
import { communityNetwork } from "./community/network.js";
import { createJsonLineCommunityDiagnosticSink } from "./community/operationalMetrics.js";

if (!communityNetwork.serverEnabled) {
  throw new Error("Set EMAIL_SHIELD_COMMUNITY_SERVER=1 before starting the community service.");
}

const port = Number(process.env.PORT ?? 4174);
const host = process.env.HOST ?? "127.0.0.1";

createCommunityServiceServer(communityNetwork, {
  diagnosticSink: createJsonLineCommunityDiagnosticSink((line) => process.stderr.write(line)),
}).listen(port, host, () => {
  console.log(`Email Shield community service listening on http://${host}:${port}`);
});
