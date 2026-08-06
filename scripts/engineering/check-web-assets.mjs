import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import vm from "node:vm";

const root = process.cwd();
const webDir = resolve(root, "web");
const failures = [];

function requireCondition(condition, message) {
  if (!condition) failures.push(message);
}

function read(path) {
  return readFileSync(resolve(root, path), "utf8");
}

const html = read("web/index.html");
const server = read("server/src/api/server.ts");
const browserFiles = readdirSync(webDir).filter((name) => name.endsWith(".js")).sort();
requireCondition(browserFiles.length > 0, "No browser JavaScript files were found.");

for (const file of browserFiles) {
  try {
    execFileSync(process.execPath, ["--check", resolve(webDir, file)], { stdio: "pipe" });
  } catch (error) {
    failures.push(`Browser JavaScript syntax check failed for web/${file}: ${error.stderr?.toString().trim() || error.message}`);
  }
}

const inlineScripts = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi)]
  .filter((match) => !/\ssrc\s*=/.test(match[0]))
  .map((match) => match[1]);
requireCondition(inlineScripts.length > 0, "web/index.html contains no inline application script to validate.");
for (const [index, source] of inlineScripts.entries()) {
  try {
    new vm.Script(source, { filename: `web/index.html:inline-${index + 1}.js` });
  } catch (error) {
    failures.push(`Inline browser script ${index + 1} does not parse: ${error.message}`);
  }
}

for (const id of [
  "providerSelect", "modeSelect", "connectBtn", "credentialFields", "accountsList",
  "scanPanel", "quickScanBtn", "fullScanBtn", "spamScanBtn", "stopScanBtn",
  "counters", "cards", "devSuiteBtn",
]) {
  requireCondition(new RegExp(`id=["']${id}["']`).test(html), `Required browser element #${id} is missing from web/index.html.`);
}

const injectedScripts = ["scan-monitor.js", "unsubscribe-monitor.js"];
for (const script of injectedScripts) {
  requireCondition(server.includes(`/${script}`), `Express dashboard injection no longer includes /${script}.`);
  requireCondition(browserFiles.includes(script), `Injected browser script is missing: web/${script}.`);
}

const dynamicDependencies = [
  ["web/unsubscribe-monitor.js", "safe-audit.js"],
  ["web/unsubscribe-monitor.js", "review-actions.js"],
];
for (const [owner, dependency] of dynamicDependencies) {
  requireCondition(read(owner).includes(`/${dependency}`), `${owner} no longer loads /${dependency}.`);
  requireCondition(browserFiles.includes(dependency), `Dynamic browser dependency is missing: web/${dependency}.`);
}

const endpointContracts = [
  ["web/scan-monitor.js", "/scan/stop", 'app.post("/api/accounts/:id/scan/stop"'],
  ["web/scan-monitor.js", "block-sender", 'app.post("/api/accounts/:id/messages/block-sender"'],
  ["web/scan-monitor.js", "block-domain", 'app.post("/api/accounts/:id/messages/block-domain"'],
  ["web/scan-monitor.js", "/messages/trash", 'app.post("/api/accounts/:id/messages/trash"'],
  ["web/review-actions.js", "mark-safe", 'app.post("/api/accounts/:id/messages/mark-safe"'],
  ["web/review-actions.js", "trust-sender", 'app.post("/api/accounts/:id/messages/trust-sender"'],
  ["web/review-actions.js", "report-scam", 'app.post("/api/accounts/:id/messages/report-scam"'],
  ["web/review-actions.js", "report-spam", 'app.post("/api/accounts/:id/messages/report-spam"'],
  ["web/unsubscribe-monitor.js", "/messages/unsubscribe", 'app.post("/api/accounts/:id/messages/unsubscribe"'],
];
for (const [browserPath, browserNeedle, serverNeedle] of endpointContracts) {
  requireCondition(read(browserPath).includes(browserNeedle), `${browserPath} no longer references ${browserNeedle}.`);
  requireCondition(server.includes(serverNeedle), `Server endpoint contract is missing: ${serverNeedle}.`);
}

for (const serverNeedle of [
  'app.get("/api/community/v1/status"',
  'app.post("/api/community/v1/report"',
  'app.get("/api/community/v1/feed"',
  'app.get("/api/community/v1/public-key"',
]) requireCondition(server.includes(serverNeedle), `Community service endpoint contract is missing: ${serverNeedle}.`);

for (const path of ["web/scan-monitor.js", "web/safe-audit.js", "web/review-actions.js", "web/unsubscribe-monitor.js"]) {
  const content = read(path);
  for (const forbidden of [
    "textPreview", "htmlSignals", "listUnsubscribe:", "listUnsubscribePost:",
    "campaignFingerprint", "reporterProof", "communityReport", "providerNativeIds",
  ]) {
    requireCondition(!content.includes(forbidden), `${path} exposes or depends on privacy-sensitive field ${forbidden}.`);
  }
}

const reviewActions = read("web/review-actions.js");
requireCondition(reviewActions.includes("Report Scam to Email Shield"), "Shared community reporting is missing from review actions.");
requireCondition(reviewActions.includes("privacy-reduced indicators"), "Community report confirmation no longer explains its privacy boundary.");
requireCondition(reviewActions.includes("One report cannot globally block a sender"), "Community report confirmation no longer explains aggregation thresholds.");
requireCondition(reviewActions.includes("JSON.stringify(isReportScam ? { token, blockSender } : { token })"), "Review actions no longer submit only opaque tokens and an explicit sender-block choice.");
requireCondition(reviewActions.includes("result.requested !== 1") && reviewActions.includes("result.reported !== 1"), "Provider Spam/Junk UI no longer requires exact-one confirmation.");
requireCondition(!reviewActions.includes("providerNativeIds"), "Browser actions must not submit provider-native identifiers.");

requireCondition(html.includes("Fixture demo mailbox"), "Fixture mode is no longer exposed for credential-free hard testing.");
requireCondition(html.includes('value="gmail"') && html.includes('value="icloud"') && html.includes('value="outlook"') && html.includes('value="yahoo"') && html.includes('value="imap"'), "One or more supported provider options are missing from the dashboard.");

if (failures.length) {
  for (const failure of failures) console.error(`FAIL: ${failure}`);
  process.exit(1);
}

console.log(`Browser source checks passed for ${browserFiles.length} JavaScript files and ${inlineScripts.length} inline script block(s).`);