import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const root = process.cwd();
const webDir = resolve(root, "web");
const files = readdirSync(webDir).filter((name) => name.endsWith(".js")).sort();
const sources = new Map(files.map((name) => [name, readFileSync(resolve(webDir, name), "utf8")]));
const failures = [];

function ownersMatching(predicate) {
  return [...sources.entries()].filter(([name, source]) => predicate(source, name)).map(([name]) => name);
}

function requireOnly(label, predicate, expectedOwner) {
  const owners = ownersMatching(predicate);
  if (owners.length !== 1 || owners[0] !== expectedOwner) {
    failures.push(`${label} must have exactly one browser execution owner (${expectedOwner}); found: ${owners.join(", ") || "none"}.`);
  }
}

const scanMonitor = sources.get("scan-monitor.js") || "";
const reviewActions = sources.get("review-actions.js") || "";
const protectionLearning = sources.get("protection-learning.js") || "";
const unsubscribeMonitor = sources.get("unsubscribe-monitor.js") || "";
const policyManagement = sources.get("policy-management.js") || "";

// Execution ownership is identified by the mutation fetch contract, not by
// incidental labels, result text, or secondary observers that watch a
// canonical button after success.
requireOnly(
  "Block sender/domain",
  (source) => source.includes('/messages/block-${scope}') && source.includes('JSON.stringify({ token, shareWithFamily })'),
  "scan-monitor.js",
);
requireOnly(
  "Move to Trash",
  (source) => source.includes('/messages/trash') && source.includes('result.requested !== 1') && source.includes('result.moved !== 1'),
  "scan-monitor.js",
);
requireOnly(
  "Report Scam / Spam / Safe / Trust",
  (source) => source.includes("const endpoint = isReportScam ? 'report-scam' : isMoveSpam ? 'report-spam' : isMarkSafe ? 'mark-safe' : 'trust-sender'")
    && source.includes('/messages/${endpoint}')
    && source.includes('JSON.stringify(isReportScam ? { token, blockSender } : { token })'),
  "review-actions.js",
);
requireOnly(
  "Unsubscribe",
  (source) => source.includes('/messages/unsubscribe') && source.includes('JSON.stringify({ token })'),
  "unsubscribe-monitor.js",
);

const eventSourceOwners = ownersMatching((source) => /new\s+EventSource\s*\(/.test(source));
if (eventSourceOwners.length !== 1 || eventSourceOwners[0] !== "scan-monitor.js") {
  failures.push(`Scan SSE must have exactly one browser owner (scan-monitor.js); found: ${eventSourceOwners.join(", ") || "none"}.`);
}

for (const required of [
  '[data-action="block-sender"],[data-action="block-domain"]',
  '/messages/block-${scope}',
  'JSON.stringify({ token, shareWithFamily })',
  'await policyChanged()',
]) {
  if (!scanMonitor.includes(required)) failures.push(`Canonical Block owner is missing required contract: ${required}`);
}
if (/JSON\.stringify\(\{[^}]*\b(address|domain)\b/s.test(scanMonitor)) {
  failures.push("Block owner must not authorize policy mutations from browser-displayed address/domain values.");
}

for (const required of [
  '[data-action="mark-safe"],[data-action="trust-sender"],[data-action="move-spam"],[data-action="report-scam"]',
  "const endpoint = isReportScam ? 'report-scam' : isMoveSpam ? 'report-spam' : isMarkSafe ? 'mark-safe' : 'trust-sender'",
  '/messages/${endpoint}',
  'JSON.stringify(isReportScam ? { token, blockSender } : { token })',
  'result.localProtected !== true',
  'await refreshPersonalPolicy()',
]) {
  if (!reviewActions.includes(required)) failures.push(`Canonical review-action owner is missing required contract: ${required}`);
}
if (!unsubscribeMonitor.includes('/messages/unsubscribe') || !unsubscribeMonitor.includes("JSON.stringify({ token })")) {
  failures.push("Unsubscribe owner no longer uses the dedicated opaque-token mutation contract.");
}

for (const [name, source] of sources) {
  if (source.includes("unblock-sender") || source.includes("unblock-domain")) {
    failures.push(`web/${name} reintroduced message-card raw-address Unblock ownership; durable revocation belongs to Personal Policy Management.`);
  }
}

for (const forbidden of [
  '[data-action="block-sender"]',
  '[data-action="block-domain"]',
  '[data-action="report-scam"]',
  '/messages/block-',
  '/messages/report-scam',
]) {
  if (protectionLearning.includes(forbidden)) {
    failures.push(`protection-learning.js must remain a secondary learning/family helper and may not own ${forbidden}.`);
  }
}
if (protectionLearning.includes("event.stopImmediatePropagation()")) {
  failures.push("protection-learning.js must not suppress canonical message-action handlers.");
}
for (const required of [
  'emailShieldChooseFamilyBlockSharing',
  "post(accountId, 'legitimate-feedback', { token })",
  'Message marked Safe ✓',
  'Sender trusted ✓',
]) {
  if (!protectionLearning.includes(required)) failures.push(`Secondary protection-learning contract is missing: ${required}`);
}

const publicRefreshOwners = ownersMatching((source) => source.includes("Object.defineProperty(window, 'emailShieldRefreshPersonalPolicy'"));
if (publicRefreshOwners.length !== 1 || publicRefreshOwners[0] !== "policy-management.js") {
  failures.push(`Personal Policy refresh must have exactly one public owner (policy-management.js); found: ${publicRefreshOwners.join(", ") || "none"}.`);
}
if (!policyManagement.includes("cache: 'no-store'") || !policyManagement.includes('requestSequence !== loadSequence')) {
  failures.push("Personal Policy owner no longer rejects stale asynchronous reads.");
}

if (failures.length) {
  for (const failure of failures) console.error(`FAIL: ${failure}`);
  process.exit(1);
}

console.log(`Browser action ownership passed across ${files.length} production JavaScript modules.`);
console.log("Single execution owners: scan-monitor (scan/Block/Trash), review-actions (Report/Spam/Safe/Trust), unsubscribe-monitor (Unsubscribe), policy-management (policy refresh).");
