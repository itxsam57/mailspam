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

function requireExclusiveOwners(label, owners, expectedOwner) {
  if (owners.length !== 1 || owners[0] !== expectedOwner) {
    failures.push(`${label} must have exactly one browser mutation owner (${expectedOwner}); found: ${owners.join(", ") || "none"}.`);
  }
}

function messageMutationOwners(endpoint) {
  const literal = `/messages/${endpoint}`;
  return ownersMatching((source) => {
    if (source.includes(literal)) return true;
    const usesDynamicEndpoint = source.includes('/messages/${endpoint}') || source.includes("/messages/${endpoint}");
    const declaresEndpoint = source.includes(`'${endpoint}'`) || source.includes(`\"${endpoint}\"`);
    return usesDynamicEndpoint && declaresEndpoint;
  });
}

const blockOwners = ownersMatching((source) => /\/messages\/block-(?:sender|domain|\$\{scope\})/.test(source));
requireExclusiveOwners("Block sender/domain", blockOwners, "scan-monitor.js");
requireExclusiveOwners("Move to Trash", messageMutationOwners("trash"), "scan-monitor.js");
requireExclusiveOwners("Report Scam", messageMutationOwners("report-scam"), "review-actions.js");
requireExclusiveOwners("Move to Spam/Junk", messageMutationOwners("report-spam"), "review-actions.js");
requireExclusiveOwners("Mark Safe", messageMutationOwners("mark-safe"), "review-actions.js");
requireExclusiveOwners("Trust sender", messageMutationOwners("trust-sender"), "review-actions.js");
requireExclusiveOwners("Unsubscribe", messageMutationOwners("unsubscribe"), "unsubscribe-monitor.js");

const eventSourceOwners = ownersMatching((source) => /new\s+EventSource\s*\(/.test(source));
if (eventSourceOwners.length !== 1 || eventSourceOwners[0] !== "scan-monitor.js") {
  failures.push(`Scan SSE must have exactly one browser owner (scan-monitor.js); found: ${eventSourceOwners.join(", ") || "none"}.`);
}

const scanMonitor = sources.get("scan-monitor.js") || "";
const reviewActions = sources.get("review-actions.js") || "";
const protectionLearning = sources.get("protection-learning.js") || "";
const unsubscribeMonitor = sources.get("unsubscribe-monitor.js") || "";

for (const required of [
  '[data-action="block-sender"],[data-action="block-domain"]',
  '/messages/block-${scope}',
  'JSON.stringify({ token, shareWithFamily })',
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
]) {
  if (protectionLearning.includes(forbidden)) {
    failures.push(`protection-learning.js must remain a secondary learning/family helper and may not own ${forbidden}.`);
  }
}
if (protectionLearning.includes("event.stopImmediatePropagation()")) {
  failures.push("protection-learning.js must not suppress canonical message-action handlers.");
}
if (!protectionLearning.includes("emailShieldChooseFamilyBlockSharing")) {
  failures.push("Family sharing choice disappeared from the secondary protection-learning helper.");
}

const publicRefreshOwners = ownersMatching((source) => source.includes("Object.defineProperty(window, 'emailShieldRefreshPersonalPolicy'"));
if (publicRefreshOwners.length !== 1 || publicRefreshOwners[0] !== "policy-management.js") {
  failures.push(`Personal Policy refresh must have exactly one public owner (policy-management.js); found: ${publicRefreshOwners.join(", ") || "none"}.`);
}

if (failures.length) {
  for (const failure of failures) console.error(`FAIL: ${failure}`);
  process.exit(1);
}

console.log(`Browser action ownership passed across ${files.length} production JavaScript modules.`);
console.log("Single owners: scan-monitor (scan/Block/Trash), review-actions (Report/Spam/Safe/Trust), unsubscribe-monitor (Unsubscribe), policy-management (policy refresh).");
