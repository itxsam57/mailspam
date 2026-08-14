import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const root = process.cwd();
const webDir = resolve(root, "web");
const files = readdirSync(webDir).filter((name) => name.endsWith(".js")).sort();
const sources = new Map(files.map((name) => [name, readFileSync(resolve(webDir, name), "utf8")]));
const failures = [];

function ownersContaining(needle) {
  return [...sources.entries()].filter(([, source]) => source.includes(needle)).map(([name]) => name);
}

function requireExclusiveOwner(label, needle, expectedOwner) {
  const owners = ownersContaining(needle);
  if (owners.length !== 1 || owners[0] !== expectedOwner) {
    failures.push(`${label} must have exactly one browser mutation owner (${expectedOwner}); found: ${owners.join(", ") || "none"}.`);
  }
}

for (const [label, needle, owner] of [
  ["Block sender", "/messages/block-sender", "scan-monitor.js"],
  ["Block domain", "/messages/block-domain", "scan-monitor.js"],
  ["Move to Trash", "/messages/trash", "scan-monitor.js"],
  ["Report Scam", "/messages/report-scam", "review-actions.js"],
  ["Move to Spam/Junk", "/messages/report-spam", "review-actions.js"],
  ["Mark Safe", "/messages/mark-safe", "review-actions.js"],
  ["Trust sender", "/messages/trust-sender", "review-actions.js"],
  ["Unsubscribe", "/messages/unsubscribe", "unsubscribe-monitor.js"],
]) requireExclusiveOwner(label, needle, owner);

const eventSourceOwners = [...sources.entries()]
  .filter(([, source]) => /new\s+EventSource\s*\(/.test(source))
  .map(([name]) => name);
if (eventSourceOwners.length !== 1 || eventSourceOwners[0] !== "scan-monitor.js") {
  failures.push(`Scan SSE must have exactly one browser owner (scan-monitor.js); found: ${eventSourceOwners.join(", ") || "none"}.`);
}

const scanMonitor = sources.get("scan-monitor.js") || "";
const reviewActions = sources.get("review-actions.js") || "";
const protectionLearning = sources.get("protection-learning.js") || "";
const unsubscribeMonitor = sources.get("unsubscribe-monitor.js") || "";

if (!scanMonitor.includes("JSON.stringify({ token, shareWithFamily })")) {
  failures.push("Block owner no longer submits only the opaque review token plus explicit Family-sharing choice.");
}
if (/JSON\.stringify\(\{[^}]*\b(address|domain)\b/s.test(scanMonitor)) {
  failures.push("Block owner must not authorize policy mutations from browser-displayed address/domain values.");
}
if (!reviewActions.includes("JSON.stringify(isReportScam ? { token, blockSender } : { token })")) {
  failures.push("Review action owner no longer uses opaque token authorization plus explicit sender-block choice.");
}
if (!unsubscribeMonitor.includes("JSON.stringify({ token })")) {
  failures.push("Unsubscribe owner no longer uses opaque token authorization.");
}

for (const [name, source] of sources) {
  if (source.includes("unblock-sender") || source.includes("unblock-domain")) {
    failures.push(`web/${name} reintroduced message-card raw-address Unblock ownership; durable revocation belongs to Personal Policy Management.`);
  }
}

for (const forbidden of [
  "[data-action=\"block-sender\"]",
  "[data-action=\"block-domain\"]",
  "[data-action=\"report-scam\"]",
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

const publicRefreshOwners = ownersContaining("Object.defineProperty(window, 'emailShieldRefreshPersonalPolicy'");
if (publicRefreshOwners.length !== 1 || publicRefreshOwners[0] !== "policy-management.js") {
  failures.push(`Personal Policy refresh must have exactly one public owner (policy-management.js); found: ${publicRefreshOwners.join(", ") || "none"}.`);
}

if (failures.length) {
  for (const failure of failures) console.error(`FAIL: ${failure}`);
  process.exit(1);
}

console.log(`Browser action ownership passed across ${files.length} production JavaScript modules.`);
console.log("Single owners: scan-monitor (scan/Block/Trash), review-actions (Report/Spam/Safe/Trust), unsubscribe-monitor (Unsubscribe), policy-management (policy refresh).");
