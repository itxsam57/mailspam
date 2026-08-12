import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { COMMUNITY_REPORT_RETENTION_MS } from "../../server/dist/community/aggregateStore.js";

const required = {
  "PRIVACY.md": ["## What the desktop client processes", "## Community report", "90 days", "2,000 pending reports"],
  "SECURITY.md": ["## Reporting a vulnerability", "security/advisories/new", "## Release and supply-chain requirements", "Production release signing keys"],
  "THREAT_MODEL.md": ["## Trust boundaries", "## Threats and controls", "## Out of scope / external controls", "Android/iOS full mailbox shells are not implemented"],
  "INCIDENT_RESPONSE.md": ["## Severity", "## Response sequence", "### Release signing key or distribution compromise", "### Privacy leak in logs/metrics/report schema"],
  "docs/DEPLOYMENT_CAPACITY_COST.md": ["## Proven application boundaries", "npm run capacity:plan", "npm run test:capacity", "planning triggers", "not a throughput, latency, availability or cloud-price SLA"],
  "docs/THREE_MILESTONE_FINAL_RECONCILIATION.md": ["1 — cross-adapter protection core", "CODE-COMPLETE / EXTERNAL ACCEPTANCE OPEN", "Android/iOS mailbox application shells are not implemented", "The project must not be described as all three milestones formally closed"],
};

for (const [path, markers] of Object.entries(required)) {
  const absolute = resolve(path);
  if (!existsSync(absolute)) throw new Error(`Required public engineering document is missing: ${path}`);
  const content = readFileSync(absolute, "utf8");
  if (content.length < 500) throw new Error(`Public engineering document is unexpectedly incomplete: ${path}`);
  for (const marker of markers) if (!content.includes(marker)) throw new Error(`${path} is missing required reviewed statement: ${marker}`);
  if (/\b(?:TODO|TBD|coming soon|placeholder)\b/i.test(content)) throw new Error(`${path} contains an unfinished placeholder.`);
}

if (COMMUNITY_REPORT_RETENTION_MS !== 90 * 24 * 60 * 60_000) throw new Error("Privacy notice retention no longer matches the runtime 90-day contract.");
const audit = readFileSync(resolve(".engineering/CANONICAL_ROADMAP_GAP_AUDIT.md"), "utf8");
for (const former of [
  "| Privacy-safe operational dashboards | MISSING |",
  "| Public privacy, security, threat-model and incident-response documentation | MISSING |",
  "| Automated Regression Vault expansion | PARTIAL |",
  "| Long-term provider compatibility tests and release gates | PARTIAL |",
]) if (audit.includes(former)) throw new Error(`Canonical roadmap still contains stale status: ${former}`);

console.log(`Public privacy/security/threat/incident/capacity/reconciliation documentation passed (${Object.keys(required).length} documents).`);
