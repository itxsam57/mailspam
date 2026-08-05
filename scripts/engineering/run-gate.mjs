import { spawnSync, execFileSync } from "node:child_process";
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const root = process.cwd();
const artifactDir = resolve(root, process.env.ENGINEERING_ARTIFACT_DIR || "artifacts/engineering");
mkdirSync(artifactDir, { recursive: true });

const npm = process.platform === "win32" ? "npm.cmd" : "npm";
const startedAt = new Date();

function git(args, fallback = "unknown") {
  try {
    return execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim() || fallback;
  } catch {
    return fallback;
  }
}

const steps = [
  { id: "preflight", name: "Repository preflight", command: npm, args: ["run", "preflight"] },
  { id: "typecheck", name: "Strict TypeScript typecheck", command: npm, args: ["run", "typecheck"] },
  { id: "build", name: "Production build", command: npm, args: ["run", "build"] },
  { id: "unit", name: "Unit and regression tests", command: npm, args: ["run", "test:unit"] },
  { id: "integration", name: "Integration, corpus and Worker tests", command: npm, args: ["run", "test:integration"] },
  { id: "web", name: "Browser source, privacy and wiring checks", command: npm, args: ["run", "check:web"] },
  { id: "smoke", name: "Compiled server and API smoke", command: npm, args: ["run", "smoke:server"] },
];

if (process.env.ENGINEERING_AUDIT !== "0") {
  steps.push({ id: "audit-inventory", name: "All-dependency advisory inventory", command: npm, args: ["run", "audit:inventory"] });
  steps.push({ id: "audit", name: "Production dependency audit", command: npm, args: ["run", "audit:prod"] });
}

const results = [];
for (const step of steps) {
  const stepStarted = Date.now();
  console.log(`\n============================================================`);
  console.log(`ENGINEERING GATE: ${step.name}`);
  console.log(`============================================================`);
  const outcome = spawnSync(step.command, step.args, {
    cwd: root,
    env: process.env,
    stdio: "inherit",
    shell: false,
  });
  const durationMs = Date.now() - stepStarted;
  const exitCode = typeof outcome.status === "number" ? outcome.status : 1;
  results.push({
    id: step.id,
    name: step.name,
    status: exitCode === 0 ? "passed" : "failed",
    exitCode,
    durationMs,
    signal: outcome.signal ?? null,
    error: outcome.error?.message ?? null,
  });
  if (exitCode !== 0) console.error(`Gate stage failed: ${step.name} (exit ${exitCode}). Continuing to collect independent results.`);
}

const finishedAt = new Date();
const failures = results.filter((result) => result.status === "failed");
const overall = failures.length === 0 ? "PASSED" : "FAILED";
const branch = git(["branch", "--show-current"], "detached/unknown");
const commit = git(["rev-parse", "HEAD"]);
const workingTree = git(["status", "--porcelain"], "");

const dependencyAuditPath = resolve(artifactDir, "dependency-audit.json");
let dependencyInventory = null;
if (existsSync(dependencyAuditPath)) {
  try { dependencyInventory = JSON.parse(readFileSync(dependencyAuditPath, "utf8")); }
  catch { dependencyInventory = { error: "dependency-audit.json could not be parsed" }; }
}

const preExistingFindings = [
  {
    id: "PRE-001",
    area: "strict test type safety",
    status: "fixed during automation installation",
    file: "tests/unit/messageIntentProfileLure.test.ts",
    finding: "The existing CanonicalEnvelope test fixture omitted the required diagnostics.contentCoverage field. The former build plus Vitest gate did not typecheck test sources, so it remained hidden while production build and behavior tests passed.",
    productionRuntimeImpact: "none observed",
  },
];

const report = {
  project: "Email Shield",
  repository: "itxsam57/mailspam",
  branch,
  commit,
  node: process.versions.node,
  platform: process.platform,
  architecture: process.arch,
  startedAt: startedAt.toISOString(),
  finishedAt: finishedAt.toISOString(),
  durationMs: finishedAt.getTime() - startedAt.getTime(),
  overall,
  auditEnabled: process.env.ENGINEERING_AUDIT !== "0",
  workingTreeCleanBeforeArtifacts: workingTree === "",
  baseline: {
    auditedFunctionalCommit: "18d7a7b657762afb79d304f1cfac4cecdae7468b",
    formerGateStatus: "green on Ubuntu and Windows before this installation",
    formerGateCoverage: "production build, Vitest behavior tests and Linux production dependency audit; no strict test-source typecheck",
    preExistingFindings,
  },
  dependencyInventory,
  dependencyPolicy: {
    inventory: "all installed production and development dependencies are recorded when audit is enabled",
    blocking: "high or critical production dependency advisories fail npm run audit:prod",
    followUp: "development-only and moderate advisories remain visible for a separate reviewed dependency upgrade",
  },
  steps: results,
  failedSteps: failures.map((failure) => failure.id),
  knownProductGapsSource: ".engineering/REGRESSION_REGISTER.md",
  manualHandoff: "artifacts/engineering/MANUAL_TEST_HANDOFF.md",
};

writeFileSync(resolve(artifactDir, "verification-report.json"), `${JSON.stringify(report, null, 2)}\n`);

const stepRows = results.map((result) =>
  `| ${result.status === "passed" ? "PASS" : "FAIL"} | ${result.name} | ${result.exitCode} | ${(result.durationMs / 1000).toFixed(1)}s |`,
).join("\n");
const failureText = failures.length
  ? failures.map((failure) => `- **${failure.name}** — exit ${failure.exitCode}${failure.error ? `; ${failure.error}` : ""}`).join("\n")
  : "- None.";
const preExistingText = preExistingFindings.map((finding) =>
  `- **${finding.id} — ${finding.area}:** ${finding.finding} Status: ${finding.status}. Production runtime impact: ${finding.productionRuntimeImpact}.`,
).join("\n");
const dependencyText = dependencyInventory?.counts
  ? `All installed dependencies: **${dependencyInventory.counts.total} total advisories** — ${dependencyInventory.counts.critical} critical, ${dependencyInventory.counts.high} high, ${dependencyInventory.counts.moderate} moderate, ${dependencyInventory.counts.low} low. Package-level evidence is in \`dependency-audit.json\`. The separate production audit remains the blocking security decision.`
  : (report.auditEnabled ? "Dependency inventory was enabled but no parseable summary was produced." : "Dependency inventory was not run on this platform invocation.");

const markdownReport = `# Email Shield Engineering Verification Report

- **Overall:** ${overall}
- **Repository:** \`itxsam57/mailspam\`
- **Branch:** \`${branch}\`
- **Commit:** \`${commit}\`
- **Platform:** \`${process.platform}/${process.arch}\`
- **Node.js:** \`${process.versions.node}\`
- **Started:** ${startedAt.toISOString()}
- **Finished:** ${finishedAt.toISOString()}
- **Dependency audit:** ${report.auditEnabled ? "full inventory plus blocking production audit enabled" : "not run on this platform invocation"}

## Gate results

| Result | Stage | Exit | Duration |
|---|---|---:|---:|
${stepRows}

## Current gate failures

${failureText}

## Pre-existing findings discovered by the stronger gate

${preExistingText}

The audited functional baseline commit \`18d7a7b657762afb79d304f1cfac4cecdae7468b\` passed the former Ubuntu and Windows matrix. That does not mean the repository had no hidden defect: the former command did not typecheck test sources. PRE-001 is retained in this report even after correction so the installation history remains truthful.

## Dependency advisory inventory

${dependencyText}

Known incomplete product capabilities remain listed separately in \`.engineering/REGRESSION_REGISTER.md\`; they are not hidden inside a green command-line result.

## Browser handoff

${overall === "PASSED"
  ? "The automated gate is green. The owner may perform only the visible checks in `MANUAL_TEST_HANDOFF.md`."
  : "The browser handoff is blocked. Fix or explicitly triage the automated failures before asking the owner for visible acceptance."}
`;
writeFileSync(resolve(artifactDir, "VERIFICATION_REPORT.md"), markdownReport);

const handoffStatus = overall === "PASSED" ? "READY FOR OWNER VISIBLE TESTING" : "BLOCKED BY AUTOMATED GATE";
const check = "- [ ]";
const manualHandoff = `# Email Shield — Manual Browser Test Handoff

## Status

**${handoffStatus}**

- Repository: \`itxsam57/mailspam\`
- Branch: \`${branch}\`
- Commit: \`${commit}\`
- Automated report: \`artifacts/engineering/VERIFICATION_REPORT.md\`
- Generated: ${finishedAt.toISOString()}

${overall === "PASSED"
  ? "All applicable command-line checks passed for this platform invocation. Complete only the visible checks below; do not repeat build, typecheck, unit, integration, corpus, Worker, source-wiring, API-smoke or dependency commands manually."
  : `Do not begin browser acceptance. Failed automated stages: ${failures.map((item) => item.name).join(", ")}.`}

## Start the verified build

\`\`\`bash
npm run dev
\`\`\`

Open \`http://127.0.0.1:4173\` and record PASS/FAIL beside each item.

## Visible checks

${check} **Initial render** — dashboard appears without a blank page, permanent spinner, flicker loop, frozen controls or overlapping primary panels.

${check} **Responsive layout** — inspect normal desktop width and a narrow/mobile width; controls, counters, tables and cards remain readable and reachable.

${check} **Five fixture providers** — connect Gmail, iCloud, Outlook, Yahoo and Generic IMAP in Fixture mode one at a time; each visibly becomes selected and completes Quick Scan.

${check} **Scan presentation** — run Quick, Full Mailbox and Spam/Junk fixture scans; visible progress, counters, Safe audit and warning cards update without duplicates or stale results.

${check} **Stop and restart** — stop a Full fixture scan while active; controls return and a new scan starts without refreshing the page.

${check} **Safe audit** — Safe rows show only subject, sender, parse/evidence and available Trust/Unsubscribe actions; no body or raw destination is displayed.

${check} **Review actions** — inspect confirmation wording for Mark this message Safe, Trust sender, Block sender, Block domain, Move to Trash and unsubscribe. Cancel actions not intentionally under test.

${check} **Controlled fixture actions** — execute safe fixture-only actions and confirm success appears only after server confirmation; failures remain visible and retryable.

${check} **Account isolation** — connect two fixture accounts, switch between them and verify selected-account results/actions do not visibly cross-link.

${check} **Rapid interaction** — click account and scan controls rapidly but safely; duplicate requests are prevented or truthfully reported and the UI stays responsive.

${check} **Controlled live iCloud presentation** — when an app-specific password is available, reconnect iCloud and run the agreed non-destructive scan. Credentials must not remain visible after connection; progress/errors must be truthful. Do not perform an unlisted destructive bulk action.

${check} **Final refresh** — refresh once after testing; the page still renders without a permanent blank/frozen state or broken layout.

## Failure capture

For any FAIL, record:

- exact checklist item;
- browser and viewport/device;
- exact visible error or incorrect behavior;
- whether refresh changed the result;
- screenshot only when useful;
- terminal lines only when an error appeared.

Never include a mailbox password, app password, OAuth token, complete message body or private provider message identifier.

## Explicitly excluded product gaps

Guided Gmail/Outlook OAuth, OS-keychain storage, production signed-feed publishing, production QR decoding, community reporting, complete policy-management UI and persisted resumable scans are not accepted by this handoff. They remain open in the regression register.
`;
writeFileSync(resolve(artifactDir, "MANUAL_TEST_HANDOFF.md"), manualHandoff);

if (process.env.GITHUB_STEP_SUMMARY) {
  appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${markdownReport}\n`);
}

console.log(`\nEngineering gate ${overall}.`);
console.log(`Report: ${resolve(artifactDir, "VERIFICATION_REPORT.md")}`);
console.log(`Manual handoff: ${resolve(artifactDir, "MANUAL_TEST_HANDOFF.md")}`);

if (failures.length) process.exit(1);