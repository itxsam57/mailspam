import { spawnSync, execFileSync } from "node:child_process";
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const root = process.cwd();
const artifactDir = resolve(root, process.env.ENGINEERING_ARTIFACT_DIR || "artifacts/engineering");
mkdirSync(artifactDir, { recursive: true });

const npmCli = process.env.npm_execpath;
if (!npmCli) {
  console.error("FAIL: npm_execpath is unavailable. Run this gate through `npm run gate` or `npm run verify`.");
  process.exit(1);
}
const startedAt = new Date();

function git(args, fallback = "unknown") {
  try {
    return execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim() || fallback;
  } catch {
    return fallback;
  }
}

function npmStep(id, name, script) {
  return { id, name, command: process.execPath, args: [npmCli, "run", script] };
}

const steps = [
  npmStep("preflight", "Repository preflight", "preflight"),
  npmStep("typecheck", "Strict TypeScript typecheck", "typecheck"),
  npmStep("portable-core", "Portable scanner/account/family dependency boundary", "check:core"),
  npmStep("build", "Production build", "build"),
  npmStep("core-vectors", "Versioned portable-core conformance vectors", "check:core-vectors"),
  npmStep("provider-compatibility", "Versioned provider compatibility contracts", "check:provider-compatibility"),
  npmStep("regression-vault", "Approved anonymized Regression Vault", "check:regression-vault"),
  npmStep("capacity-budgets", "Deployment capacity and cost budgets", "check:capacity"),
  ...(process.env.ENGINEERING_CAPACITY_STRESS === "1"
    ? [npmStep("capacity-stress", "10,000-client release-capacity qualification", "test:capacity")]
    : []),
  npmStep("public-docs", "Public privacy, security, threat, incident and deployment contracts", "check:public-docs"),
  npmStep("unit", "Unit, API and regression tests", "test:unit"),
  npmStep("integration", "Integration, corpus and Worker tests", "test:integration"),
  npmStep("web", "Browser source, privacy and wiring checks", "check:web"),
  npmStep("desktop-smoke", "Compiled desktop server and API smoke", "smoke:server"),
  npmStep("community-smoke", "Compiled dedicated community service smoke", "smoke:community"),
  npmStep("account-service-smoke", "Compiled account, entitlement and Family Shield service smoke", "smoke:account-service"),
  npmStep("background-smoke", "Compiled scheduled background protection smoke", "smoke:background"),
  npmStep("portable-package", "Reproducible portable package and bundled-runtime smoke", "package:verify"),
  npmStep("release-lifecycle", "Signed release install, activation and uninstall smoke", "smoke:release"),
];

if (process.env.ENGINEERING_AUDIT !== "0") {
  steps.push(npmStep("audit-inventory", "All-dependency advisory inventory", "audit:inventory"));
  steps.push(npmStep("audit", "Production dependency audit", "audit:prod"));
}

const results = [];
for (const step of steps) {
  const stepStarted = Date.now();
  console.log("\n============================================================");
  console.log(`ENGINEERING GATE: ${step.name}`);
  console.log("============================================================");
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
  if (exitCode !== 0) {
    console.error(`Gate stage failed: ${step.name} (exit ${exitCode}). Continuing to collect independent results.`);
  }
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
    finding: "An existing CanonicalEnvelope test fixture omitted diagnostics.contentCoverage. The former build plus Vitest command did not typecheck test sources.",
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
  capacityStressEnabled: process.env.ENGINEERING_CAPACITY_STRESS === "1",
  workingTreeCleanBeforeArtifacts: workingTree === "",
  baseline: {
    auditedFunctionalCommit: "18d7a7b657762afb79d304f1cfac4cecdae7468b",
    formerGateStatus: "green on Ubuntu and Windows before the automation installation",
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

The audited baseline commit \`18d7a7b657762afb79d304f1cfac4cecdae7468b\` passed the former Ubuntu and Windows matrix. PRE-001 remains recorded even after correction so the installation history is truthful.

## Dependency advisory inventory

${dependencyText}

Known incomplete product and deployment capabilities remain listed in \`.engineering/REGRESSION_REGISTER.md\`; they are not hidden inside a green result.

## Browser handoff

${overall === "PASSED"
  ? "The automated gate is green. The owner may perform only the visible checks in `MANUAL_TEST_HANDOFF.md`."
  : "The browser handoff is blocked. Fix or explicitly triage the automated failures before asking the owner for visible acceptance."}
`;
writeFileSync(resolve(artifactDir, "VERIFICATION_REPORT.md"), markdownReport);

const handoffStatus = overall === "PASSED" ? "READY FOR OWNER VISIBLE TESTING" : "BLOCKED BY AUTOMATED GATE";
const handoffTemplatePath = resolve(root, ".engineering/MANUAL_TEST_HANDOFF_TEMPLATE.md");
const handoffTemplate = existsSync(handoffTemplatePath)
  ? readFileSync(handoffTemplatePath, "utf8")
  : "# Manual handoff template missing\n\nThe source-controlled handoff template could not be found.";
const manualHandoff = `# Generated Email Shield Browser Handoff

## Status

**${handoffStatus}**

- Repository: \`itxsam57/mailspam\`
- Branch: \`${branch}\`
- Commit: \`${commit}\`
- Automated report: \`artifacts/engineering/VERIFICATION_REPORT.md\`
- Generated: ${finishedAt.toISOString()}

${overall === "PASSED"
  ? "All applicable automated checks passed for this platform invocation. Complete only the visible checks below."
  : `Do not begin browser acceptance. Failed automated stages: ${failures.map((item) => item.name).join(", ")}.`}

---

${handoffTemplate}
`;
writeFileSync(resolve(artifactDir, "MANUAL_TEST_HANDOFF.md"), manualHandoff);

if (process.env.GITHUB_STEP_SUMMARY) {
  appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${markdownReport}\n`);
}

console.log(`\nEngineering gate ${overall}.`);
console.log(`Report: ${resolve(artifactDir, "VERIFICATION_REPORT.md")}`);
console.log(`Manual handoff: ${resolve(artifactDir, "MANUAL_TEST_HANDOFF.md")}`);

if (failures.length) process.exit(1);
