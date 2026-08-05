import { spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const root = process.cwd();
const artifactDir = resolve(root, process.env.ENGINEERING_ARTIFACT_DIR || "artifacts/engineering");
mkdirSync(artifactDir, { recursive: true });

const npmCli = process.env.npm_execpath;
if (!npmCli) {
  console.error("FAIL: npm_execpath is unavailable. Run this command through `npm run audit:inventory`.");
  process.exit(1);
}

const outcome = spawnSync(process.execPath, [npmCli, "audit", "--json"], {
  cwd: root,
  encoding: "utf8",
  env: process.env,
  shell: false,
  maxBuffer: 20 * 1024 * 1024,
});

let parsed;
try {
  parsed = JSON.parse(outcome.stdout || "{}");
} catch (error) {
  console.error(`FAIL: npm audit did not return parseable JSON: ${error.message}`);
  if (outcome.stderr) console.error(outcome.stderr.trim());
  process.exit(1);
}

const vulnerabilities = parsed.metadata?.vulnerabilities ?? {};
const summary = {
  generatedAt: new Date().toISOString(),
  scope: "all installed production and development dependencies",
  npmExitCode: typeof outcome.status === "number" ? outcome.status : null,
  counts: {
    info: Number(vulnerabilities.info ?? 0),
    low: Number(vulnerabilities.low ?? 0),
    moderate: Number(vulnerabilities.moderate ?? 0),
    high: Number(vulnerabilities.high ?? 0),
    critical: Number(vulnerabilities.critical ?? 0),
    total: Number(vulnerabilities.total ?? 0),
  },
  dependencyCounts: parsed.metadata?.dependencies ?? null,
  advisoryPackages: Object.entries(parsed.vulnerabilities ?? {}).map(([name, value]) => ({
    name,
    severity: value?.severity ?? "unknown",
    direct: value?.isDirect === true,
    range: value?.range ?? null,
    fixAvailable: value?.fixAvailable ?? false,
    via: Array.isArray(value?.via)
      ? value.via.map((item) => typeof item === "string" ? item : {
          source: item?.source ?? null,
          name: item?.name ?? null,
          severity: item?.severity ?? null,
          title: item?.title ?? null,
          url: item?.url ?? null,
          range: item?.range ?? null,
        })
      : [],
  })),
  blockingPolicy: "This inventory is evidence only. npm run audit:prod separately blocks high or critical production dependency findings.",
};

writeFileSync(resolve(artifactDir, "dependency-audit.json"), `${JSON.stringify(summary, null, 2)}\n`);

console.log("Dependency advisory inventory generated.");
console.log(`All-dependency counts: ${summary.counts.total} total; ${summary.counts.critical} critical, ${summary.counts.high} high, ${summary.counts.moderate} moderate, ${summary.counts.low} low.`);
console.log("See artifacts/engineering/dependency-audit.json for package-level details.");
