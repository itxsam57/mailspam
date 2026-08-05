import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const root = process.cwd();
const failures = [];
const warnings = [];

function requireCondition(condition, message) {
  if (!condition) failures.push(message);
}

function readJson(path) {
  return JSON.parse(readFileSync(resolve(root, path), "utf8"));
}

function git(args) {
  try {
    return execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  } catch (error) {
    warnings.push(`Git command failed: git ${args.join(" ")} (${error.message})`);
    return "";
  }
}

const requiredFiles = [
  "package.json",
  "package-lock.json",
  "server/package.json",
  "server/tsconfig.json",
  "server/tsconfig.build.json",
  "server/vitest.config.ts",
  "server/src/index.ts",
  "server/src/api/server.ts",
  "web/index.html",
  ".github/workflows/verify.yml",
  ".engineering/PROJECT_PROFILE.md",
  ".engineering/TEST_MATRIX.md",
  ".engineering/REGRESSION_REGISTER.md",
];
for (const path of requiredFiles) requireCondition(existsSync(resolve(root, path)), `Required repository file is missing: ${path}`);

const nodeMajor = Number(process.versions.node.split(".")[0]);
requireCondition(nodeMajor === 22, `Node.js 22 is required; current runtime is ${process.versions.node}.`);

const rootPackage = readJson("package.json");
const serverPackage = readJson("server/package.json");
const lockfile = readJson("package-lock.json");

requireCondition(rootPackage.private === true, "Root package must remain private.");
requireCondition(Array.isArray(rootPackage.workspaces) && rootPackage.workspaces.includes("server"), "Root npm workspace must include server.");
requireCondition(lockfile.lockfileVersion === 3, `npm lockfile v3 is required; found ${lockfile.lockfileVersion}.`);
requireCondition(lockfile.name === rootPackage.name, "package.json and package-lock.json project names differ.");
requireCondition(serverPackage.type === "module", "Server workspace must remain an ES module package.");

for (const script of [
  "preflight", "typecheck", "build", "test:unit", "test:integration",
  "check:web", "smoke:server", "audit:prod", "gate", "verify",
]) {
  requireCondition(typeof rootPackage.scripts?.[script] === "string", `Required root npm script is missing: ${script}`);
}

const tracked = git(["ls-files"]).split(/\r?\n/).filter(Boolean);
const forbiddenTracked = tracked.filter((path) =>
  /(^|\/)\.env($|\.)/.test(path) && !path.endsWith(".env.example") ||
  /(^|\/)(personal-policy\.key|personal-policies\.enc\.json)$/.test(path) ||
  /(^|\/)(node_modules|dist|coverage|artifacts\/engineering)(\/|$)/.test(path)
);
requireCondition(forbiddenTracked.length === 0, `Generated, encrypted or secret files are tracked: ${forbiddenTracked.join(", ")}`);

const textExtensions = /\.(?:ts|js|mjs|cjs|json|yml|yaml|md|html|css)$/i;
const secretPatterns = [
  { name: "private key", pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
  { name: "GitHub token", pattern: /\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b/ },
  { name: "OpenAI-style secret", pattern: /\bsk-[A-Za-z0-9_-]{20,}\b/ },
  { name: "Google API key", pattern: /\bAIza[0-9A-Za-z_-]{30,}\b/ },
  { name: "Slack token", pattern: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/ },
];

for (const path of tracked.filter((value) => textExtensions.test(value) && !value.startsWith("fixtures/"))) {
  const absolute = resolve(root, path);
  if (!existsSync(absolute)) continue;
  const content = readFileSync(absolute, "utf8");
  if (/^(?:<<<<<<< .+|=======|>>>>>>> .+)$/m.test(content)) failures.push(`Merge-conflict marker found in ${path}.`);
  for (const secret of secretPatterns) {
    if (secret.pattern.test(content)) failures.push(`Possible ${secret.name} found in tracked file ${path}.`);
  }
}

const branch = git(["branch", "--show-current"]) || "detached/unknown";
const commit = git(["rev-parse", "--short=12", "HEAD"]) || "unknown";
const status = git(["status", "--porcelain"]);
if (status) warnings.push("Working tree is not clean. The gate reports this but does not erase or rewrite local work.");

console.log(`Project: ${rootPackage.name}`);
console.log(`Branch: ${branch}`);
console.log(`Commit: ${commit}`);
console.log(`Node: ${process.versions.node}`);
console.log(`Tracked files inspected: ${tracked.length}`);
for (const warning of warnings) console.warn(`WARNING: ${warning}`);

if (failures.length) {
  for (const failure of failures) console.error(`FAIL: ${failure}`);
  process.exit(1);
}

console.log("Preflight audit checks passed.");