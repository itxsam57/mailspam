import { execFileSync } from "node:child_process";
import {
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, extname, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const scriptPath = fileURLToPath(import.meta.url);
const root = resolve(dirname(scriptPath), "../..");
const DEFAULT_OUTPUT = resolve(root, "artifacts/engineering/runtime-trace-manifest.json");
const COMMIT_SHA = /^[0-9a-f]{40}$/i;
const SAFE_LABEL = /^[a-z0-9][a-z0-9_.:/-]{0,159}$/i;
const SOURCE_EXTENSIONS = new Set([".ts", ".js"]);

function gitHead() {
  const value = execFileSync("git", ["rev-parse", "HEAD"], {
    cwd: root,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
  if (!COMMIT_SHA.test(value)) throw new Error("The checked-out Git HEAD is not a full commit SHA.");
  return value.toLowerCase();
}

function exactBuildId() {
  const head = gitHead();
  const supplied = [
    process.env.EMAIL_SHIELD_BUILD_COMMIT?.trim(),
    process.env.GITHUB_SHA?.trim(),
  ].filter(Boolean);
  for (const candidate of supplied) {
    if (!COMMIT_SHA.test(candidate)) throw new Error("Runtime trace build identity must be a full 40-character Git commit SHA.");
    if (candidate.toLowerCase() !== head) {
      throw new Error(`Runtime trace build identity ${candidate} does not match checked-out HEAD ${head}.`);
    }
  }
  return head;
}

function walk(directory) {
  const files = [];
  for (const name of readdirSync(directory).sort()) {
    const path = resolve(directory, name);
    const stat = statSync(path);
    if (stat.isDirectory()) files.push(...walk(path));
    else if (SOURCE_EXTENSIONS.has(extname(path))) files.push(path);
  }
  return files;
}

function repoPath(path) {
  return relative(root, path).split(sep).join("/");
}

function lineNumber(source, index) {
  let line = 1;
  for (let cursor = 0; cursor < index; cursor += 1) {
    if (source.charCodeAt(cursor) === 10) line += 1;
  }
  return line;
}

function nearestOwner(source, index, path) {
  const lines = source.slice(0, index).split("\n");
  for (let lineIndex = lines.length - 1; lineIndex >= Math.max(0, lines.length - 140); lineIndex -= 1) {
    const line = lines[lineIndex];
    const functionMatch = line.match(/(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(/);
    if (functionMatch) return functionMatch[1];
    const assignedMatch = line.match(/(?:const|let)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][A-Za-z0-9_$]*)\s*=>/);
    if (assignedMatch) return assignedMatch[1];
    const methodMatch = line.match(/^\s*(?:async\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*\([^)]*\)\s*\{/);
    if (methodMatch && !["if", "for", "while", "switch", "catch"].includes(methodMatch[1])) return methodMatch[1];
  }
  return basename(path).replace(/\.[^.]+$/, "");
}

function safeComponent(path, explicit) {
  if (explicit && SAFE_LABEL.test(explicit)) return explicit;
  return repoPath(path)
    .replace(/\.(?:ts|js)$/, "")
    .replace(/[^A-Za-z0-9_.:/-]+/g, "_")
    .slice(0, 160);
}

function registryWorkflowIds() {
  const path = resolve(root, "server/src/diagnostics/workflowRegistry.ts");
  const source = readFileSync(path, "utf8");
  const ids = new Set();
  for (const regex of [
    /linearWorkflow\(\s*["']([^"']+)["']/g,
    /uiWorkflow\(\s*["']([^"']+)["']/g,
    /automaticWorkflow\(\s*["']([^"']+)["']/g,
  ]) {
    for (const match of source.matchAll(regex)) ids.add(match[1]);
  }
  for (const match of source.matchAll(/scanWorkflow\(\s*["'](quick|full|spam)["']/g)) {
    ids.add(`mailbox.scan.${match[1]}`);
  }
  return [...ids].sort((a, b) => a.localeCompare(b));
}

function literalObjectField(body, name) {
  return body.match(new RegExp(`\\b${name}\\s*:\\s*["']([^"']+)["']`))?.[1] ?? null;
}

function addEntry(entries, entry) {
  if (!SAFE_LABEL.test(entry.checkpointId) || !SAFE_LABEL.test(entry.workflowId)) return;
  const existing = entries.get(entry.checkpointId);
  // A literal callsite is a stronger owner than the central dynamic fallback.
  if (!existing || existing.dynamic === true) entries.set(entry.checkpointId, entry);
}

function dynamicRequestedOwners(entries, workflowIds) {
  const path = resolve(root, "web/runtime-workflow-trace.js");
  const source = readFileSync(path, "utf8");
  const marker = "checkpointId: `${context.workflowId}.requested`";
  const index = source.indexOf(marker);
  if (index < 0) throw new Error("Central browser trace owner no longer emits the dynamic requested checkpoint.");
  const line = lineNumber(source, index);
  const owner = nearestOwner(source, index, path);
  for (const workflowId of workflowIds) {
    addEntry(entries, {
      checkpointId: `${workflowId}.requested`,
      workflowId,
      component: "browser",
      sourcePath: repoPath(path),
      owner,
      line,
      dynamic: true,
    });
  }
}

function serverLiteralCheckpoints(entries, path, source) {
  const patterns = [
    /recordRuntimeCheckpoint\s*\(\s*\{([\s\S]*?)\}\s*\)/g,
    /recordRuntimeTraceCheckpoint\s*\([^,]+,\s*\{([\s\S]*?)\}\s*\)/g,
  ];
  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern)) {
      const body = match[1];
      const checkpointId = literalObjectField(body, "checkpointId");
      const workflowId = literalObjectField(body, "workflowId");
      if (!checkpointId || !workflowId) continue;
      addEntry(entries, {
        checkpointId,
        workflowId,
        component: safeComponent(path, literalObjectField(body, "component")),
        sourcePath: repoPath(path),
        owner: nearestOwner(source, match.index, path),
        line: lineNumber(source, match.index),
        dynamic: false,
      });
    }
  }
}

function browserLiteralCheckpoints(entries, path, source, workflowIds) {
  const sortedWorkflows = [...workflowIds].sort((a, b) => b.length - a.length || a.localeCompare(b));
  const pattern = /(?:emailShieldRuntimeTrace(?:\?\.|\.)|window\.emailShieldRuntimeTrace(?:\?\.|\.))checkpoint\s*\(\s*["']([^"']+)["']/g;
  for (const match of source.matchAll(pattern)) {
    const checkpointId = match[1];
    const workflowId = sortedWorkflows.find((id) => checkpointId === id || checkpointId.startsWith(`${id}.`));
    if (!workflowId) throw new Error(`${repoPath(path)} emits unregistered runtime checkpoint ${checkpointId}.`);
    addEntry(entries, {
      checkpointId,
      workflowId,
      component: safeComponent(path),
      sourcePath: repoPath(path),
      owner: nearestOwner(source, match.index, path),
      line: lineNumber(source, match.index),
      dynamic: false,
    });
  }
}

export function generateRuntimeTraceManifest() {
  const buildId = exactBuildId();
  const workflowIds = registryWorkflowIds();
  const entries = new Map();
  dynamicRequestedOwners(entries, workflowIds);

  const files = [
    ...walk(resolve(root, "server/src")),
    ...walk(resolve(root, "web")),
  ];
  for (const path of files) {
    const source = readFileSync(path, "utf8");
    if (repoPath(path).startsWith("server/src/")) serverLiteralCheckpoints(entries, path, source);
    else browserLiteralCheckpoints(entries, path, source, workflowIds);
  }

  const checkpoints = [...entries.values()]
    .map(({ dynamic: _dynamic, ...entry }) => entry)
    .sort((a, b) => a.checkpointId.localeCompare(b.checkpointId));
  if (checkpoints.length === 0) throw new Error("Runtime trace manifest generation found no checkpoint owners.");
  return { schemaVersion: 1, buildId, checkpoints };
}

function cliOutputPath() {
  const outputIndex = process.argv.indexOf("--output");
  if (outputIndex < 0) return DEFAULT_OUTPUT;
  const value = process.argv[outputIndex + 1];
  if (!value) throw new Error("--output requires a path.");
  return resolve(root, value);
}

if (resolve(process.argv[1] || "") === scriptPath) {
  const output = cliOutputPath();
  const manifest = generateRuntimeTraceManifest();
  mkdirSync(dirname(output), { recursive: true });
  writeFileSync(output, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  console.log(`Runtime trace manifest generated: ${relative(root, output)} (${manifest.checkpoints.length} checkpoints) for ${manifest.buildId}.`);
}
