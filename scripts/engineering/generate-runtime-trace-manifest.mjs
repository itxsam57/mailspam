import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import process from "node:process";

const root = process.cwd();
const DEFAULT_OUTPUT = resolve(root, "artifacts/engineering/runtime-trace-manifest.json");
const SAFE_LABEL = /^[a-z0-9][a-z0-9_.:/-]{0,159}$/i;
const COMMIT_SHA = /^[0-9a-f]{40}$/i;
const SOURCE_EXTENSIONS = new Set([".ts", ".js"]);

function gitHead() {
  try {
    return execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
  } catch {
    return "";
  }
}

function resolveBuildId() {
  const candidate = process.env.EMAIL_SHIELD_BUILD_COMMIT?.trim()
    || process.env.GITHUB_SHA?.trim()
    || gitHead();
  if (!COMMIT_SHA.test(candidate)) throw new Error("A full 40-character Git build commit is required to generate the runtime trace manifest.");
  return candidate.toLowerCase();
}

function extension(path) {
  const index = path.lastIndexOf(".");
  return index >= 0 ? path.slice(index) : "";
}

function walk(directory) {
  const files = [];
  for (const name of readdirSync(directory).sort()) {
    const path = join(directory, name);
    const stat = statSync(path);
    if (stat.isDirectory()) files.push(...walk(path));
    else if (SOURCE_EXTENSIONS.has(extension(path))) files.push(path);
  }
  return files;
}

function repoPath(path) {
  return relative(root, path).split(sep).join("/");
}

function lineNumber(source, index) {
  let line = 1;
  for (let cursor = 0; cursor < index; cursor += 1) if (source.charCodeAt(cursor) === 10) line += 1;
  return line;
}

function nearestOwner(source, index, path) {
  const prefix = source.slice(0, index);
  const lines = prefix.split("\n");
  for (let lineIndex = lines.length - 1; lineIndex >= Math.max(0, lines.length - 120); lineIndex -= 1) {
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
  const source = readFileSync(resolve(root, "server/src/diagnostics/workflowRegistry.ts"), "utf8");
  const ids = new Set();
  for (const regex of [
    /linearWorkflow\(\s*["']([^"']+)["']/g,
    /automaticWorkflow\(\s*["']([^"']+)["']/g,
  ]) {
    for (const match of source.matchAll(regex)) ids.add(match[1]);
  }
  for (const match of source.matchAll(/scanWorkflow\(\s*["'](quick|full|spam)["']/g)) ids.add(`mailbox.scan.${match[1]}`);
  return [...ids].sort((a, b) => b.length - a.length || a.localeCompare(b));
}

function workflowForCheckpoint(checkpointId, workflowIds) {
  return workflowIds.find((workflowId) => checkpointId === workflowId || checkpointId.startsWith(`${workflowId}.`)) || null;
}

function extractObjectLiteralField(body, name) {
  const match = body.match(new RegExp(`\\b${name}\\s*:\\s*["']([^"']+)["']`));
  return match?.[1] || null;
}

function serverCheckpoints(path, source) {
  const entries = [];
  const call = /recordRuntimeCheckpoint\s*\(\s*\{([\s\S]*?)\}\s*\)/g;
  for (const match of source.matchAll(call)) {
    const body = match[1];
    const checkpointId = extractObjectLiteralField(body, "checkpointId");
    const workflowId = extractObjectLiteralField(body, "workflowId");
    if (!checkpointId || !workflowId) throw new Error(`${repoPath(path)} contains a runtime checkpoint without literal checkpointId/workflowId.`);
    if (!SAFE_LABEL.test(checkpointId) || !SAFE_LABEL.test(workflowId)) throw new Error(`${repoPath(path)} contains an invalid runtime checkpoint label.`);
    entries.push({
      checkpointId,
      workflowId,
      component: safeComponent(path, extractObjectLiteralField(body, "component")),
      sourcePath: repoPath(path),
      owner: nearestOwner(source, match.index, path),
      line: lineNumber(source, match.index),
    });
  }
  return entries;
}

function browserCheckpoints(path, source, workflowIds) {
  const entries = [];
  const call = /(?:emailShieldRuntimeTrace\?\.|emailShieldRuntimeTrace\.)checkpoint\s*\(\s*["']([^"']+)["']/g;
  for (const match of source.matchAll(call)) {
    const checkpointId = match[1];
    const workflowId = workflowForCheckpoint(checkpointId, workflowIds);
    if (!workflowId) throw new Error(`${repoPath(path)} checkpoint ${checkpointId} is not owned by a registered workflow.`);
    entries.push({
      checkpointId,
      workflowId,
      component: safeComponent(path),
      sourcePath: repoPath(path),
      owner: nearestOwner(source, match.index, path),
      line: lineNumber(source, match.index),
    });
  }
  return entries;
}

export function generateRuntimeTraceManifest() {
  const workflowIds = registryWorkflowIds();
  const files = [
    ...walk(resolve(root, "server/src")),
    ...walk(resolve(root, "web")),
  ];
  const checkpoints = [];
  for (const path of files) {
    const source = readFileSync(path, "utf8");
    checkpoints.push(...serverCheckpoints(path, source));
    if (repoPath(path).startsWith("web/")) checkpoints.push(...browserCheckpoints(path, source, workflowIds));
  }
  checkpoints.sort((a, b) => a.checkpointId.localeCompare(b.checkpointId) || a.sourcePath.localeCompare(b.sourcePath) || a.line - b.line);
  const seen = new Set();
  for (const entry of checkpoints) {
    if (seen.has(entry.checkpointId)) throw new Error(`Duplicate runtime checkpoint id: ${entry.checkpointId}`);
    seen.add(entry.checkpointId);
  }
  return { schemaVersion: 1, buildId: resolveBuildId(), checkpoints };
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(new URL(import.meta.url).pathname)) {
  const outputIndex = process.argv.indexOf("--output");
  const output = outputIndex >= 0 && process.argv[outputIndex + 1]
    ? resolve(root, process.argv[outputIndex + 1])
    : DEFAULT_OUTPUT;
  const manifest = generateRuntimeTraceManifest();
  mkdirSync(dirname(output), { recursive: true });
  writeFileSync(output, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  console.log(`Runtime trace manifest generated: ${relative(root, output)} (${manifest.checkpoints.length} checkpoints) for ${manifest.buildId}.`);
}
