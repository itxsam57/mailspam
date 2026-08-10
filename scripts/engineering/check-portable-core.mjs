import { existsSync, readFileSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";

const root = process.cwd();
const entry = resolve(root, "server/src/core/portableCore.ts");
const allowedExternalModules = new Set(["tldts"]);
const forbiddenPathSegments = ["/adapters/", "/api/", "/oauth/", "/security/", "/workers/"];
const visited = new Set();
const failures = [];

function sourcePath(importer, specifier) {
  const candidate = resolve(dirname(importer), specifier.replace(/\.js$/, ".ts"));
  if (existsSync(candidate)) return candidate;
  const indexCandidate = resolve(dirname(importer), specifier, "index.ts");
  return existsSync(indexCandidate) ? indexCandidate : null;
}

function visit(path) {
  if (visited.has(path)) return;
  visited.add(path);
  const projectPath = relative(root, path).split("\\").join("/");
  if (forbiddenPathSegments.some((segment) => `/${projectPath}`.includes(segment))) {
    failures.push(`Portable core dependency crosses a platform-shell boundary: ${projectPath}`);
  }
  const source = readFileSync(path, "utf8");
  if (/\b(?:fetch|XMLHttpRequest|WebSocket)\s*\(/.test(source)) failures.push(`Portable core dependency performs network I/O: ${projectPath}`);
  if (/\b(?:process|Buffer|Deno|Bun)\s*\./.test(source)) failures.push(`Portable core dependency uses a platform runtime global: ${projectPath}`);

  const imports = [...source.matchAll(/(?:import|export)\s+(?:type\s+)?(?:[^"']*?\s+from\s+)?["']([^"']+)["']/g)]
    .map((match) => match[1]);
  for (const specifier of imports) {
    if (!specifier) continue;
    if (specifier.startsWith("node:") || ["fs", "path", "os", "http", "https", "net", "tls", "crypto", "child_process", "worker_threads"].includes(specifier)) {
      failures.push(`Portable core dependency imports a host module in ${projectPath}: ${specifier}`);
      continue;
    }
    if (!specifier.startsWith(".")) {
      if (!allowedExternalModules.has(specifier)) failures.push(`Portable core dependency imports an unapproved external module in ${projectPath}: ${specifier}`);
      continue;
    }
    const dependency = sourcePath(path, specifier);
    if (!dependency) failures.push(`Portable core dependency could not be resolved from ${projectPath}: ${specifier}`);
    else visit(dependency);
  }
}

visit(entry);
if (failures.length) {
  for (const failure of [...new Set(failures)]) console.error(`FAIL: ${failure}`);
  process.exit(1);
}
console.log(`Portable core dependency boundary passed for ${visited.size} source modules.`);
