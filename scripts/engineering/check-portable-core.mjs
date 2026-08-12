import { existsSync, readFileSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";

const root = process.cwd();
const entries = [
  resolve(root, "server/src/core/portableCore.ts"),
  resolve(root, "server/src/platform/accountFamilyTypes.ts"),
  resolve(root, "server/src/platform/accountFamilyPorts.ts"),
  resolve(root, "server/src/platform/accountFamilyService.ts"),
  resolve(root, "server/src/platform/familyThreatProtocol.ts"),
];
const allowedExternalModules = new Set(["tldts"]);
const forbiddenPathSegments = ["/adapters/", "/api/", "/oauth/", "/security/", "/workers/", "/accountService/"];
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
    failures.push(`Portable domain dependency crosses a platform-shell boundary: ${projectPath}`);
  }
  const source = readFileSync(path, "utf8");
  if (/\b(?:fetch|XMLHttpRequest|WebSocket)\s*\(/.test(source)) failures.push(`Portable domain dependency performs network I/O: ${projectPath}`);
  if (/\b(?:process|Buffer|Deno|Bun)\s*\./.test(source)) failures.push(`Portable domain dependency uses a platform runtime global: ${projectPath}`);

  const imports = [...source.matchAll(/(?:import|export)\s+(?:type\s+)?(?:[^"']*?\s+from\s+)?["']([^"']+)["']/g)]
    .map((match) => match[1]);
  for (const specifier of imports) {
    if (!specifier) continue;
    if (specifier.startsWith("node:") || ["fs", "path", "os", "http", "https", "net", "tls", "crypto", "child_process", "worker_threads"].includes(specifier)) {
      failures.push(`Portable domain dependency imports a host module in ${projectPath}: ${specifier}`);
      continue;
    }
    if (!specifier.startsWith(".")) {
      if (!allowedExternalModules.has(specifier)) failures.push(`Portable domain dependency imports an unapproved external module in ${projectPath}: ${specifier}`);
      continue;
    }
    const dependency = sourcePath(path, specifier);
    if (!dependency) failures.push(`Portable domain dependency could not be resolved from ${projectPath}: ${specifier}`);
    else visit(dependency);
  }
}

for (const entry of entries) visit(entry);
if (failures.length) {
  for (const failure of [...new Set(failures)]) console.error(`FAIL: ${failure}`);
  process.exit(1);
}
console.log(`Portable scanner/account/family dependency boundary passed for ${visited.size} source modules.`);
