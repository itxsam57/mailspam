from pathlib import Path
import json
import re

ROOT = Path.cwd()

# Cross-platform exact build identity in the recorder.
recorder_path = ROOT / 'server/src/diagnostics/runtimeWorkflowTrace.ts'
recorder = recorder_path.read_text(encoding='utf-8')
if 'execFileSync' not in recorder:
    recorder = 'import { execFileSync } from "node:child_process";\n' + recorder
if 'function resolveRuntimeTraceBuildId' not in recorder:
    marker = 'const DEFAULT_MAX_BYTES'
    pos = recorder.find(marker)
    if pos < 0:
        raise RuntimeError('runtimeWorkflowTrace: constant marker missing')
    helper = '''function resolveRuntimeTraceBuildId(environment: Record<string, string | undefined>): string {
  const explicit = environment.EMAIL_SHIELD_BUILD_COMMIT ?? environment.GITHUB_SHA;
  if (typeof explicit === "string" && /^[0-9a-f]{40}$/i.test(explicit)) return explicit.toLowerCase();
  try {
    const gitHead = execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: process.cwd(),
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 2_000,
    }).trim();
    if (/^[0-9a-f]{40}$/i.test(gitHead)) return gitHead.toLowerCase();
  } catch {}
  return "development";
}

'''
    recorder = recorder[:pos] + helper + recorder[pos:]
# Replace common explicit/fallback build-id expressions.
recorder = re.sub(
    r'const buildId\s*=\s*(?:environment\.)?(?:EMAIL_SHIELD_BUILD_COMMIT|[^;]*GITHUB_SHA)[^;]*;',
    'const buildId = resolveRuntimeTraceBuildId(environment);',
    recorder,
    count=1,
)
# If the exact replacement did not find current source, replace a development
# fallback assignment near runId/filePath.
if 'const buildId = resolveRuntimeTraceBuildId(environment);' not in recorder:
    match = re.search(r'const buildId\s*=\s*[^;]+;', recorder)
    if not match:
        raise RuntimeError('runtimeWorkflowTrace: buildId assignment missing')
    recorder = recorder[:match.start()] + 'const buildId = resolveRuntimeTraceBuildId(environment);' + recorder[match.end():]
recorder_path.write_text(recorder, encoding='utf-8')

# Manifest generator: Windows-safe import.meta.url handling + exact Git SHA
# fallback when the environment does not provide a build identity.
generator_path = ROOT / 'scripts/engineering/generate-runtime-trace-manifest.mjs'
generator = generator_path.read_text(encoding='utf-8')
if 'fileURLToPath' not in generator:
    generator = 'import { fileURLToPath } from "node:url";\n' + generator
if 'execFileSync' not in generator:
    generator = 'import { execFileSync } from "node:child_process";\n' + generator

generator = generator.replace('new URL(import.meta.url).pathname', 'fileURLToPath(import.meta.url)')
if 'function resolveBuildId' not in generator:
    # Insert after imports.
    matches = list(re.finditer(r'^import .*?;\s*$', generator, re.M))
    pos = matches[-1].end() if matches else 0
    helper = '''
function resolveBuildId() {
  const explicit = process.env.EMAIL_SHIELD_BUILD_COMMIT || process.env.GITHUB_SHA;
  if (typeof explicit === 'string' && /^[0-9a-f]{40}$/i.test(explicit)) return explicit.toLowerCase();
  try {
    const gitHead = execFileSync('git', ['rev-parse', 'HEAD'], {
      cwd: process.cwd(),
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 2000,
    }).trim();
    if (/^[0-9a-f]{40}$/i.test(gitHead)) return gitHead.toLowerCase();
  } catch {}
  return 'development';
}
'''
    generator = generator[:pos] + helper + generator[pos:]
# Normalize likely build-id declarations.
generator = re.sub(r'const buildId\s*=\s*[^;]*(?:EMAIL_SHIELD_BUILD_COMMIT|GITHUB_SHA|development)[^;]*;', 'const buildId = resolveBuildId();', generator, count=1)
if 'const buildId = resolveBuildId();' not in generator:
    # Generator may use a differently named immutable identifier.
    match = re.search(r'const\s+(?:buildId|BUILD_ID)\s*=\s*[^;]+;', generator)
    if not match:
        raise RuntimeError('manifest generator: build id declaration not found')
    name = re.search(r'const\s+([A-Za-z_$][A-Za-z0-9_$]*)', match.group(0)).group(1)
    generator = generator[:match.start()] + f'const {name} = resolveBuildId();' + generator[match.end():]
generator_path.write_text(generator, encoding='utf-8')

# Root npm hooks: predev generates the exact source manifest automatically;
# permanent coverage has its own explicit command.
package_path = ROOT / 'package.json'
package = json.loads(package_path.read_text(encoding='utf-8'))
scripts = package.setdefault('scripts', {})
scripts['predev'] = 'node scripts/engineering/generate-runtime-trace-manifest.mjs --output artifacts/engineering/runtime-trace-manifest.json'
scripts['check:runtime-trace'] = 'node scripts/engineering/check-runtime-trace-coverage.mjs'
package_path.write_text(json.dumps(package, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')

# Wire only the canonical Engineering Gate workflow.
workflow_candidates = []
for path in (ROOT / '.github/workflows').glob('*.y*ml'):
    text = path.read_text(encoding='utf-8')
    if 'Engineering Gate' in text and ('windows' in text.lower() or 'matrix' in text.lower()) and 'npm ci' in text:
        workflow_candidates.append((path, text))
if len(workflow_candidates) != 1:
    raise RuntimeError(f'expected one canonical Engineering Gate workflow, found {[p.name for p,_ in workflow_candidates]}')
workflow_path, workflow = workflow_candidates[0]
if 'check:runtime-trace' not in workflow:
    # Add immediately after the existing UI workflow audit when available,
    # otherwise directly after npm ci.
    lines = workflow.splitlines()
    insert_index = None
    indent = '      '
    for index, line in enumerate(lines):
        if 'check:ui' in line or 'check-ui-workflows' in line:
            insert_index = index + 1
            indent = re.match(r'[ \t]*', line).group(0)
            break
    if insert_index is None:
        for index, line in enumerate(lines):
            if re.search(r'\bnpm ci\b', line):
                insert_index = index + 1
                indent = re.match(r'[ \t]*', line).group(0)
                break
    if insert_index is None:
        raise RuntimeError('canonical Engineering Gate: npm ci/UI audit insertion point missing')
    step_indent = indent[:-2] if len(indent) >= 2 else indent
    addition = [
        f'{step_indent}- name: Runtime workflow trace coverage',
        f'{indent}run: npm run check:runtime-trace',
        f'{step_indent}- name: Exact runtime trace source manifest',
        f'{indent}env:',
        f'{indent}  EMAIL_SHIELD_BUILD_COMMIT: ${{{{ github.sha }}}}',
        f'{indent}run: node scripts/engineering/generate-runtime-trace-manifest.mjs --output artifacts/engineering/runtime-trace-manifest.json',
    ]
    lines[insert_index:insert_index] = addition
    workflow = '\n'.join(lines) + '\n'
    workflow_path.write_text(workflow, encoding='utf-8')

print(f'Flight recorder build identity/predev/permanent gate wired through {workflow_path.relative_to(ROOT)}')
