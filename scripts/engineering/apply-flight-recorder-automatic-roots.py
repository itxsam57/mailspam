from pathlib import Path
import re

ROOT = Path.cwd()


def insert_import(source: str, line: str) -> str:
    if line in source:
        return source
    matches = list(re.finditer(r'^import .*?;\s*$', source, re.M))
    pos = matches[-1].end() if matches else 0
    return source[:pos] + ('\n' if pos else '') + line + source[pos:]


# Add a scoped automatic-run helper inside the AsyncLocalStorage owner.
context_path = ROOT / 'server/src/diagnostics/runtimeTraceRequestContext.ts'
context = context_path.read_text(encoding='utf-8')
if 'export async function runAutomaticRuntimeTrace' not in context:
    marker = 'export function recordCurrentRuntimeCheckpoint('
    pos = context.find(marker)
    if pos < 0:
        raise RuntimeError('runtimeTraceRequestContext: checkpoint function marker missing')
    helper = '''export async function runAutomaticRuntimeTrace<T>(
  workflowId: string,
  component: string,
  task: () => Promise<T> | T,
  provider?: Provider,
): Promise<T> {
  if (!safeLabel(workflowId) || !safeLabel(component) || (provider !== undefined && !PROVIDERS.has(provider))) {
    throw new Error("Invalid automatic runtime trace definition.");
  }
  const context: RuntimeTraceRequestContext = {
    traceId: randomUUID(),
    workflowId,
    actionId: `system.${workflowId}`,
    expectedWorkflow: workflowId,
    ...(provider ? { provider } : {}),
  };
  return storage.run(context, () => validationStorage.run(true, async () => {
    recordCurrentRuntimeCheckpoint("started", {
      stage: "system",
      outcome: "started",
      component,
    });
    try {
      const result = await task();
      recordCurrentRuntimeCheckpoint("completed", {
        stage: "system",
        outcome: "success",
        component,
      });
      return result;
    } catch (error) {
      recordCurrentRuntimeCheckpoint("completed", {
        stage: "system",
        outcome: "failed",
        component,
        errorCode: "automatic_workflow_failed",
      });
      throw error;
    }
  }));
}

'''
    context = context[:pos] + helper + context[pos:]
    context_path.write_text(context, encoding='utf-8')


def parse_async_candidates():
    candidates = []
    pattern = re.compile(r'async\s+(?:function\s+)?(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*\([^)]*\)\s*(?::\s*[^\{]+)?\{')
    for path in (ROOT / 'server/src').rglob('*.ts'):
        if 'diagnostics' in path.parts:
            continue
        source = path.read_text(encoding='utf-8')
        for match in pattern.finditer(source):
            open_brace = match.end() - 1
            depth = 0
            end = None
            quote = None
            escape = False
            for i in range(open_brace, len(source)):
                ch = source[i]
                if quote:
                    if escape:
                        escape = False
                    elif ch == '\\':
                        escape = True
                    elif ch == quote:
                        quote = None
                    continue
                if ch in ('\"', "'", '`'):
                    quote = ch
                    continue
                if ch == '{': depth += 1
                elif ch == '}':
                    depth -= 1
                    if depth == 0:
                        end = i
                        break
            if end is None:
                continue
            candidates.append({
                'path': path,
                'source': source,
                'name': match.group('name'),
                'start': match.start(),
                'open': open_brace,
                'end': end,
                'body': source[open_brace + 1:end],
            })
    return candidates


def choose(kind: str, candidates):
    scored = []
    for c in candidates:
        name = c['name'].lower()
        path = c['path'].as_posix().lower()
        body = c['body'].lower()
        score = 0
        if kind == 'provider.restore_sessions':
            if 'restore' in name: score += 20
            if any(token in name for token in ('session', 'connection', 'provider')): score += 16
            if any(token in path for token in ('session', 'provider', 'connection')): score += 12
            if 'vault' in body or 'credential' in body: score += 8
            if 'provider' in body: score += 6
        elif kind == 'protection.background.run':
            if 'background' in name: score += 24
            if 'background' in path: score += 20
            if any(token in name for token in ('run', 'scan', 'execute', 'tick', 'process')): score += 12
            if 'scan' in body or 'worker' in body: score += 10
            if 'scheduled' in body: score += 5
        elif kind == 'protection.realtime.run':
            if 'realtime' in name or 'real_time' in name: score += 24
            if 'realtime' in path or 'real-time' in path: score += 20
            if any(token in name for token in ('run', 'scan', 'execute', 'poll', 'process', 'handle')): score += 12
            if 'scan' in body or 'worker' in body or 'trigger' in body: score += 10
        if score:
            scored.append((score, c))
    scored.sort(key=lambda item: item[0], reverse=True)
    if not scored or scored[0][0] < 30:
        raise RuntimeError(f'no strong automatic workflow owner for {kind}; top={[(s, c["path"].as_posix(), c["name"]) for s,c in scored[:5]]}')
    if len(scored) > 1 and scored[1][0] == scored[0][0]:
        raise RuntimeError(f'ambiguous automatic workflow owner for {kind}; top={[(s, c["path"].as_posix(), c["name"]) for s,c in scored[:5]]}')
    return scored[0][1]


def wrap_candidate(kind: str, component: str, candidate):
    path = candidate['path']
    source = path.read_text(encoding='utf-8')
    if f'runAutomaticRuntimeTrace("{kind}"' in source:
        return
    # Re-find the exact signature by name in the current source.
    pattern = re.compile(rf'async\s+(?:function\s+)?{re.escape(candidate["name"])}\s*\([^)]*\)\s*(?::\s*[^\{{]+)?\{{')
    match = pattern.search(source)
    if not match:
        raise RuntimeError(f'{path}: async owner {candidate["name"]} moved')
    open_brace = match.end() - 1
    depth = 0
    end = None
    quote = None
    escape = False
    for i in range(open_brace, len(source)):
        ch = source[i]
        if quote:
            if escape: escape = False
            elif ch == '\\': escape = True
            elif ch == quote: quote = None
            continue
        if ch in ('\"', "'", '`'):
            quote = ch
            continue
        if ch == '{': depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                end = i
                break
    if end is None:
        raise RuntimeError(f'{path}: async owner {candidate["name"]} body not found')
    body = source[open_brace + 1:end]
    indent_match = re.search(r'\n([ \t]+)\S', body)
    indent = indent_match.group(1) if indent_match else '  '
    wrapped = f'''\n{indent}return runAutomaticRuntimeTrace("{kind}", "{component}", async () => {{{body}\n{indent}}});\n'''
    source = source[:open_brace + 1] + wrapped + source[end:]
    relative = path.relative_to(ROOT / 'server/src')
    depth_dirs = len(relative.parts) - 1
    prefix = '../' * depth_dirs if depth_dirs else './'
    source = insert_import(source, f'import {{ runAutomaticRuntimeTrace }} from "{prefix}diagnostics/runtimeTraceRequestContext.js";')
    path.write_text(source, encoding='utf-8')

candidates = parse_async_candidates()
selections = [
    ('provider.restore_sessions', 'provider_restore', choose('provider.restore_sessions', candidates)),
    ('protection.background.run', 'background_protection', choose('protection.background.run', candidates)),
    ('protection.realtime.run', 'realtime_protection', choose('protection.realtime.run', candidates)),
]
seen = set()
for kind, component, candidate in selections:
    key = (candidate['path'], candidate['name'])
    if key in seen:
        raise RuntimeError(f'automatic workflow owner collision: {kind} selected {candidate["path"]}:{candidate["name"]}')
    seen.add(key)
    wrap_candidate(kind, component, candidate)

print('Automatic roots wrapped:')
for kind, _, candidate in selections:
    print(f'  {kind} -> {candidate["path"].relative_to(ROOT)}::{candidate["name"]}')
