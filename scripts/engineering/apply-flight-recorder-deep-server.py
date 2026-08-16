from pathlib import Path
import re

ROOT = Path.cwd()


def insert_import(path: Path, line: str) -> str:
    source = path.read_text(encoding='utf-8')
    if line in source:
        return source
    matches = list(re.finditer(r'^import .*?;\s*$', source, re.M))
    pos = matches[-1].end() if matches else 0
    return source[:pos] + ('\n' if pos else '') + line + source[pos:]


def statement_bounds(source: str, position: int) -> tuple[int, int]:
    start = source.rfind('\n', 0, position) + 1
    depth = 0
    quote = None
    escape = False
    for index in range(start, len(source)):
        ch = source[index]
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
        if ch in '([{': depth += 1
        elif ch in ')]}': depth = max(0, depth - 1)
        elif ch == ';' and depth == 0:
            return start, index + 1
    raise RuntimeError('statement terminator not found')


def indent_at(source: str, position: int) -> str:
    line_start = source.rfind('\n', 0, position) + 1
    return re.match(r'[ \t]*', source[line_start:]).group(0)


# Provider connection: successful /api/accounts/connect already means provider
# validation plus durable connection persistence succeeded (the route is
# fail-closed/rollback-on-persistence-failure). Record both stages immediately
# before that route's final successful response.
connect_candidates = []
for path in (ROOT / 'server/src').rglob('*.ts'):
    source = path.read_text(encoding='utf-8')
    if '/api/accounts/connect' in source:
        connect_candidates.append((path, source))
if len(connect_candidates) != 1:
    raise RuntimeError(f'expected one account connect route owner, found {[p.as_posix() for p,_ in connect_candidates]}')
connect_path, connect = connect_candidates[0]
if 'provider_authenticated' not in connect:
    connect = insert_import(connect_path, 'import { recordCurrentRuntimeCheckpoint } from "../diagnostics/runtimeTraceRequestContext.js";')
    route_pos = connect.index('/api/accounts/connect')
    window_end = min(len(connect), route_pos + 14000)
    region = connect[route_pos:window_end]
    successes = list(re.finditer(r'(?:sendJson|writeJson|jsonResponse|respondJson|writeHead)\s*\([^;\n]{0,140}(?:200|201)', region))
    if not successes:
        # Fallback to a successful status assignment near the route.
        successes = list(re.finditer(r'statusCode\s*=\s*(?:200|201)', region))
    if not successes:
        raise RuntimeError(f'{connect_path}: no successful account-connect response marker found')
    marker = route_pos + successes[-1].start()
    line_start = connect.rfind('\n', 0, marker) + 1
    indent = re.match(r'[ \t]*', connect[line_start:]).group(0)
    calls = (
        f'{indent}recordCurrentRuntimeCheckpoint("provider_authenticated", {{ stage: "provider", outcome: "success", component: "provider_connect" }});\n'
        f'{indent}recordCurrentRuntimeCheckpoint("connection_persisted", {{ stage: "storage", outcome: "success", component: "provider_connect" }});\n'
    )
    connect = connect[:line_start] + calls + connect[line_start:]
    connect_path.write_text(connect, encoding='utf-8')

# Scan Worker: anchor deep markers to the actual bounded-batch execution path.
scan_path = ROOT / 'server/src/workers/scanWorker.ts'
if not scan_path.exists():
    raise RuntimeError('server/src/workers/scanWorker.ts is missing')
scan = scan_path.read_text(encoding='utf-8')
if 'recordCurrentRuntimeCheckpoint' not in scan:
    scan = insert_import(scan_path, 'import { recordCurrentRuntimeCheckpoint } from "../diagnostics/runtimeTraceRequestContext.js";')

if 'provider_enumeration' not in scan:
    bounded = scan.find('bounded_batches')
    if bounded < 0:
        raise RuntimeError('scanWorker: bounded_batches phase not found')
    start, end = statement_bounds(scan, bounded)
    indent = indent_at(scan, start)
    scan = scan[:start] + f'{indent}recordCurrentRuntimeCheckpoint("provider_enumeration", {{ stage: "worker", outcome: "success", component: "scan_worker" }});\n' + scan[start:]
    bounded = scan.find('bounded_batches', start)
    _, bounded_end = statement_bounds(scan, bounded)

    # First awaited provider/message page operation after the bounded-batch
    # status is the successful page read boundary.
    after = scan[bounded_end:bounded_end + 12000]
    await_matches = list(re.finditer(r'(?m)^(?P<indent>[ \t]*)(?P<stmt>[^\n;]*await[^;]*;)', after))
    page_match = next((m for m in await_matches if re.search(r'(provider|adapter|message|page|folder)', m.group('stmt'), re.I)), None)
    if page_match is None:
        raise RuntimeError('scanWorker: provider page await not found after bounded batch phase')
    page_end = bounded_end + page_match.end()
    page_indent = page_match.group('indent')
    scan = scan[:page_end] + f'\n{page_indent}recordCurrentRuntimeCheckpoint("provider_page_read", {{ stage: "provider", outcome: "success", component: "scan_worker" }});' + scan[page_end:]

if 'message_normalized' not in scan:
    # Anchor normalization/verdict evidence after a page-level processing await
    # that occurs after the provider read. This is a page completion marker,
    # not a per-message content log.
    read_pos = scan.index('provider_page_read')
    tail = scan[read_pos:read_pos + 16000]
    process_match = re.search(r'(?m)^(?P<indent>[ \t]*)(?P<stmt>[^\n;]*await[^;]*(?:process|scan|analy|normal|evalu|engine)[^;]*;)', tail, re.I)
    if process_match is None:
        raise RuntimeError('scanWorker: page processing await not found after provider read')
    process_end = read_pos + process_match.end()
    ind = process_match.group('indent')
    calls = (
        f'\n{ind}recordCurrentRuntimeCheckpoint("message_normalized", {{ stage: "worker", outcome: "success", component: "scan_worker" }});'
        f'\n{ind}recordCurrentRuntimeCheckpoint("verdict_evaluated", {{ stage: "worker", outcome: "success", component: "scan_worker" }});'
    )
    scan = scan[:process_end] + calls + scan[process_end:]

if 'checkpoint_persisted' not in scan:
    checkpoint_matches = list(re.finditer(r'(?m)^(?P<indent>[ \t]*)(?P<stmt>[^\n;]*await[^;]*(?:checkpoint|history|persist|save)[^;]*;)', scan, re.I))
    if not checkpoint_matches:
        raise RuntimeError('scanWorker: persisted checkpoint await not found')
    chosen = checkpoint_matches[-1]
    pos = chosen.end()
    ind = chosen.group('indent')
    scan = scan[:pos] + f'\n{ind}recordCurrentRuntimeCheckpoint("checkpoint_persisted", {{ stage: "storage", outcome: "success", component: "scan_worker" }});' + scan[pos:]

scan_path.write_text(scan, encoding='utf-8')

# Startup: extend the existing runtime trace initialization with a real
# application startup root and terminal checkpoint around the existing boot.
index_path = ROOT / 'server/src/index.ts'
index = index_path.read_text(encoding='utf-8')
if 'startAutomaticRuntimeTrace("application.startup"' not in index:
    index = insert_import(index_path, 'import { recordCurrentRuntimeCheckpoint, startAutomaticRuntimeTrace } from "./diagnostics/runtimeTraceRequestContext.js";')
    init = index.find('initializeRuntimeWorkflowTrace(')
    if init < 0:
        raise RuntimeError('index.ts: runtime trace initialization not found')
    _, init_end = statement_bounds(index, init)
    ind = indent_at(index, init)
    start_calls = (
        f'\n{ind}startAutomaticRuntimeTrace("application.startup", "server_startup");'
        f'\n{ind}recordCurrentRuntimeCheckpoint("started", {{ stage: "system", outcome: "started", component: "server_startup" }});'
    )
    index = index[:init_end] + start_calls + index[init_end:]
    # Use the last startup console line as the existing ready boundary.
    logs = list(re.finditer(r'(?m)^(?P<indent>[ \t]*)console\.(?:log|info)\([^;]*\);', index))
    if not logs:
        raise RuntimeError('index.ts: startup ready log not found')
    ready = logs[-1]
    ready_end = ready.end()
    ind2 = ready.group('indent')
    index = index[:ready_end] + f'\n{ind2}recordCurrentRuntimeCheckpoint("completed", {{ stage: "system", outcome: "success", component: "server_startup" }});' + index[ready_end:]
    index_path.write_text(index, encoding='utf-8')

print(f'Deep server tracing applied: connect={connect_path.relative_to(ROOT)}, scan={scan_path.relative_to(ROOT)}, startup={index_path.relative_to(ROOT)}')
