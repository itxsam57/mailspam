from pathlib import Path
import re

ROOT = Path.cwd()
path = ROOT / 'server/src/api/runtimeWorkflowTraceRoutes.ts'
source = path.read_text(encoding='utf-8')


def insert_import(text: str, line: str) -> str:
    if line in text:
        return text
    matches = list(re.finditer(r'^import .*?;\s*$', text, re.M))
    pos = matches[-1].end() if matches else 0
    return text[:pos] + ('\n' if pos else '') + line + text[pos:]

source = insert_import(source, 'import { diagnoseRuntimeTrace, loadRuntimeTraceManifest } from "../diagnostics/runtimeTraceDiagnosis.js";')
source = insert_import(source, 'import { runtimeWorkflowTrace } from "../diagnostics/runtimeWorkflowTrace.js";')

if '/api/dev/runtime-trace/diagnosis' not in source:
    marker_pos = source.find('/api/dev/runtime-trace/current')
    if marker_pos < 0:
        raise RuntimeError('runtimeWorkflowTraceRoutes: current route marker missing')
    if_start = source.rfind('\n', 0, source.rfind('if', 0, marker_pos)) + 1
    header_match = re.search(r'if\s*\((?P<condition>[\s\S]*?)\)\s*\{', source[if_start:marker_pos + 200])
    if not header_match:
        raise RuntimeError('runtimeWorkflowTraceRoutes: current route if condition not found')
    condition = header_match.group('condition')
    current_literal = re.search(r'(["\'])/api/dev/runtime-trace/current\1', condition)
    if not current_literal:
        raise RuntimeError('runtimeWorkflowTraceRoutes: current path literal not in route condition')
    url_match = re.search(r'([A-Za-z_$][A-Za-z0-9_$]*)\.pathname', condition)
    if not url_match:
        raise RuntimeError('runtimeWorkflowTraceRoutes: URL variable not found')
    url_var = url_match.group(1)

    # Locate the enclosing function and its request/response parameter names.
    prefix = source[:if_start]
    function_matches = list(re.finditer(r'(?:export\s+)?function\s+[A-Za-z_$][A-Za-z0-9_$]*\s*\((?P<params>[^)]*)\)[^{]*\{', prefix))
    if not function_matches:
        raise RuntimeError('runtimeWorkflowTraceRoutes: enclosing handler function not found')
    params = function_matches[-1].group('params')
    identifiers = []
    for raw in params.split(','):
        match = re.match(r'\s*([A-Za-z_$][A-Za-z0-9_$]*)', raw)
        if match:
            identifiers.append(match.group(1))
    if len(identifiers) < 2:
        raise RuntimeError('runtimeWorkflowTraceRoutes: request/response parameters not found')
    req, res = identifiers[0], identifiers[1]

    # Clone the exact protected-read statement used by the current route so the
    # new routes inherit the existing loopback/session/origin/CSRF boundary.
    block_window = source[if_start:if_start + 5000]
    security_line_match = re.search(r'(?m)^(?P<indent>[ \t]*)(?P<line>[^\n]*(?:requireProtectedRead|requireProtectedMutation)\([^\n]+)$', block_window)
    if not security_line_match:
        raise RuntimeError('runtimeWorkflowTraceRoutes: protected security statement not found')
    security_line = security_line_match.group('line').rstrip()
    indent = re.match(r'[ \t]*', source[if_start:]).group(0)
    inner = indent + '  '

    manifest_condition = condition.replace('/api/dev/runtime-trace/current', '/api/dev/runtime-trace/manifest')
    diagnosis_condition = condition.replace('/api/dev/runtime-trace/current', '/api/dev/runtime-trace/diagnosis')
    branches = f'''{indent}if ({manifest_condition}) {{
{inner}{security_line.strip()}
{inner}const recorder = runtimeWorkflowTrace();
{inner}const manifest = recorder?.enabled ? loadRuntimeTraceManifest(recorder.buildId) : null;
{inner}if (!manifest) {{
{inner}  {res}.statusCode = 503;
{inner}  {res}.setHeader("Content-Type", "application/json; charset=utf-8");
{inner}  {res}.setHeader("Cache-Control", "no-store");
{inner}  {res}.end(JSON.stringify({{ error: "runtime_trace_manifest_unavailable" }}));
{inner}  return true;
{inner}}}
{inner}{res}.statusCode = 200;
{inner}{res}.setHeader("Content-Type", "application/json; charset=utf-8");
{inner}{res}.setHeader("Cache-Control", "no-store");
{inner}{res}.end(JSON.stringify(manifest));
{inner}return true;
{indent}}}

{indent}if ({diagnosis_condition}) {{
{inner}{security_line.strip()}
{inner}const traceId = {url_var}.searchParams.get("traceId") ?? "";
{inner}const diagnosis = diagnoseRuntimeTrace(traceId);
{inner}if (!diagnosis) {{
{inner}  {res}.statusCode = 404;
{inner}  {res}.setHeader("Content-Type", "application/json; charset=utf-8");
{inner}  {res}.setHeader("Cache-Control", "no-store");
{inner}  {res}.end(JSON.stringify({{ error: "runtime_trace_diagnosis_unavailable" }}));
{inner}  return true;
{inner}}}
{inner}{res}.statusCode = 200;
{inner}{res}.setHeader("Content-Type", "application/json; charset=utf-8");
{inner}{res}.setHeader("Cache-Control", "no-store");
{inner}{res}.end(JSON.stringify(diagnosis));
{inner}return true;
{indent}}}

'''
    source = source[:if_start] + branches + source[if_start:]

path.write_text(source, encoding='utf-8')
print('Protected runtime diagnosis routes added.')
