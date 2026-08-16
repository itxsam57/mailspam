from pathlib import Path
import re

ROOT = Path.cwd()


def replace_once(path: str, label: str, before: str, after: str) -> None:
    target = ROOT / path
    source = target.read_text(encoding="utf-8")
    count = source.count(before)
    if count != 1:
        raise RuntimeError(f"{path}: expected exactly one match for {label}, got {count}")
    target.write_text(source.replace(before, after, 1), encoding="utf-8")


def insert_import(source: str, import_line: str) -> str:
    if import_line in source:
        return source
    matches = list(re.finditer(r'^import .*?;\s*$', source, re.M))
    if not matches:
        return import_line + "\n" + source
    pos = matches[-1].end()
    return source[:pos] + "\n" + import_line + source[pos:]


# Browser trace owner exposes only opaque/safe current context fields.
replace_once(
    "web/runtime-workflow-trace.js",
    "trace public context accessors",
    """      currentTraceId: () => current()?.traceId || null,
      currentWorkflowId: () => current()?.workflowId || null,""",
    """      currentTraceId: () => current()?.traceId || null,
      currentWorkflowId: () => current()?.workflowId || null,
      currentActionId: () => current()?.actionId || null,
      currentProvider: () => current()?.provider || null,
      currentScanType: () => current()?.scanType || null,""",
)

# Browser trace roots emit the registry's required first checkpoint. This is a
# fixed identifier only; no visible/control values enter the trace.
replace_once(
    "web/runtime-workflow-trace.js",
    "root requested/start checkpoint",
    """    transport({
      traceId: context.traceId,
      workflowId: context.workflowId,
      stage: origin === 'automatic' ? 'system' : 'ui_action',
      actionId: context.actionId,
      expectedWorkflow: context.expectedWorkflow,
      ...(context.provider ? { provider: context.provider } : {}),
      ...(context.scanType ? { scanType: context.scanType } : {}),
      component: origin === 'automatic' ? 'browser_automatic' : 'browser',
      step: origin === 'automatic' ? 'automatic_root' : 'button_pressed',
      outcome: 'started',
    });
    return context;""",
    """    transport({
      traceId: context.traceId,
      workflowId: context.workflowId,
      stage: origin === 'automatic' ? 'system' : 'ui_action',
      actionId: context.actionId,
      expectedWorkflow: context.expectedWorkflow,
      ...(context.provider ? { provider: context.provider } : {}),
      ...(context.scanType ? { scanType: context.scanType } : {}),
      component: origin === 'automatic' ? 'browser_automatic' : 'browser',
      step: origin === 'automatic' ? 'automatic_root' : 'button_pressed',
      outcome: 'started',
    });
    checkpointFor(context, origin === 'automatic' ? `${context.workflowId}.started` : `${context.workflowId}.requested`, 'success', {
      component: origin === 'automatic' ? 'browser_automatic' : 'browser',
      step: origin === 'automatic' ? 'automatic_root' : 'user_action',
    });
    return context;""",
)

# Add safe correlation headers beside the already-existing trace ID. Search the
# unique header write so this fails closed if local-security ownership changes.
local_path = ROOT / "web/local-security.js"
local = local_path.read_text(encoding="utf-8")
if "X-Email-Shield-Workflow-Id" not in local:
    pattern = re.compile(r"(?P<indent>\s*)(?P<target>[A-Za-z_$][A-Za-z0-9_$.]*)\.set\((?P<q>['\"])X-Email-Shield-Trace-Id(?P=q),\s*(?P<value>[^;]+)\);")
    match = pattern.search(local)
    if not match:
        raise RuntimeError("web/local-security.js: X-Email-Shield-Trace-Id header write not found")
    indent = match.group("indent")
    target = match.group("target")
    addition = match.group(0) + f"""{indent}const workflowId = window.emailShieldRuntimeTrace?.currentWorkflowId?.();
{indent}const actionId = window.emailShieldRuntimeTrace?.currentActionId?.();
{indent}const traceProvider = window.emailShieldRuntimeTrace?.currentProvider?.();
{indent}const traceScanType = window.emailShieldRuntimeTrace?.currentScanType?.();
{indent}if (workflowId) {target}.set('X-Email-Shield-Workflow-Id', workflowId);
{indent}if (actionId) {target}.set('X-Email-Shield-Action-Id', actionId);
{indent}if (traceProvider) {target}.set('X-Email-Shield-Provider', traceProvider);
{indent}if (traceScanType) {target}.set('X-Email-Shield-Scan-Type', traceScanType);"""
    local = local[:match.start()] + addition + local[match.end():]
    local_path.write_text(local, encoding="utf-8")

# AsyncLocal validation state stays separate so the public context shape remains
# content-free and the existing exact-equality unit contract is unchanged.
context_path = ROOT / "server/src/diagnostics/runtimeTraceRequestContext.ts"
context = context_path.read_text(encoding="utf-8")
if "validationStorage" not in context:
    context = context.replace(
        "const storage = new AsyncLocalStorage<RuntimeTraceRequestContext | null>();",
        "const storage = new AsyncLocalStorage<RuntimeTraceRequestContext | null>();\nconst validationStorage = new AsyncLocalStorage<boolean>();",
        1,
    )
    context = context.replace(
        "function clearContext(): void {\n  storage.enterWith(null);\n}",
        "function clearContext(): void {\n  storage.enterWith(null);\n  validationStorage.enterWith(false);\n}",
        1,
    )
    context = context.replace(
        "  storage.enterWith({\n    traceId,",
        "  validationStorage.enterWith(false);\n  storage.enterWith({\n    traceId,",
        1,
    )
    context = context.replace(
        "  storage.enterWith(context);\n  return context;",
        "  storage.enterWith(context);\n  validationStorage.enterWith(true);\n  return context;",
        1,
    )
    marker = """
export function markRuntimeTraceRequestValidated(): boolean {
  const context = currentRuntimeTraceContext();
  if (!context) return false;
  validationStorage.enterWith(true);
  recordCurrentRuntimeCheckpoint("request_validated", {
    stage: "service",
    outcome: "success",
    component: "local_api_security",
  });
  return true;
}

export function isRuntimeTraceRequestValidated(): boolean {
  return currentRuntimeTraceContext() !== null && validationStorage.getStore() === true;
}

"""
    insert_at = context.index("export function recordCurrentRuntimeCheckpoint(")
    context = context[:insert_at] + marker + context[insert_at:]
    context_path.write_text(context, encoding="utf-8")

# Response boundary does not emit anything unless protected request validation
# marked the AsyncLocal trace context trusted.
response_path = ROOT / "server/src/diagnostics/runtimeTraceResponseBoundary.ts"
response = response_path.read_text(encoding="utf-8")
if "isRuntimeTraceRequestValidated" not in response:
    response = response.replace(
        'import { recordCurrentRuntimeCheckpoint } from "./runtimeTraceRequestContext.js";',
        'import { isRuntimeTraceRequestValidated, recordCurrentRuntimeCheckpoint } from "./runtimeTraceRequestContext.js";',
        1,
    )
    response = response.replace(
        "    const status = Number.isSafeInteger(response.statusCode) ? Number(response.statusCode) : 200;\n    recordCurrentRuntimeCheckpoint",
        "    if (!isRuntimeTraceRequestValidated()) return originalEnd.apply(this, args);\n    const status = Number.isSafeInteger(response.statusCode) ? Number(response.statusCode) : 200;\n    recordCurrentRuntimeCheckpoint",
        1,
    )
    response_path.write_text(response, encoding="utf-8")

# Locate the canonical protected-read/mutation owner. Bind/attach before checks,
# then mark validation on the final success path. Early rejection returns never
# reach the marker, so forged requests cannot produce trusted terminal records.
security_candidates = []
for candidate in (ROOT / "server/src").rglob("*.ts"):
    text = candidate.read_text(encoding="utf-8")
    if "requireProtectedRead" in text and "requireProtectedMutation" in text and "diagnostics/runtimeTrace" not in candidate.as_posix():
        security_candidates.append((candidate, text))
if len(security_candidates) != 1:
    raise RuntimeError(f"expected exactly one canonical protected security owner, found {[p.as_posix() for p,_ in security_candidates]}")
security_path, security = security_candidates[0]
relative_import = "../diagnostics/runtimeTraceRequestContext.js" if security_path.parent.name == "api" else "./diagnostics/runtimeTraceRequestContext.js"
response_import = "../diagnostics/runtimeTraceResponseBoundary.js" if security_path.parent.name == "api" else "./diagnostics/runtimeTraceResponseBoundary.js"
security = insert_import(security, f'import {{ bindRuntimeTraceRequest, markRuntimeTraceRequestValidated }} from "{relative_import}";')
security = insert_import(security, f'import {{ attachRuntimeTraceResponse }} from "{response_import}";')


def wire_guard(source: str, name: str) -> str:
    pattern = re.compile(rf"(?P<prefix>(?:export\s+)?function\s+{name}\s*\((?P<params>[^)]*)\)\s*(?::\s*[^{{]+)?\s*\{{)")
    match = pattern.search(source)
    if not match:
        # Also allow exported const arrow functions.
        raise RuntimeError(f"{security_path.as_posix()}: function {name} signature not found")
    params = match.group("params")
    identifiers = []
    for raw in params.split(","):
        raw = raw.strip()
        ident_match = re.match(r"([A-Za-z_$][A-Za-z0-9_$]*)", raw)
        if ident_match:
            identifiers.append(ident_match.group(1))
    if len(identifiers) < 2:
        raise RuntimeError(f"{security_path.as_posix()}: cannot identify request/response params for {name}")
    req, res = identifiers[0], identifiers[1]
    open_brace = match.end() - 1
    depth = 0
    end = None
    for index in range(open_brace, len(source)):
        char = source[index]
        if char == "{": depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                end = index
                break
    if end is None:
        raise RuntimeError(f"{security_path.as_posix()}: cannot locate end of {name}")
    body = source[open_brace + 1:end]
    if "bindRuntimeTraceRequest(" not in body:
        prologue = f"\n  if (!String({req}.url ?? '').startsWith('/api/security/mutation-token') && !String({req}.url ?? '').startsWith('/api/dev/runtime-trace')) {{\n    bindRuntimeTraceRequest({req}.headers as Record<string, string | string[] | undefined>);\n    attachRuntimeTraceResponse({res}, {req}.url);\n  }}"
        body = prologue + body
    if "markRuntimeTraceRequestValidated()" not in body:
        returns = list(re.finditer(r"\breturn\b", body))
        if returns:
            pos = returns[-1].start()
            body = body[:pos] + "markRuntimeTraceRequestValidated();\n  " + body[pos:]
        else:
            body = body.rstrip() + "\n  markRuntimeTraceRequestValidated();\n"
    return source[:open_brace + 1] + body + source[end:]

for guard in ("requireProtectedRead", "requireProtectedMutation"):
    security = wire_guard(security, guard)
security_path.write_text(security, encoding="utf-8")

print(f"Task 5 trace wiring applied through {security_path.relative_to(ROOT).as_posix()}.")
