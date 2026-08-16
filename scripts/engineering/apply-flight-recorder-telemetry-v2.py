from pathlib import Path
import re

ROOT = Path.cwd()
path = ROOT / 'server/src/telemetry/technicalTelemetry.ts'
source = path.read_text(encoding='utf-8')

# Extend the exact trace allowlist container(s) that already own traceId,
# actionId and expectedWorkflow. No other telemetry event allowlists are touched.
for match in list(re.finditer(r'(?:new\s+Set(?:<[^>]+>)?\s*\(\s*)?\[(?P<body>[\s\S]{0,6000}?)\](?:\s*\))?', source)):
    body = match.group('body')
    if all(token in body for token in ('"traceId"', '"actionId"', '"expectedWorkflow"')) and '"workflowId"' not in body:
        replacement = body.replace(
            '"traceId",',
            '"traceId",\n  "workflowId",\n  "checkpointId",\n  "buildId",\n  "parentTraceId",\n  "errorLocationId",',
            1,
        )
        source = source[:match.start('body')] + replacement + source[match.end('body'):]
        break

if 'workflow_id' not in source:
    event_pos = source.find('email_shield_workflow_trace')
    if event_pos < 0:
        raise RuntimeError('technicalTelemetry: workflow trace event missing')

    # Find the nearest enclosing function before the event string.
    function_matches = list(re.finditer(r'(?:export\s+)?(?:async\s+)?function\s+[A-Za-z_$][A-Za-z0-9_$]*\s*\((?P<params>[^)]*)\)[^{]*\{', source[:event_pos]))
    if not function_matches:
        raise RuntimeError('technicalTelemetry: workflow trace capture function not found')
    function = function_matches[-1]
    params = function.group('params')
    first_param = re.match(r'\s*([A-Za-z_$][A-Za-z0-9_$]*)', params)
    if not first_param:
        raise RuntimeError('technicalTelemetry: trace event parameter not found')
    event_var = first_param.group(1)
    open_brace = function.end() - 1

    validation = f'''\n  const runtimeTraceV2 = {event_var} as unknown as Record<string, unknown>;
  const v2 = runtimeTraceV2.schemaVersion === 2;
  const safeTraceLabel = (value: unknown): value is string => typeof value === "string" && /^[a-z0-9][a-z0-9_.:/-]{{0,159}}$/i.test(value);
  const safeBuildId = (value: unknown): value is string => typeof value === "string" && /^(?:development|[0-9a-f]{{40}})$/i.test(value);
  if (v2 && (
    !safeTraceLabel(runtimeTraceV2.workflowId)
    || !safeTraceLabel(runtimeTraceV2.checkpointId)
    || !safeBuildId(runtimeTraceV2.buildId)
    || (runtimeTraceV2.parentTraceId !== undefined && (typeof runtimeTraceV2.parentTraceId !== "string" || !/^[0-9a-f-]{{36}}$/i.test(runtimeTraceV2.parentTraceId)))
    || (runtimeTraceV2.errorLocationId !== undefined && !safeTraceLabel(runtimeTraceV2.errorLocationId))
  )) return false;
'''
    source = source[:open_brace + 1] + validation + source[open_brace + 1:]
    event_pos = source.find('email_shield_workflow_trace', event_pos + len(validation))

    # Find the properties object following the event name. Insert safe optional
    # v2 properties at its start using spreads so v1 behavior is unchanged.
    object_start = source.find('{', event_pos)
    if object_start < 0:
        raise RuntimeError('technicalTelemetry: workflow trace properties object missing')
    properties = '''
      ...(v2 ? {
        workflow_id: runtimeTraceV2.workflowId as string,
        checkpoint_id: runtimeTraceV2.checkpointId as string,
        build_id: runtimeTraceV2.buildId as string,
        ...(runtimeTraceV2.parentTraceId ? { parent_trace_id: runtimeTraceV2.parentTraceId as string } : {}),
        ...(runtimeTraceV2.errorLocationId ? { error_location_id: runtimeTraceV2.errorLocationId as string } : {}),
      } : {}),'''
    source = source[:object_start + 1] + properties + source[object_start + 1:]

path.write_text(source, encoding='utf-8')
print('Strict workflow trace telemetry v2 mapping applied.')
