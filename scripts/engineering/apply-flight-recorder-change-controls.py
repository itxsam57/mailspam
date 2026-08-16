from pathlib import Path

ROOT = Path.cwd()


def replace_once(path: str, label: str, before: str, after: str) -> None:
    target = ROOT / path
    source = target.read_text(encoding="utf-8")
    count = source.count(before)
    if count != 1:
        raise RuntimeError(f"{path}: expected exactly one match for {label}, got {count}")
    target.write_text(source.replace(before, after, 1), encoding="utf-8")


replace_once(
    "web/runtime-workflow-trace.js",
    "register static change controls",
    """  document.addEventListener('click', (event) => {
""",
    """  [
    ['backgroundInterval', 'protection.background.interval', 'protection.background.interval', 'background_protection_interval'],
    ['providerSelect', 'developer.provider.select', 'developer.provider.select', 'developer_provider_select'],
    ['modeSelect', 'developer.mode.select', 'developer.mode.select', 'developer_mode_select'],
    ['consumerRicherNotifications', 'notifications.rich_text.toggle', 'notifications.rich_text.toggle', 'notification_privacy'],
    ['accountTransferTarget', 'family.transfer.selection', 'family.transfer.selection', 'family_transfer_selection'],
    ['policyCategory', 'policy.filter.change', 'policy.filter.change', 'policy_filter'],
    ['policyImportMode', 'policy.import_mode.change', 'policy.import_mode.change', 'policy_import_mode'],
    ['policySearch', 'policy.search.change', 'policy.search.change', 'policy_search'],
  ].forEach(([id, actionId, workflowId, expectedWorkflow]) => registerControl(id, actionId, workflowId, expectedWorkflow));

  const CENTRAL_CHANGE_TERMINALS = new Set([
    'developer.provider.select',
    'developer.mode.select',
    'family.transfer.selection',
    'policy.filter.change',
    'policy.import_mode.change',
    'policy.search.change',
  ]);

  document.addEventListener('click', (event) => {
""",
)

replace_once(
    "web/runtime-workflow-trace.js",
    "central change terminal",
    """    const bound = registeredElements.get(control) || (control.id ? registeredById.get(control.id) : null);
    if (!bound) return;
    begin(bound.actionId, bound.workflowId, bound.expectedWorkflow, bound.provider || providerFor(control));
  }, true);
""",
    """    const bound = registeredElements.get(control) || (control.id ? registeredById.get(control.id) : null);
    if (!bound) return;
    const context = begin(bound.actionId, bound.workflowId, bound.expectedWorkflow, bound.provider || providerFor(control));
    if (context && CENTRAL_CHANGE_TERMINALS.has(bound.workflowId)) {
      queueMicrotask(() => checkpointFor(context, `${bound.workflowId}.ui_confirmed`));
    }
  }, true);
""",
)

print("Change-control trace edits applied.")
