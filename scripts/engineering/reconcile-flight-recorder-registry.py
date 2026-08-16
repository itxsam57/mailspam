from pathlib import Path

path = Path('server/src/diagnostics/workflowRegistry.ts')
source = path.read_text(encoding='utf-8')


def ensure_after(anchor: str, addition: str) -> None:
    global source
    if addition.strip() in source:
        return
    if anchor not in source:
        raise RuntimeError(f'missing workflow registry anchor: {anchor!r}')
    source = source.replace(anchor, anchor + addition, 1)

ensure_after(
    '  linearWorkflow("support.bundle.export"),\n',
    '  linearWorkflow("notifications.rich_text.toggle"),\n'
    '  uiWorkflow("policy.filter.change"),\n'
    '  uiWorkflow("policy.import_mode.change"),\n'
    '  uiWorkflow("policy.search.change"),\n',
)
ensure_after(
    '  linearWorkflow("shopping_safety.run"),\n',
    '  uiWorkflow("shopping_safety.clear"),\n',
)
ensure_after(
    '  linearWorkflow("family.invite"),\n',
    '  uiWorkflow("family.invite.copy"),\n',
)
ensure_after(
    '  linearWorkflow("family.guardian_preferences"),\n',
    '  uiWorkflow("family.guardian_preferences.edit"),\n',
)
ensure_after(
    '  linearWorkflow("family.transfer"),\n',
    '  uiWorkflow("family.transfer.selection"),\n',
)

path.write_text(source, encoding='utf-8')
print('Flight recorder workflow registry reconciled.')
