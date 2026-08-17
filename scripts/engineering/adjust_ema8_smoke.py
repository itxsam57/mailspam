from pathlib import Path

path = Path("scripts/engineering/smoke-browser-scan-results.mjs")
source = path.read_text(encoding="utf-8")
before = '''  assert(positiveDecisionState?.safeDisabled === true && positiveDecisionState?.safeText.includes('marked Safe'),
    `Browser Mark Safe did not persist its visible local decision. State: ${JSON.stringify(positiveDecisionState)}`);
  assert(positiveDecisionState?.reportDisabled === true && positiveDecisionState?.reportText.includes('Campaign decision already saved'),
    `Positive campaign learning did not reconcile the mutually-exclusive Report Scam control. State: ${JSON.stringify(positiveDecisionState)}`);

  const blockTarget = await evaluate(client, `(() => {
'''
after = '''  assert(positiveDecisionState?.safeDisabled === true && positiveDecisionState?.safeText.includes('marked Safe'),
    `Browser Mark Safe did not persist its visible local decision. State: ${JSON.stringify(positiveDecisionState)}`);
  if (positiveDecisionState?.reportDisabled) {
    assert(positiveDecisionState.reportText.includes('Campaign decision already saved'),
      `Retained campaign-decision capability was disabled with the wrong consumer state. State: ${JSON.stringify(positiveDecisionState)}`);
  } else {
    assert(positiveDecisionState?.reportText === 'Report Scam to Email Shield',
      `Released campaign-decision capability was not restored truthfully. State: ${JSON.stringify(positiveDecisionState)}`);
    await evaluate(client, `(() => {
      window.confirm = () => true;
      document.querySelector('[data-action="report-scam"][data-review-token="${positiveDecisionToken}"]')?.click();
      return true;
    })()`);
    const reportDeadline = Date.now() + 10_000;
    while (Date.now() < reportDeadline) {
      positiveDecisionState = await evaluate(client, `(() => {
        const report = document.querySelector('[data-action="report-scam"][data-review-token="${positiveDecisionToken}"]');
        return { reportDisabled: report?.disabled === true, reportText: report?.textContent || '' };
      })()`);
      if (positiveDecisionState?.reportDisabled && /Reported to Email Shield|Campaign protected locally/.test(positiveDecisionState.reportText)) break;
      await sleep(100);
    }
    assert(positiveDecisionState?.reportDisabled === true && /Reported to Email Shield|Campaign protected locally/.test(positiveDecisionState?.reportText || ''),
      `Released campaign-decision capability was visibly offered but still failed when used. State: ${JSON.stringify(positiveDecisionState)}`);
  }

  const blockTarget = await evaluate(client, `(() => {
'''
if source.count(before) != 1:
    raise RuntimeError(f"expected generated smoke block exactly once, found {source.count(before)}")
path.write_text(source.replace(before, after, 1), encoding="utf-8")
print("EMA-8 browser acceptance adjusted to the actual server capability outcome")
