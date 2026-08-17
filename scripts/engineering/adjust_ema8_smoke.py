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
    let releasedReportState = null;
    while (Date.now() < reportDeadline) {
      releasedReportState = await evaluate(client, `(() => {
        const report = document.querySelector('[data-action="report-scam"][data-review-token="${positiveDecisionToken}"]');
        const card = report?.closest('.card');
        const status = card?.querySelector('.review-action-status');
        return {
          reportDisabled: report?.disabled === true,
          reportText: report?.textContent || '',
          statusText: status?.textContent || '',
        };
      })()`);
      const reported = releasedReportState?.reportDisabled && /Reported|Campaign protected/.test(releasedReportState.reportText);
      const failedForAnotherReason = !releasedReportState?.reportDisabled && /^Message action failed:/.test(releasedReportState?.statusText || '');
      if (reported || failedForAnotherReason) break;
      await sleep(100);
    }
    assert(releasedReportState,
      'Released Report Scam capability did not produce an observable browser state.');
    const replayConflict = /message_action_conflict|already been used|rescan before performing another action/i.test(releasedReportState.statusText || '');
    assert(replayConflict === false,
      `Released campaign-decision capability still hit the stale replay conflict. State: ${JSON.stringify(releasedReportState)}`);
    assert(
      (releasedReportState.reportDisabled && /Reported|Campaign protected/.test(releasedReportState.reportText)) ||
      (!releasedReportState.reportDisabled && /^Message action failed:/.test(releasedReportState.statusText)),
      `Released Report Scam capability never settled to success or an unrelated explicit failure. State: ${JSON.stringify(releasedReportState)}`,
    );
  }

  const blockTarget = await evaluate(client, `(() => {
'''
if source.count(before) != 1:
    raise RuntimeError(f"expected generated smoke block exactly once, found {source.count(before)}")
path.write_text(source.replace(before, after, 1), encoding="utf-8")
print("EMA-8 browser acceptance now verifies retained-vs-released campaign capability truthfully")
