from pathlib import Path

path = Path("scripts/engineering/smoke-browser-scan-results.mjs")
source = path.read_text(encoding="utf-8")
trace_anchor = '''  const positiveDecisionToken = await evaluate(client, `(() => {
'''
trace_replacement = '''  await evaluate(client, `(() => {
    if (window.__ema8FetchTraceInstalled) return true;
    window.__ema8FetchTraceInstalled = true;
    window.__ema8FetchTrace = [];
    const originalFetch = window.fetch.bind(window);
    window.fetch = async (...args) => {
      const url = typeof args[0] === 'string' ? args[0] : args[0]?.url || '';
      const method = String(args[1]?.method || 'GET').toUpperCase();
      const relevant = url.includes('/messages/');
      const entry = relevant ? { url, method, startedAt: Date.now(), status: null, ok: null, error: null } : null;
      if (entry) window.__ema8FetchTrace.push(entry);
      try {
        const response = await originalFetch(...args);
        if (entry) { entry.status = response.status; entry.ok = response.ok; entry.finishedAt = Date.now(); }
        return response;
      } catch (error) {
        if (entry) { entry.error = error instanceof Error ? error.message : String(error); entry.finishedAt = Date.now(); }
        throw error;
      }
    };
    return true;
  })()`);

  const positiveDecisionToken = await evaluate(client, `(() => {
'''
if source.count(trace_anchor) != 1:
    raise RuntimeError(f"expected positive decision trace anchor exactly once, found {source.count(trace_anchor)}")
source = source.replace(trace_anchor, trace_replacement, 1)

before = '''  assert(positiveDecisionState?.safeDisabled === true && positiveDecisionState?.safeText.includes('marked Safe'),
    `Browser Mark Safe did not persist its visible local decision. State: ${JSON.stringify(positiveDecisionState)}`);
  assert(positiveDecisionState?.reportDisabled === true && positiveDecisionState?.reportText.includes('Campaign decision already saved'),
    `Positive campaign learning did not reconcile the mutually-exclusive Report Scam control. State: ${JSON.stringify(positiveDecisionState)}`);

  const blockTarget = await evaluate(client, `(() => {
'''
after = '''  assert(positiveDecisionState?.safeDisabled === true && positiveDecisionState?.safeText.includes('marked Safe'),
    `Browser Mark Safe did not persist its visible local decision. State: ${JSON.stringify(positiveDecisionState)}`);
  const authoritativeWorkspaceState = await evaluate(client, `(async () => {
    const response = await fetch('/api/accounts/workspace', { headers: { Accept: 'application/json' }, cache: 'no-store' });
    const workspace = await response.json().catch(() => ({}));
    const presentation = workspace?.presentation && typeof workspace.presentation === 'object' ? workspace.presentation : {};
    const entries = [
      ...(Array.isArray(presentation.suspiciousCards) ? presentation.suspiciousCards : []),
      ...(Array.isArray(presentation.diagnosticSummaries) ? presentation.diagnosticSummaries : []),
    ];
    const matching = entries.find((candidate) => candidate?.reviewAction?.token === ${JSON.stringify(positiveDecisionToken)}) || null;
    return {
      responseOk: response.ok,
      selectedAccountId: workspace?.selectedAccountId || null,
      expectedAccountId: ${JSON.stringify(accountId)},
      matchingTokenFound: Boolean(matching),
      reportScamAvailable: matching?.reviewAction?.reportScamAvailable ?? null,
      workspaceEntryCount: entries.length,
    };
  })()`);
  if (positiveDecisionState?.reportDisabled) {
    assert(positiveDecisionState.reportText.includes('Campaign decision already saved'),
      `Retained campaign-decision capability was disabled with the wrong consumer state. State: ${JSON.stringify(positiveDecisionState)} Workspace: ${JSON.stringify(authoritativeWorkspaceState)}`);
  } else {
    assert(positiveDecisionState?.reportText === 'Report Scam to Email Shield',
      `Released campaign-decision capability was not restored truthfully. State: ${JSON.stringify(positiveDecisionState)} Workspace: ${JSON.stringify(authoritativeWorkspaceState)}`);
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
    const mutationTrace = await evaluate(client, `window.__ema8FetchTrace || []`);
    assert(releasedReportState,
      'Released Report Scam capability did not produce an observable browser state.');
    const replayConflict = /message_action_conflict|already been used|rescan before performing another action/i.test(releasedReportState.statusText || '');
    assert(replayConflict === false,
      `Released campaign-decision capability still hit the stale replay conflict. State: ${JSON.stringify(releasedReportState)} Workspace: ${JSON.stringify(authoritativeWorkspaceState)} Requests: ${JSON.stringify(mutationTrace)}`);
    assert(
      (releasedReportState.reportDisabled && /Reported|Campaign protected/.test(releasedReportState.reportText)) ||
      (!releasedReportState.reportDisabled && /^Message action failed:/.test(releasedReportState.statusText)),
      `Released Report Scam capability never settled to success or an unrelated explicit failure. State: ${JSON.stringify(releasedReportState)} Workspace: ${JSON.stringify(authoritativeWorkspaceState)} Requests: ${JSON.stringify(mutationTrace)}`,
    );
  }

  const blockTarget = await evaluate(client, `(() => {
'''
if source.count(before) != 1:
    raise RuntimeError(f"expected generated smoke block exactly once, found {source.count(before)}")
path.write_text(source.replace(before, after, 1), encoding="utf-8")
print("EMA-8 browser acceptance now traces message mutation requests around the authoritative capability race")
