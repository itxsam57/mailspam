(() => {
  const panel = document.getElementById('operationsPanel');
  const refresh = document.getElementById('operationsRefresh');
  const status = document.getElementById('operationsStatus');
  const summary = document.getElementById('operationsSummary');
  const rows = document.getElementById('operationsRows');
  if (!panel || !refresh || !status || !summary || !rows) return;

  const i18n = window.emailShieldI18n;
  const t = (key, values) => i18n?.t(key, values) || key;
  const number = (value) => i18n?.formatNumber(value) || String(Number(value) || 0);

  function cell(value, scope) {
    const element = document.createElement(scope ? 'th' : 'td');
    if (scope) element.scope = scope;
    element.textContent = value;
    return element;
  }

  function render(data) {
    if (!data || data.schemaVersion !== 1 || data.privacy !== 'aggregate_only_no_mailbox_identity_or_content') {
      throw new Error(t('operations.invalid'));
    }
    rows.replaceChildren();
    for (const contract of data.providerContracts || []) {
      const health = data.local?.providers?.[contract.provider];
      if (!health) continue;
      const failures = Object.values(health.operations || {}).reduce((total, operation) => total + Number(operation.failed || 0), 0);
      const active = Object.values(health.operations || {}).reduce((total, operation) => total + Number(operation.active || 0), 0);
      const row = document.createElement('tr');
      row.append(
        cell(String(contract.provider), 'row'),
        cell(String(contract.transport).replaceAll('_', ' ')),
        cell(number(health.scans.started)),
        cell(number(health.scans.completed)),
        cell(number(health.scans.failed + health.scans.stopped)),
        cell(number(health.messages.examined)),
        cell(number(failures)),
        cell(number(active)),
      );
      rows.append(row);
    }
    const review = data.local.review;
    summary.textContent = t('operations.summary', {
      feed: data.feed.verified ? t('operations.feed.verified') : t('operations.feed.unavailable'),
      feedEntries: number(data.feed.entries),
      pending: number(data.feed.pendingReports),
      falsePositive: number(review.falsePositiveApprovals),
      abuseAccepted: number(review.abuseReportsAccepted),
      abuseFailed: number(review.abuseReportsFailed),
      background: number(data.background.enabled),
    });
    status.textContent = t('operations.updated', { date: i18n?.formatDate(data.generatedAt) || data.generatedAt });
  }

  async function load() {
    refresh.disabled = true;
    status.textContent = t('operations.loading');
    try {
      const response = await fetch('/api/operations/v1/snapshot');
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.error || t('operations.failed'));
      render(body);
    } catch (error) {
      status.textContent = error instanceof Error ? error.message : t('operations.failed');
    } finally {
      refresh.disabled = false;
    }
  }

  refresh.addEventListener('click', load);
  void load();
})();
