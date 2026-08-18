(() => {
  const installedModules = window.emailShieldInstalledModules ||= new Set();
  if (installedModules.has('consumer-scan-results')) return;
  installedModules.add('consumer-scan-results');

  const diagnostics = document.getElementById('scanDiagnosticAudit');
  const tableBody = diagnostics?.querySelector('tbody');
  if (!(diagnostics instanceof HTMLElement) || !(tableBody instanceof HTMLTableSectionElement)) return;

  const style = document.createElement('style');
  style.textContent = `
    .consumer-scan-feed{margin:12px 0 14px;border:1px solid var(--border);border-radius:9px;background:var(--panel)}
    .consumer-scan-feed>summary{cursor:pointer;display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px 14px;color:var(--text);font-size:12px;font-weight:600;user-select:none}
    .consumer-scan-feed>summary::marker{color:var(--text-muted)}
    .consumer-scan-feed-copy{padding:0 14px 10px;color:var(--text-faint);font-size:11px;border-bottom:1px solid var(--border)}
    .consumer-scan-count{font-size:11px;color:var(--text-muted);font-weight:400;white-space:nowrap;margin-left:auto}
    .consumer-scan-list{display:flex;flex-direction:column;max-height:420px;overflow:auto}
    .consumer-scan-message{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:10px;padding:11px 14px;border-top:1px solid var(--border)}
    .consumer-scan-message:first-child{border-top:0}.consumer-scan-message-main{min-width:0}
    .consumer-scan-subject{font-size:12px;font-weight:600;overflow-wrap:anywhere}.consumer-scan-sender{margin-top:3px;font-size:11px;color:var(--text-muted);overflow-wrap:anywhere}
    .consumer-scan-meta{display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-top:7px;font-size:10px;color:var(--text-faint)}
    .consumer-scan-verdict{padding:2px 6px;border-radius:999px;background:rgba(108,118,132,.15);text-transform:capitalize}
    .consumer-scan-verdict.safe{color:var(--safe);background:rgba(63,184,138,.12)}
    .consumer-scan-verdict.review{color:var(--review);background:rgba(232,178,61,.12)}
    .consumer-scan-verdict.high_risk{color:var(--high-risk);background:rgba(232,99,46,.12)}
    .consumer-scan-verdict.confirmed_threat{color:var(--confirmed);background:rgba(226,61,79,.12)}
    .consumer-scan-actions{display:flex;align-items:flex-start;gap:6px;flex-wrap:wrap;justify-content:flex-end}
    .consumer-scan-actions button{font-size:10px;padding:5px 8px;min-height:30px}
    .consumer-scan-empty{padding:18px 14px;color:var(--text-faint);font-size:11px}
    #scanDiagnosticAudit>summary{font-size:11px}
    @media(max-width:700px){.consumer-scan-message{grid-template-columns:1fr}.consumer-scan-actions{justify-content:flex-start}}
  `;
  document.head.appendChild(style);

  const feed = document.createElement('details');
  feed.id = 'consumerScanMessageFeed';
  feed.className = 'consumer-scan-feed';
  feed.open = false;

  const summary = document.createElement('summary');
  summary.id = 'consumerScanMessageHeading';
  const summaryTitle = document.createElement('span');
  summaryTitle.textContent = 'Scanned emails';
  const count = document.createElement('span');
  count.className = 'consumer-scan-count';
  count.setAttribute('aria-live', 'polite');
  summary.append(summaryTitle, count);

  const explanation = document.createElement('div');
  explanation.className = 'consumer-scan-feed-copy';
  explanation.textContent = 'Open this list only when you want to inspect individual messages. The newest 500 stay available; the counters track the full scan. Message bodies stay private.';

  const list = document.createElement('div');
  list.className = 'consumer-scan-list';
  list.setAttribute('role', 'list');
  feed.append(summary, explanation, list);
  diagnostics.before(feed);

  diagnostics.open = false;
  diagnostics.querySelector('summary')?.replaceChildren(document.createTextNode('Technical scan details (0)'));

  function value(row, selector, fallback = '') {
    return row.querySelector(selector)?.textContent?.trim() || fallback;
  }

  function unsubscribeLabel(method, done) {
    if (done && method === 'one_click_post') return 'Unsubscribed ✓';
    if (method === 'link_only') return 'Open unsubscribe page (not confirmed)';
    if (method === 'mailto') return 'Open unsubscribe email (not confirmed)';
    return 'Unsubscribe';
  }

  function unsubscribeButton(row) {
    if (row.dataset.unsubscribeAvailable !== 'true') return null;
    const token = row.dataset.unsubscribeToken || '';
    const actionKey = row.dataset.unsubscribeKey || '';
    const method = row.dataset.unsubscribeMethod || 'none';
    if (!token || !actionKey || !['one_click_post', 'link_only', 'mailto'].includes(method)) return null;

    const button = document.createElement('button');
    button.type = 'button';
    button.dataset.action = 'unsubscribe';
    button.dataset.unsubscribeToken = token;
    button.dataset.unsubscribeKey = actionKey;
    button.dataset.unsubscribeMethod = method;
    const done = row.dataset.unsubscribeDone === 'true';
    button.textContent = unsubscribeLabel(method, done);
    button.disabled = done && method === 'one_click_post';
    return button;
  }

  function render() {
    const rows = [...tableBody.querySelectorAll('tr[data-message-row="true"]')];
    count.textContent = `${Math.min(rows.length, 500)} available`;
    diagnostics.querySelector('summary')?.replaceChildren(document.createTextNode(`Technical scan details (${rows.length})`));

    if (!rows.length) {
      const empty = document.createElement('div');
      empty.className = 'consumer-scan-empty';
      empty.textContent = 'Scanned emails will appear here as soon as the first provider batch is examined.';
      list.replaceChildren(empty);
      return;
    }

    const fragment = document.createDocumentFragment();
    for (const row of rows.slice(-500).reverse()) {
      const verdict = value(row, 'td:first-child', 'unknown').toLowerCase().replace(/\s+/g, '_');
      const score = value(row, 'td:nth-child(2)', '0');
      const subject = value(row, '.diag-subject', '(no subject)');
      const sender = value(row, '.diag-sender', 'unknown sender');
      const parse = value(row, 'td:nth-child(5)', 'unknown');

      const item = document.createElement('article');
      item.className = 'consumer-scan-message';
      item.setAttribute('role', 'listitem');
      item.dataset.messageRow = 'true';
      item.dataset.reviewToken = row.dataset.reviewToken || '';
      item.dataset.unsubscribeAvailable = row.dataset.unsubscribeAvailable || 'false';
      item.dataset.unsubscribeToken = row.dataset.unsubscribeToken || '';
      item.dataset.unsubscribeKey = row.dataset.unsubscribeKey || '';
      item.dataset.unsubscribeMethod = row.dataset.unsubscribeMethod || 'none';
      item.dataset.unsubscribeDone = row.dataset.unsubscribeDone || 'false';

      const main = document.createElement('div');
      main.className = 'consumer-scan-message-main';
      const subjectEl = document.createElement('div');
      subjectEl.className = 'consumer-scan-subject safe-subject';
      subjectEl.textContent = subject;
      const senderEl = document.createElement('div');
      senderEl.className = 'consumer-scan-sender safe-sender';
      senderEl.textContent = sender;
      const meta = document.createElement('div');
      meta.className = 'consumer-scan-meta';
      const verdictEl = document.createElement('span');
      verdictEl.className = `consumer-scan-verdict ${verdict}`;
      verdictEl.textContent = verdict.replace(/_/g, ' ');
      const scoreEl = document.createElement('span');
      scoreEl.textContent = `score ${score}`;
      const parseEl = document.createElement('span');
      parseEl.textContent = `inspection ${parse}`;
      meta.append(verdictEl, scoreEl, parseEl);
      main.append(subjectEl, senderEl, meta);

      const actions = document.createElement('div');
      actions.className = 'consumer-scan-actions';
      const unsubscribe = unsubscribeButton(row);
      if (unsubscribe) actions.append(unsubscribe);

      item.append(main, actions);
      fragment.append(item);
    }
    list.replaceChildren(fragment);
  }

  function confirmCompletedProjection(type) {
    if (!['quick', 'full', 'spam'].includes(type)) return;
    render();
    const workflowId = `mailbox.scan.${type}`;
    const itemCount = tableBody.querySelectorAll('tr[data-message-row="true"]').length;
    const trace = window.emailShieldRuntimeTrace;
    trace?.checkpoint(`${workflowId}.projection_rendered`, 'success', {
      scanType: type,
      component: 'consumer_scan_results',
      step: 'projection_rendered',
      itemCount,
    });
    trace?.checkpoint(`${workflowId}.ui_confirmed`, 'success', {
      scanType: type,
      component: 'consumer_scan_results',
      step: 'results_visible',
      itemCount,
    });
  }

  const observer = new MutationObserver(render);
  observer.observe(tableBody, { childList: true });
  window.addEventListener('email-shield-workspace-restored', () => queueMicrotask(render));
  window.addEventListener('email-shield-scan-stream-complete', (event) => {
    const type = event instanceof CustomEvent ? event.detail?.type : null;
    confirmCompletedProjection(type);
  });
  render();
})();
