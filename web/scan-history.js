(() => {
  const scanPanel = document.getElementById('scanPanel');
  const accountsList = document.getElementById('accountsList');
  if (!scanPanel || !accountsList) return;

  const style = document.createElement('style');
  style.textContent = `
    .scan-history-panel{display:none}
    .scan-history-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:10px}
    .scan-history-head h2{margin:0}
    .scan-history-state{font-size:11px;color:var(--text-faint)}
    .scan-history-list{display:flex;flex-direction:column;gap:8px}
    .scan-history-row{display:grid;grid-template-columns:minmax(110px,.7fr) minmax(130px,1fr) minmax(220px,1.8fr) auto;gap:12px;align-items:center;padding:10px 12px;border:1px solid #2a2f3a;border-radius:7px;background:#222732;font-size:11px}
    .scan-history-type{font-weight:600;text-transform:uppercase;letter-spacing:.05em}
    .scan-history-status{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;color:var(--text-muted)}
    .scan-history-status.completed{color:#3fb88a}.scan-history-status.failed{color:#e23d4f}.scan-history-status.interrupted,.scan-history-status.stopped{color:#e8b23d}.scan-history-status.running{color:#6fb7ff}
    .scan-history-counts{color:var(--text-muted);line-height:1.5}
    .scan-history-actions{display:flex;gap:6px;justify-content:flex-end}
    .scan-history-actions button{padding:5px 9px;font-size:11px}
    .scan-history-empty{padding:14px;color:var(--text-faint);border:1px dashed #2a2f3a;border-radius:7px;font-size:11px}
    @media(max-width:760px){.scan-history-row{grid-template-columns:1fr}.scan-history-actions{justify-content:flex-start}}
  `;
  document.head.appendChild(style);

  const panel = document.createElement('section');
  panel.className = 'panel scan-history-panel';
  panel.id = 'scanHistoryPanel';
  panel.setAttribute('aria-labelledby', 'scanHistoryHeading');
  panel.innerHTML = `
    <div class="scan-history-head">
      <h2 id="scanHistoryHeading">Scan history & resume</h2>
      <div class="row">
        <span id="scanHistoryPersistence" class="scan-history-state"></span>
        <button id="scanHistoryRefreshBtn" type="button">Refresh</button>
      </div>
    </div>
    <div class="hint">Only privacy-reduced scan status and counters are shown here. Provider cursors and resume hashes remain encrypted server-side.</div>
    <div id="scanHistoryList" class="scan-history-list" style="margin-top:10px;" role="status" aria-live="polite" aria-atomic="false"></div>`;
  scanPanel.after(panel);

  const list = panel.querySelector('#scanHistoryList');
  const persistence = panel.querySelector('#scanHistoryPersistence');
  const refreshButton = panel.querySelector('#scanHistoryRefreshBtn');
  let lastAccountId = null;
  let refreshTimer = null;
  let refreshing = false;

  function selectedAccountId() {
    return document.querySelector('.account-chip.active')?.dataset.id || null;
  }

  function formatTime(value) {
    const time = Number(value);
    if (!Number.isFinite(time) || time <= 0) return '—';
    return window.emailShieldI18n?.formatDate(time) ?? new Intl.DateTimeFormat('en', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(time));
  }

  function render(history, persistent) {
    persistence.textContent = persistent ? 'Encrypted history: persistent' : 'History: this process only';
    if (!Array.isArray(history) || history.length === 0) {
      list.innerHTML = '<div class="scan-history-empty">No scan history for this connected account yet.</div>';
      return;
    }

    list.innerHTML = '';
    for (const record of history) {
      const row = document.createElement('div');
      row.className = 'scan-history-row';

      const identity = document.createElement('div');
      const type = document.createElement('div');
      type.className = 'scan-history-type';
      type.textContent = String(record.type || 'scan');
      const state = document.createElement('div');
      state.className = `scan-history-status ${String(record.status || '')}`;
      state.textContent = String(record.status || 'unknown');
      identity.append(type, state);

      const time = document.createElement('div');
      time.innerHTML = `<div>${formatTime(record.startedAt)}</div><div class="scan-history-state">Updated ${formatTime(record.updatedAt)}</div>`;

      const counters = record.counters || {};
      const counts = document.createElement('div');
      counts.className = 'scan-history-counts';
      counts.textContent = `Examined ${Number(counters.examined || 0)} · Safe ${Number(counters.safe || 0)} · Review ${Number(counters.review || 0)} · High ${Number(counters.highRisk || 0)} · Confirmed ${Number(counters.confirmedThreat || 0)} · Unknown ${Number(counters.unknown || 0)}`;

      const actions = document.createElement('div');
      actions.className = 'scan-history-actions';
      if (record.status === 'running') {
        const stop = document.createElement('button');
        stop.className = 'danger';
        stop.type = 'button';
        stop.textContent = 'Stop';
        stop.dataset.scanHistoryStop = 'true';
        actions.append(stop);
      } else if (record.resumable === true) {
        const resume = document.createElement('button');
        resume.className = 'primary';
        resume.type = 'button';
        resume.textContent = 'Resume';
        resume.dataset.scanHistoryResume = String(record.scanId || '');
        resume.dataset.scanType = String(record.type || 'full');
        actions.append(resume);
      }

      row.append(identity, time, counts, actions);
      list.append(row);
    }
  }

  function scheduleRunningRefresh(history) {
    if (refreshTimer) clearTimeout(refreshTimer);
    refreshTimer = null;
    if (Array.isArray(history) && history.some((record) => record?.status === 'running')) {
      refreshTimer = setTimeout(() => { void refresh(); }, 3000);
    }
  }

  async function refresh() {
    const id = selectedAccountId();
    lastAccountId = id;
    if (!id) {
      panel.style.display = 'none';
      if (refreshTimer) clearTimeout(refreshTimer);
      refreshTimer = null;
      return;
    }
    panel.style.display = 'block';
    if (refreshing) return;
    refreshing = true;
    refreshButton.disabled = true;
    try {
      const response = await fetch(`/api/accounts/${encodeURIComponent(id)}/scan-history`, {
        headers: { Accept: 'application/json' },
        cache: 'no-store',
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.error || `Server returned HTTP ${response.status}`);
      if (selectedAccountId() !== id) return;
      render(body.history, body.persistent === true);
      scheduleRunningRefresh(body.history);
    } catch (error) {
      list.innerHTML = '';
      const message = document.createElement('div');
      message.className = 'scan-history-empty';
      message.textContent = `Scan history unavailable: ${error instanceof Error ? error.message : String(error)}`;
      list.append(message);
    } finally {
      refreshing = false;
      refreshButton.disabled = false;
    }
  }

  refreshButton.addEventListener('click', () => { void refresh(); });

  list.addEventListener('click', async (event) => {
    const target = event.target instanceof Element ? event.target.closest('button') : null;
    if (!(target instanceof HTMLButtonElement) || target.disabled) return;
    const id = selectedAccountId();
    if (!id) return;

    if (target.dataset.scanHistoryResume) {
      const starter = window.emailShieldStartScan;
      if (typeof starter !== 'function') {
        window.alert('The scan monitor is not ready. Reload Email Shield and try again.');
        return;
      }
      target.disabled = true;
      try {
        await starter(target.dataset.scanType || 'full', { resumeScanId: target.dataset.scanHistoryResume });
      } finally {
        setTimeout(() => { void refresh(); }, 250);
      }
      return;
    }

    if (target.dataset.scanHistoryStop === 'true') {
      target.disabled = true;
      try {
        const response = await fetch(`/api/accounts/${encodeURIComponent(id)}/scan/stop`, { method: 'POST' });
        const body = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(body.error || `Server returned HTTP ${response.status}`);
      } catch (error) {
        window.alert(`Stop failed: ${error instanceof Error ? error.message : String(error)}`);
      } finally {
        setTimeout(() => { void refresh(); }, 300);
      }
    }
  });

  const observer = new MutationObserver(() => {
    const id = selectedAccountId();
    if (id !== lastAccountId) void refresh();
  });
  observer.observe(accountsList, { childList: true, subtree: true, attributes: true, attributeFilter: ['class'] });

  window.addEventListener('email-shield-scan-history-changed', () => { void refresh(); });
  void refresh();
})();
