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
    .scan-history-disclosure{margin-top:10px;border:1px solid #2a2f3a;border-radius:7px;background:rgba(255,255,255,.01)}
    .scan-history-disclosure>summary{cursor:pointer;padding:10px 12px;color:var(--text-muted);font-size:11px;user-select:none}
    .scan-history-list{display:flex;flex-direction:column;gap:8px;padding:0 10px 10px}
    .scan-history-row{display:grid;grid-template-columns:minmax(110px,.7fr) minmax(130px,1fr) minmax(220px,1.8fr);gap:12px;align-items:center;padding:10px 12px;border:1px solid #2a2f3a;border-radius:7px;background:#222732;font-size:11px}
    .scan-history-type{font-weight:600;text-transform:uppercase;letter-spacing:.05em}
    .scan-history-status{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;color:var(--text-muted)}
    .scan-history-status.completed{color:#3fb88a}.scan-history-status.failed{color:#e23d4f}.scan-history-status.interrupted,.scan-history-status.stopped{color:#e8b23d}.scan-history-status.running{color:#6fb7ff}
    .scan-history-counts{color:var(--text-muted);line-height:1.5}
    .scan-history-empty{padding:14px;color:var(--text-faint);border:1px dashed #2a2f3a;border-radius:7px;font-size:11px}
    @media(max-width:760px){.scan-history-row{grid-template-columns:1fr}}
  `;
  document.head.appendChild(style);

  const panel = document.createElement('section');
  panel.className = 'panel scan-history-panel';
  panel.id = 'scanHistoryPanel';
  panel.setAttribute('aria-labelledby', 'scanHistoryHeading');
  panel.innerHTML = `
    <div class="scan-history-head">
      <h2 id="scanHistoryHeading">Scan history</h2>
      <div class="row">
        <span id="scanHistoryPersistence" class="scan-history-state"></span>
        <button id="scanHistoryRefreshBtn" type="button">Refresh</button>
      </div>
    </div>
    <div class="hint">Resume and Stop are controlled only from the Scan controls above. History is read-only and contains privacy-reduced scan status/counters; provider cursors and resume hashes remain encrypted server-side.</div>
    <details id="scanHistoryDisclosure" class="scan-history-disclosure">
      <summary>Previous scans (0)</summary>
      <div id="scanHistoryList" class="scan-history-list" role="status" aria-live="polite" aria-atomic="false"></div>
    </details>`;
  scanPanel.after(panel);

  const list = panel.querySelector('#scanHistoryList');
  const disclosure = panel.querySelector('#scanHistoryDisclosure');
  const disclosureSummary = disclosure.querySelector('summary');
  const persistence = panel.querySelector('#scanHistoryPersistence');
  const refreshButton = panel.querySelector('#scanHistoryRefreshBtn');
  const stopScanButton = document.getElementById('stopScanBtn');
  const resumeScanButton = document.createElement('button');
  resumeScanButton.id = 'resumeScanBtn';
  resumeScanButton.className = 'primary';
  resumeScanButton.type = 'button';
  resumeScanButton.textContent = 'Resume Scan';
  resumeScanButton.disabled = true;
  stopScanButton?.insertAdjacentElement('afterend', resumeScanButton);
  let refreshTimer = null;
  let refreshSequence = 0;

  function selectionSnapshot() {
    const owner = window.emailShieldAccountSelection;
    if (owner?.capture) return owner.capture();
    return Object.freeze({ id: document.querySelector('.account-chip.active')?.dataset.id || null, generation: null });
  }

  function selectionMatches(snapshot) {
    const owner = window.emailShieldAccountSelection;
    if (owner?.matches && snapshot?.generation !== null) return owner.matches(snapshot);
    return snapshot?.id === (document.querySelector('.account-chip.active')?.dataset.id || null);
  }

  function formatTime(value) {
    const time = Number(value);
    if (!Number.isFinite(time) || time <= 0) return '—';
    return window.emailShieldI18n?.formatDate(time) ?? new Intl.DateTimeFormat('en', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(time));
  }

  function resetResume() {
    resumeScanButton.disabled = true;
    resumeScanButton.dataset.scanHistoryResume = '';
    resumeScanButton.dataset.scanType = '';
    resumeScanButton.dataset.accountId = '';
    resumeScanButton.dataset.selectionGeneration = '';
  }

  function render(history, persistent, ownerSnapshot) {
    persistence.textContent = persistent ? 'Encrypted history: persistent' : 'History: this process only';
    resetResume();
    const records = Array.isArray(history) ? history : [];
    disclosureSummary.textContent = `Previous scans (${records.length})`;

    if (!records.length) {
      list.innerHTML = '<div class="scan-history-empty">No scan history for this connected account yet.</div>';
      return;
    }

    list.innerHTML = '';
    const newestResumable = records.find((record) => record?.resumable === true);
    if (newestResumable) {
      resumeScanButton.disabled = false;
      resumeScanButton.dataset.scanHistoryResume = String(newestResumable.scanId || '');
      resumeScanButton.dataset.scanType = String(newestResumable.type || 'full');
      resumeScanButton.dataset.accountId = ownerSnapshot.id || '';
      resumeScanButton.dataset.selectionGeneration = String(ownerSnapshot.generation ?? '');
    }

    for (const record of records) {
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

      row.append(identity, time, counts);
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
    const ownerSnapshot = selectionSnapshot();
    const id = ownerSnapshot.id;
    const request = ++refreshSequence;
    resetResume();
    if (!id) {
      panel.style.display = 'none';
      if (refreshTimer) clearTimeout(refreshTimer);
      refreshTimer = null;
      refreshButton.disabled = false;
      return;
    }
    panel.style.display = 'block';
    refreshButton.disabled = true;
    persistence.textContent = 'Loading history for the selected account…';
    try {
      const response = await fetch(`/api/accounts/${encodeURIComponent(id)}/scan-history`, {
        headers: { Accept: 'application/json' },
        cache: 'no-store',
      });
      const body = await response.json().catch(() => ({}));
      if (request !== refreshSequence || !selectionMatches(ownerSnapshot)) return;
      if (!response.ok) throw new Error(body.error || `Server returned HTTP ${response.status}`);
      render(body.history, body.persistent === true, ownerSnapshot);
      scheduleRunningRefresh(body.history);
    } catch (error) {
      if (request !== refreshSequence || !selectionMatches(ownerSnapshot)) return;
      resetResume();
      list.innerHTML = '';
      const message = document.createElement('div');
      message.className = 'scan-history-empty';
      message.textContent = `Scan history unavailable: ${error instanceof Error ? error.message : String(error)}`;
      list.append(message);
    } finally {
      if (request === refreshSequence && selectionMatches(ownerSnapshot)) refreshButton.disabled = false;
    }
  }

  refreshButton.addEventListener('click', () => { void refresh(); });

  async function resumeProtectedScan(button, scanId, scanType) {
    if (!scanId) return;
    const current = selectionSnapshot();
    const ownerId = button.dataset.accountId || '';
    const ownerGeneration = button.dataset.selectionGeneration || '';
    if (!ownerId || current.id !== ownerId || String(current.generation ?? '') !== ownerGeneration) {
      resetResume();
      window.alert('The selected account changed. Refresh Scan history before resuming.');
      void refresh();
      return;
    }
    const starter = window.emailShieldStartScan;
    if (typeof starter !== 'function') {
      window.alert('The scan monitor is not ready. Reload Email Shield and try again.');
      return;
    }
    button.disabled = true;
    try {
      await starter(scanType || 'full', { resumeScanId: scanId });
    } finally {
      setTimeout(() => { void refresh(); }, 250);
    }
  }

  resumeScanButton.addEventListener('click', () => {
    void resumeProtectedScan(
      resumeScanButton,
      resumeScanButton.dataset.scanHistoryResume || '',
      resumeScanButton.dataset.scanType || 'full',
    );
  });

  const observer = new MutationObserver(() => { void refresh(); });
  observer.observe(accountsList, { childList: true, subtree: true, attributes: true, attributeFilter: ['class'] });

  window.addEventListener('email-shield-scan-history-changed', () => { void refresh(); });
  void refresh();
})();