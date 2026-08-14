(() => {
  const CATEGORY_LABELS = {
    blockedSenders: 'Blocked senders',
    blockedDomains: 'Blocked domains',
    trustedSenders: 'Trusted senders',
    approvedExceptions: 'Safe exceptions',
    unsubscribedActions: 'Confirmed unsubscribes',
    reportedCampaigns: 'Reported scam campaigns',
  };
  const CATEGORIES = Object.keys(CATEGORY_LABELS);
  const MAX_IMPORT_BYTES = 60 * 1024;
  const selection = new Map();
  let loadedAccountId = null;
  let snapshot = null;

  const panel = document.createElement('section');
  panel.className = 'panel policy-management-panel';
  panel.id = 'policyManagementPanel';
  panel.setAttribute('aria-labelledby', 'policyManagementHeading');
  panel.innerHTML = `
    <h2 id="policyManagementHeading">Personal Policy Management</h2>
    <div class="policy-toolbar">
      <label class="field" for="policySearch"><span>Search personal rules</span><input id="policySearch" type="search" autocomplete="off" /></label>
      <label class="field" for="policyCategory"><span>Policy type</span><select id="policyCategory">
        <option value="all">All policy types</option>
        <option value="blockedSenders">Blocked senders</option>
        <option value="blockedDomains">Blocked domains</option>
        <option value="trustedSenders">Trusted senders</option>
        <option value="approvedExceptions">Safe exceptions</option>
        <option value="unsubscribedActions">Confirmed unsubscribes</option>
        <option value="reportedCampaigns">Reported scam campaigns</option>
      </select></label>
      <button id="policyRefresh" type="button">Refresh</button>
      <button id="policySelectVisible" type="button">Select visible</button>
      <button id="policyRevokeSelected" type="button" disabled>Revoke selected</button>
      <button id="policyClearCategory" type="button" disabled>Clear category</button>
    </div>
    <div class="policy-toolbar policy-backup-toolbar">
      <button id="policyExport" type="button">Export policy backup</button>
      <label class="field" for="policyImportMode"><span>Import mode</span><select id="policyImportMode">
        <option value="merge">Import: merge</option>
        <option value="replace">Import: replace</option>
      </select></label>
      <button id="policyImport" type="button">Choose backup to import</button>
      <input id="policyImportFile" type="file" accept="application/json,.json" hidden />
      <button id="policyReset" class="danger" type="button">Reset all personal policy</button>
    </div>
    <div id="policyStatus" class="policy-status" role="status" aria-live="polite" aria-atomic="true">Select a connected account to manage its personal policy.</div>
    <div id="policyCounts" class="policy-counts" role="status" aria-label="Personal policy counts"></div>
    <div class="hint" style="margin-bottom:12px;">Confirmed unsubscribes include only endpoints Email Shield can verify as completed. Opening an external unsubscribe page or email request is recorded in Activity instead and does not falsely claim completion.</div>
    <div id="policyList" class="policy-list" aria-label="Personal policy entries"></div>
  `;

  const style = document.createElement('style');
  style.textContent = `
    .policy-management-panel { display: block; }
    .policy-toolbar { display:flex; gap:8px; flex-wrap:wrap; align-items:center; margin-bottom:10px; }
    .policy-toolbar input[type="search"] { min-width:220px; flex:1 1 240px; cursor:text; }
    .policy-backup-toolbar { padding-top:10px; border-top:1px solid var(--border); }
    .policy-status { font-size:12px; color:var(--text-muted); margin:8px 0 12px; }
    .policy-status.error { color:var(--confirmed); }
    .policy-status.ok { color:var(--safe); }
    .policy-counts { display:flex; gap:6px; flex-wrap:wrap; margin-bottom:12px; }
    .policy-count { font-size:10px; color:var(--text-muted); background:var(--panel-raised); border:1px solid var(--border); border-radius:999px; padding:4px 8px; }
    .policy-list { display:flex; flex-direction:column; gap:7px; }
    .policy-row { display:grid; grid-template-columns:auto minmax(120px, 170px) 1fr auto; gap:10px; align-items:center; padding:9px 10px; background:var(--panel-raised); border:1px solid var(--border); border-radius:7px; }
    .policy-row-label { font-size:11px; color:var(--text-faint); }
    .policy-row-value { font-family:ui-monospace,SFMono-Regular,Consolas,monospace; font-size:11px; overflow-wrap:anywhere; }
    .policy-row button { font-size:11px; padding:5px 9px; }
    .policy-empty { color:var(--text-faint); text-align:center; padding:24px 8px; font-size:12px; }
    @media (max-width:720px) { .policy-row { grid-template-columns:auto 1fr auto; } .policy-row-label { grid-column:2; } .policy-row-value { grid-column:2; } .policy-row button { grid-column:3; grid-row:1 / span 2; } }
  `;
  document.head.appendChild(style);

  const scanPanel = document.getElementById('scanPanel');
  if (scanPanel) scanPanel.insertAdjacentElement('afterend', panel);
  else document.querySelector('main')?.appendChild(panel);

  const searchInput = document.getElementById('policySearch');
  const categorySelect = document.getElementById('policyCategory');
  const refreshButton = document.getElementById('policyRefresh');
  const selectVisibleButton = document.getElementById('policySelectVisible');
  const revokeSelectedButton = document.getElementById('policyRevokeSelected');
  const clearCategoryButton = document.getElementById('policyClearCategory');
  const exportButton = document.getElementById('policyExport');
  const importModeSelect = document.getElementById('policyImportMode');
  const importButton = document.getElementById('policyImport');
  const importFile = document.getElementById('policyImportFile');
  const resetButton = document.getElementById('policyReset');
  const statusElement = document.getElementById('policyStatus');
  const countsElement = document.getElementById('policyCounts');
  const listElement = document.getElementById('policyList');

  function selectedAccountId() {
    return document.querySelector('#accountsList .account-chip.active')?.getAttribute('data-id') || null;
  }

  function setStatus(message, kind = '') {
    statusElement.textContent = message;
    statusElement.className = `policy-status${kind ? ` ${kind}` : ''}`;
  }

  function controlsEnabled(enabled) {
    [searchInput, categorySelect, refreshButton, selectVisibleButton, exportButton, importModeSelect, importButton, resetButton]
      .forEach((element) => { element.disabled = !enabled; });
    revokeSelectedButton.disabled = !enabled || selection.size === 0;
    clearCategoryButton.disabled = !enabled || categorySelect.value === 'all';
  }

  function displayValue(category, value) {
    if (category === 'approvedExceptions' && value.startsWith('message:')) {
      return `Exact message · ${value.slice(8, 20)}…`;
    }
    if (category === 'unsubscribedActions') return `Confirmed unsubscribe · ${value.slice(0, 12)}…`;
    if (category === 'reportedCampaigns') return `Campaign fingerprint · ${value.slice(0, 12)}…`;
    return value;
  }

  function selectionKey(category, value) {
    return `${category}\u0000${value}`;
  }

  function allItems() {
    if (!snapshot) return [];
    const items = [];
    for (const category of CATEGORIES) {
      for (const value of snapshot[category] || []) items.push({ category, value });
    }
    return items;
  }

  function visibleItems() {
    const query = searchInput.value.trim().toLowerCase();
    const category = categorySelect.value;
    return allItems().filter((item) => {
      if (category !== 'all' && item.category !== category) return false;
      if (!query) return true;
      return item.value.toLowerCase().includes(query) || CATEGORY_LABELS[item.category].toLowerCase().includes(query);
    });
  }

  function renderCounts() {
    countsElement.replaceChildren();
    if (!snapshot) return;
    for (const category of CATEGORIES) {
      const badge = document.createElement('span');
      badge.className = 'policy-count';
      badge.textContent = `${CATEGORY_LABELS[category]}: ${(snapshot[category] || []).length}`;
      countsElement.appendChild(badge);
    }
  }

  function renderList() {
    listElement.replaceChildren();
    const items = visibleItems();
    clearCategoryButton.disabled = !loadedAccountId || categorySelect.value === 'all';
    revokeSelectedButton.disabled = !loadedAccountId || selection.size === 0;

    if (!loadedAccountId) {
      const empty = document.createElement('div');
      empty.className = 'policy-empty';
      empty.textContent = 'Select a connected account to view its personal rules.';
      listElement.appendChild(empty);
      return;
    }
    if (!items.length) {
      const empty = document.createElement('div');
      empty.className = 'policy-empty';
      empty.textContent = 'No personal policy entries match this view.';
      listElement.appendChild(empty);
      return;
    }

    for (const item of items) {
      const row = document.createElement('div');
      row.className = 'policy-row';

      const checkbox = document.createElement('input');
      checkbox.type = 'checkbox';
      const key = selectionKey(item.category, item.value);
      checkbox.checked = selection.has(key);
      checkbox.setAttribute('aria-label', `Select ${CATEGORY_LABELS[item.category]} entry`);
      checkbox.addEventListener('change', () => {
        if (checkbox.checked) selection.set(key, { category: item.category, value: item.value });
        else selection.delete(key);
        revokeSelectedButton.disabled = selection.size === 0;
      });

      const label = document.createElement('div');
      label.className = 'policy-row-label';
      label.textContent = CATEGORY_LABELS[item.category];

      const value = document.createElement('div');
      value.className = 'policy-row-value';
      value.textContent = displayValue(item.category, item.value);
      value.title = item.category === 'blockedSenders' || item.category === 'blockedDomains' || item.category === 'trustedSenders'
        ? item.value
        : 'Privacy-reduced local policy identifier';

      const revoke = document.createElement('button');
      revoke.textContent = 'Revoke';
      revoke.addEventListener('click', async () => {
        if (!window.confirm(`Revoke this ${CATEGORY_LABELS[item.category].toLowerCase()} entry?`)) return;
        await mutate('/revoke', { category: item.category, value: item.value }, 'Policy entry revoked.');
      });

      row.append(checkbox, label, value, revoke);
      listElement.appendChild(row);
    }
  }

  function render() {
    renderCounts();
    renderList();
  }

  async function responseJson(response) {
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || `Policy request failed (${response.status}).`);
    return body;
  }

  async function loadPolicy(force = false) {
    const accountId = selectedAccountId();
    if (!accountId) {
      loadedAccountId = null;
      snapshot = null;
      selection.clear();
      controlsEnabled(false);
      setStatus('Select a connected account to manage its personal policy.');
      render();
      return;
    }
    if (!force && accountId === loadedAccountId && snapshot) return;

    controlsEnabled(false);
    setStatus('Loading personal policy…');
    try {
      const response = await fetch(`/api/accounts/${encodeURIComponent(accountId)}/personal-policy`);
      const body = await responseJson(response);
      loadedAccountId = accountId;
      snapshot = {};
      for (const category of CATEGORIES) snapshot[category] = Array.isArray(body[category]) ? body[category].slice() : [];
      selection.clear();
      controlsEnabled(true);
      setStatus(body.persistent ? 'Personal policy is encrypted and persistent for this account.' : 'Personal policy is memory-only on this platform/session.', body.persistent ? 'ok' : '');
      render();
    } catch (error) {
      loadedAccountId = accountId;
      snapshot = null;
      selection.clear();
      controlsEnabled(true);
      setStatus(error.message || String(error), 'error');
      render();
    }
  }

  async function mutate(suffix, body, successMessage) {
    if (!loadedAccountId) return;
    controlsEnabled(false);
    setStatus('Saving personal policy…');
    try {
      const response = await fetch(`/api/accounts/${encodeURIComponent(loadedAccountId)}/personal-policy${suffix}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      await responseJson(response);
      selection.clear();
      setStatus(successMessage, 'ok');
      await loadPolicy(true);
    } catch (error) {
      controlsEnabled(true);
      setStatus(error.message || String(error), 'error');
    }
  }

  searchInput.addEventListener('input', renderList);
  categorySelect.addEventListener('change', () => {
    selection.clear();
    renderList();
  });
  refreshButton.addEventListener('click', () => loadPolicy(true));

  selectVisibleButton.addEventListener('click', () => {
    for (const item of visibleItems()) selection.set(selectionKey(item.category, item.value), item);
    renderList();
  });

  revokeSelectedButton.addEventListener('click', async () => {
    if (!selection.size) return;
    if (!window.confirm(`Revoke ${selection.size} selected personal policy entries?`)) return;
    await mutate('/bulk-revoke', { items: [...selection.values()] }, `${selection.size} policy entries revoked.`);
  });

  clearCategoryButton.addEventListener('click', async () => {
    const category = categorySelect.value;
    if (!CATEGORIES.includes(category)) return;
    if (!window.confirm(`Clear every entry in ${CATEGORY_LABELS[category]} for the selected account?`)) return;
    await mutate('/clear-category', { category, confirmation: category }, `${CATEGORY_LABELS[category]} cleared.`);
  });

  resetButton.addEventListener('click', async () => {
    const phrase = window.prompt('Type RESET PERSONAL POLICY to remove every personal rule for the selected account.');
    if (phrase !== 'RESET PERSONAL POLICY') {
      if (phrase !== null) setStatus('Reset cancelled because the confirmation phrase did not match.', 'error');
      return;
    }
    await mutate('/reset', { confirmation: phrase }, 'All personal policy entries were reset.');
  });

  exportButton.addEventListener('click', async () => {
    if (!loadedAccountId) return;
    controlsEnabled(false);
    setStatus('Preparing policy-only backup…');
    try {
      const response = await fetch(`/api/accounts/${encodeURIComponent(loadedAccountId)}/personal-policy/export`);
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(body.error || 'Policy export failed.');
      }
      const blob = await response.blob();
      const href = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = href;
      anchor.download = 'email-shield-personal-policy.json';
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(href);
      controlsEnabled(true);
      setStatus('Policy-only backup exported. It contains no mailbox credentials or OAuth tokens.', 'ok');
    } catch (error) {
      controlsEnabled(true);
      setStatus(error.message || String(error), 'error');
    }
  });

  importButton.addEventListener('click', () => importFile.click());
  importFile.addEventListener('change', async () => {
    const file = importFile.files?.[0];
    importFile.value = '';
    if (!file || !loadedAccountId) return;
    if (file.size > MAX_IMPORT_BYTES) {
      setStatus('Policy backup is too large for the protected local import boundary.', 'error');
      return;
    }
    try {
      const text = await file.text();
      const document = JSON.parse(text);
      const mode = importModeSelect.value;
      const warning = mode === 'replace'
        ? 'Replace every current personal rule for this selected account with the backup?'
        : 'Merge this backup into the selected account personal policy?';
      if (!window.confirm(warning)) return;
      await mutate('/import', { mode, document }, `Policy backup ${mode === 'replace' ? 'replaced' : 'merged into'} the selected account.`);
    } catch (error) {
      setStatus(`Policy import could not be read: ${error.message || String(error)}`, 'error');
    }
  });

  const accountList = document.getElementById('accountsList');
  if (accountList) {
    const observer = new MutationObserver(() => { void loadPolicy(false); });
    observer.observe(accountList, { childList: true, subtree: true, attributes: true, attributeFilter: ['class'] });
    accountList.addEventListener('click', () => setTimeout(() => { void loadPolicy(false); }, 0));
  }

  window.addEventListener('email-shield-policy-changed', () => { void loadPolicy(true); });
  controlsEnabled(false);
  render();
  void loadPolicy(false);
})();
