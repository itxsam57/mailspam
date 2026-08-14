(() => {
  const panel = document.getElementById('backgroundProtection');
  const interval = document.getElementById('backgroundInterval');
  const toggle = document.getElementById('backgroundToggle');
  const status = document.getElementById('backgroundStatus');
  const accounts = document.getElementById('accountsList');
  if (!(panel instanceof HTMLElement) || !(interval instanceof HTMLSelectElement) || !(toggle instanceof HTMLButtonElement) || !(status instanceof HTMLElement) || !(accounts instanceof HTMLElement)) return;

  let enabled = false;
  let loadedAccountId = null;
  let requestGeneration = 0;

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
    if (!Number.isFinite(value)) return 'not scheduled';
    return window.emailShieldI18n?.formatDate(value) ?? new Intl.DateTimeFormat('en', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value));
  }

  function render(body, accountId) {
    loadedAccountId = accountId;
    enabled = body.enabled === true;
    interval.value = String(body.intervalMinutes || 60);
    toggle.textContent = enabled ? 'Pause' : 'Enable';
    toggle.setAttribute('aria-pressed', String(enabled));
    const persistence = body.persistent ? 'protected on this device' : 'available for this session only';
    if (!enabled) status.textContent = `Background protection is paused (${persistence}).`;
    else if (body.active) status.textContent = 'A bounded background scan is running now.';
    else if (body.status === 'failed') status.textContent = `The last background check failed (${body.lastErrorCode || 'provider unavailable'}). Next retry: ${formatTime(body.nextRunAt)}.`;
    else if (body.status === 'deferred') status.textContent = `The check was deferred (${body.lastErrorCode || 'manual scan priority'}). Next attempt: ${formatTime(body.nextRunAt)}.`;
    else status.textContent = `Background protection is scheduled for ${formatTime(body.nextRunAt)} (${persistence}).`;
  }

  function clearForSelectionChange() {
    loadedAccountId = null;
    enabled = false;
    toggle.textContent = 'Enable';
    toggle.setAttribute('aria-pressed', 'false');
    toggle.disabled = true;
    status.textContent = 'Loading background protection for the selected account…';
  }

  async function refresh() {
    const snapshot = selectionSnapshot();
    const id = snapshot.id;
    const request = ++requestGeneration;
    if (!id) {
      loadedAccountId = null;
      enabled = false;
      panel.hidden = true;
      toggle.disabled = true;
      return;
    }
    panel.hidden = false;
    if (loadedAccountId !== id) clearForSelectionChange();
    try {
      const response = await fetch(`/api/accounts/${encodeURIComponent(id)}/background-protection`);
      const body = await response.json();
      if (request !== requestGeneration || !selectionMatches(snapshot)) return;
      if (!response.ok) throw new Error(body.error || 'Background protection status failed.');
      render(body, id);
      toggle.disabled = false;
    } catch (error) {
      if (request === requestGeneration && selectionMatches(snapshot)) {
        loadedAccountId = null;
        toggle.disabled = true;
        status.textContent = error instanceof Error ? error.message : String(error);
      }
    }
  }

  toggle.addEventListener('click', async () => {
    const snapshot = selectionSnapshot();
    const id = snapshot.id;
    if (!id) return;
    if (loadedAccountId !== id) {
      status.textContent = 'Mailbox selection changed. Background protection was not modified; reload its current state first.';
      await refresh();
      return;
    }
    const nextEnabled = !enabled;
    const intervalMinutes = Number(interval.value);
    toggle.disabled = true;
    try {
      const response = await fetch(`/api/accounts/${encodeURIComponent(id)}/background-protection`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: nextEnabled, intervalMinutes }),
      });
      const body = await response.json();
      if (!selectionMatches(snapshot)) return;
      if (!response.ok) throw new Error(body.error || 'Background protection update failed.');
      render(body, id);
    } catch (error) {
      if (selectionMatches(snapshot)) status.textContent = error instanceof Error ? error.message : String(error);
    } finally {
      if (selectionMatches(snapshot) && loadedAccountId === id) toggle.disabled = false;
    }
  });

  interval.addEventListener('change', () => {
    const id = selectionSnapshot().id;
    if (id && loadedAccountId === id && enabled) status.textContent = 'Pause and enable again to apply the new interval.';
  });

  new MutationObserver(() => { void refresh(); }).observe(accounts, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ['class'],
  });
  window.setInterval(() => { if (selectionSnapshot().id) void refresh(); }, 30_000);
  void refresh();
})();