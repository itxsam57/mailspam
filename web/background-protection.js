(() => {
  const panel = document.getElementById('backgroundProtection');
  const interval = document.getElementById('backgroundInterval');
  const toggle = document.getElementById('backgroundToggle');
  const status = document.getElementById('backgroundStatus');
  const accounts = document.getElementById('accountsList');
  if (!(panel instanceof HTMLElement) || !(interval instanceof HTMLSelectElement) || !(toggle instanceof HTMLButtonElement) || !(status instanceof HTMLElement) || !(accounts instanceof HTMLElement)) return;

  const heading = panel.querySelector('h3');
  if (heading) heading.textContent = 'Continuous Protection';
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

  function automaticSummary(body) {
    const automatic = body?.automaticProtection;
    if (!automatic || typeof automatic !== 'object') {
      return 'Provider-event protection: runtime status unavailable. The persisted schedule remains authoritative.';
    }
    const providerEvents = automatic.providerEvents === 'not_configured_in_desktop_runtime'
      ? 'Provider-event protection is not configured in this desktop runtime.'
      : 'Provider-event protection state is unavailable.';
    const fallback = automatic.metadataCheckpointFallback === 'available'
      ? `Protected metadata checkpoint fallback is available${Number.isFinite(automatic.pollIntervalMs) ? ` every ${Math.max(1, Math.round(automatic.pollIntervalMs / 60000))} minute(s)` : ''}.`
      : 'Protected metadata checkpoint fallback is unavailable.';
    return `${providerEvents} ${fallback}`;
  }

  function render(body, accountId) {
    loadedAccountId = accountId;
    enabled = body.enabled === true;
    interval.value = String(body.intervalMinutes || 60);
    interval.disabled = false;
    toggle.textContent = enabled ? 'Pause' : 'Enable';
    toggle.setAttribute('aria-pressed', String(enabled));
    const persistence = body.persistent ? 'protected on this device' : 'available for this session only';
    const automatic = automaticSummary(body);
    if (!enabled) {
      status.textContent = `Continuous Protection is paused (${persistence}). Scheduled scans, Provider-event protection, and metadata checkpoint fallback cannot launch automatic scans. ${automatic}`;
    } else if (body.active) {
      status.textContent = `Continuous Protection is enabled and a bounded automatic scan is running now. ${automatic}`;
    } else if (body.status === 'failed') {
      status.textContent = `Continuous Protection is enabled, but the last scheduled check failed (${body.lastErrorCode || 'provider unavailable'}). Next retry: ${formatTime(body.nextRunAt)}. ${automatic}`;
    } else if (body.status === 'deferred') {
      status.textContent = `Continuous Protection is enabled. The scheduled check was deferred (${body.lastErrorCode || 'manual scan priority'}). Next attempt: ${formatTime(body.nextRunAt)}. ${automatic}`;
    } else {
      status.textContent = `Continuous Protection is enabled. Scheduled fallback: ${formatTime(body.nextRunAt)} (${persistence}). ${automatic}`;
    }
    window.dispatchEvent(new CustomEvent('email-shield-continuous-protection-changed', {
      detail: { accountId, enabled },
    }));
  }

  function clearForSelectionChange() {
    loadedAccountId = null;
    enabled = false;
    toggle.textContent = 'Enable';
    toggle.setAttribute('aria-pressed', 'false');
    toggle.disabled = true;
    interval.disabled = true;
    status.textContent = 'Loading Continuous Protection for the selected mailbox…';
  }

  async function refresh() {
    const snapshot = selectionSnapshot();
    const id = snapshot.id;
    const request = ++requestGeneration;
    panel.hidden = false;
    if (!id) {
      loadedAccountId = null;
      enabled = false;
      toggle.textContent = 'Enable';
      toggle.setAttribute('aria-pressed', 'false');
      toggle.disabled = true;
      interval.disabled = true;
      status.textContent = 'Connect or select a mailbox to configure continuous protection.';
      return;
    }
    if (loadedAccountId !== id) clearForSelectionChange();
    try {
      const response = await fetch(`/api/accounts/${encodeURIComponent(id)}/background-protection`);
      const body = await response.json();
      if (request !== requestGeneration || !selectionMatches(snapshot)) return;
      if (!response.ok) throw new Error(body.error || 'Continuous Protection status failed.');
      render(body, id);
      toggle.disabled = false;
      interval.disabled = false;
    } catch (error) {
      if (request === requestGeneration && selectionMatches(snapshot)) {
        loadedAccountId = null;
        toggle.disabled = true;
        interval.disabled = true;
        status.textContent = error instanceof Error ? error.message : String(error);
      }
    }
  }

  toggle.addEventListener('click', async () => {
    const snapshot = selectionSnapshot();
    const id = snapshot.id;
    if (!id) {
      status.textContent = 'Connect or select a mailbox to configure continuous protection.';
      return;
    }
    if (loadedAccountId !== id) {
      status.textContent = 'Mailbox selection changed. Continuous Protection was not modified; reload its current state first.';
      await refresh();
      return;
    }
    const nextEnabled = !enabled;
    const intervalMinutes = Number(interval.value);
    toggle.disabled = true;
    interval.disabled = true;
    try {
      const response = await fetch(`/api/accounts/${encodeURIComponent(id)}/background-protection`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: nextEnabled, intervalMinutes }),
      });
      const body = await response.json();
      if (!selectionMatches(snapshot)) return;
      if (!response.ok) throw new Error(body.error || 'Continuous Protection update failed.');
      // POST uses the persisted schedule owner. Refresh once to reconcile that
      // write with provider-event / metadata-fallback runtime status.
      await refresh();
    } catch (error) {
      if (selectionMatches(snapshot)) status.textContent = error instanceof Error ? error.message : String(error);
    } finally {
      if (selectionMatches(snapshot) && loadedAccountId === id) {
        toggle.disabled = false;
        interval.disabled = false;
      }
    }
  });

  interval.addEventListener('change', () => {
    const id = selectionSnapshot().id;
    if (id && loadedAccountId === id && enabled) status.textContent = 'Pause and enable again to apply the new Continuous Protection schedule.';
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