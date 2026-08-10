(() => {
  const panel = document.getElementById('backgroundProtection');
  const interval = document.getElementById('backgroundInterval');
  const toggle = document.getElementById('backgroundToggle');
  const status = document.getElementById('backgroundStatus');
  const accounts = document.getElementById('accountsList');
  if (!(panel instanceof HTMLElement) || !(interval instanceof HTMLSelectElement) || !(toggle instanceof HTMLButtonElement) || !(status instanceof HTMLElement) || !(accounts instanceof HTMLElement)) return;

  let enabled = false;
  let requestGeneration = 0;

  function selectedAccountId() {
    return document.querySelector('.account-chip.active')?.dataset.id || null;
  }

  function formatTime(value) {
    if (!Number.isFinite(value)) return 'not scheduled';
    return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value));
  }

  function render(body) {
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

  async function refresh() {
    const id = selectedAccountId();
    const generation = ++requestGeneration;
    if (!id) {
      panel.hidden = true;
      return;
    }
    panel.hidden = false;
    try {
      const response = await fetch(`/api/accounts/${encodeURIComponent(id)}/background-protection`);
      const body = await response.json();
      if (generation !== requestGeneration || id !== selectedAccountId()) return;
      if (!response.ok) throw new Error(body.error || 'Background protection status failed.');
      render(body);
    } catch (error) {
      if (generation === requestGeneration) status.textContent = error instanceof Error ? error.message : String(error);
    }
  }

  toggle.addEventListener('click', async () => {
    const id = selectedAccountId();
    if (!id) return;
    toggle.disabled = true;
    try {
      const response = await fetch(`/api/accounts/${encodeURIComponent(id)}/background-protection`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !enabled, intervalMinutes: Number(interval.value) }),
      });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error || 'Background protection update failed.');
      render(body);
    } catch (error) {
      status.textContent = error instanceof Error ? error.message : String(error);
    } finally {
      toggle.disabled = false;
    }
  });

  interval.addEventListener('change', () => {
    if (enabled) status.textContent = 'Pause and enable again to apply the new interval.';
  });

  new MutationObserver(() => { void refresh(); }).observe(accounts, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ['class'],
  });
  window.setInterval(() => { if (selectedAccountId()) void refresh(); }, 30_000);
  void refresh();
})();
