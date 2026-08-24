(() => {
  const installedModules = window.emailShieldInstalledModules ||= new Set();
  if (installedModules.has('scan-live-reattach')) return;
  installedModules.add('scan-live-reattach');

  const POLL_MS = 1000;
  const scanButtonIds = ['quickScanBtn', 'fullScanBtn', 'spamScanBtn'];
  let adopted = null;
  let pollTimer = null;
  let pollGeneration = 0;
  let stopInFlight = false;

  function selectedAccountId() {
    return window.emailShieldAccountSelection?.currentId?.()
      || document.querySelector('.account-chip.active')?.dataset.id
      || null;
  }

  function statusElement() {
    return document.getElementById('scanMonitorStatus');
  }

  function setStatus(message, state = '') {
    const status = statusElement();
    if (!status) return;
    status.textContent = message;
    status.className = `scan-monitor-status ${state}`.trim();
  }

  function setRunningControls(running) {
    for (const id of scanButtonIds) {
      const button = document.getElementById(id);
      if (button instanceof HTMLButtonElement) button.disabled = running;
    }
    const stop = document.getElementById('stopScanBtn');
    if (stop instanceof HTMLButtonElement) stop.disabled = !running || stopInFlight;
    const panel = document.getElementById('scanPanel');
    if (panel) panel.setAttribute('aria-busy', running ? 'true' : 'false');
  }

  function cancelPoll() {
    pollGeneration += 1;
    if (pollTimer) clearTimeout(pollTimer);
    pollTimer = null;
  }

  function finishAdoption() {
    cancelPoll();
    adopted = null;
    stopInFlight = false;
    setRunningControls(false);
    window.dispatchEvent(new CustomEvent('email-shield-scan-history-changed'));
  }

  function dispatchWorkspace(workspace) {
    window.dispatchEvent(new CustomEvent('email-shield-workspace-restored', {
      detail: { ...workspace, liveReattachUpdate: true },
    }));
  }

  function schedulePoll(generation) {
    if (!adopted || generation !== pollGeneration) return;
    pollTimer = setTimeout(() => { void poll(generation); }, POLL_MS);
  }

  async function loadWorkspace() {
    const response = await fetch('/api/accounts/workspace', {
      headers: { Accept: 'application/json' },
      cache: 'no-store',
    });
    const workspace = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(workspace.error || `Server returned HTTP ${response.status}`);
    return workspace;
  }

  function presentationMatches(workspace) {
    return Boolean(
      adopted
      && workspace?.selectedAccountId === adopted.accountId
      && workspace?.presentation?.scanId === adopted.scanId,
    );
  }

  function renderAdoptedWorkspace(workspace) {
    const presentation = workspace.presentation;
    if (selectedAccountId() === adopted.accountId) dispatchWorkspace(workspace);

    if (presentation.status === 'running') {
      const examined = Number(presentation.counters?.examined || 0);
      const selected = selectedAccountId();
      setStatus(
        selected === adopted.accountId
          ? `Reattached to the running ${adopted.type} scan… ${examined} messages examined.`
          : 'A scan is still running for another connected mailbox. Return to that mailbox to watch progress or stop it.',
        'running',
      );
      setRunningControls(true);
      return true;
    }

    if (selectedAccountId() === adopted.accountId) {
      const examined = Number(presentation.counters?.examined || 0);
      const label = presentation.status === 'completed' ? 'complete' : presentation.status;
      setStatus(`Reattached scan ${label}. ${examined} messages examined.`, presentation.status === 'completed' ? 'complete' : '');
    }
    finishAdoption();
    return false;
  }

  async function poll(generation) {
    if (!adopted || generation !== pollGeneration) return;
    try {
      const workspace = await loadWorkspace();
      if (!adopted || generation !== pollGeneration) return;
      if (!presentationMatches(workspace)) {
        setStatus('The running scan could no longer be matched to the protected workspace. Check Activity before starting another scan.', 'error');
        finishAdoption();
        return;
      }
      if (renderAdoptedWorkspace(workspace)) schedulePoll(generation);
    } catch (error) {
      if (!adopted || generation !== pollGeneration) return;
      setStatus(`Could not refresh the running scan view: ${error instanceof Error ? error.message : String(error)}`, 'error');
      schedulePoll(generation);
    }
  }

  function adopt(workspace) {
    const presentation = workspace?.presentation;
    if (!presentation || presentation.status !== 'running') return;
    if (typeof workspace.selectedAccountId !== 'string' || !workspace.selectedAccountId) return;
    if (typeof presentation.scanId !== 'string' || !presentation.scanId) return;

    if (adopted?.accountId === workspace.selectedAccountId && adopted?.scanId === presentation.scanId) {
      renderAdoptedWorkspace(workspace);
      return;
    }

    cancelPoll();
    adopted = {
      accountId: workspace.selectedAccountId,
      scanId: presentation.scanId,
      type: typeof presentation.type === 'string' ? presentation.type : 'mailbox',
    };
    stopInFlight = false;
    const generation = pollGeneration;
    renderAdoptedWorkspace(workspace);
    schedulePoll(generation);
  }

  window.addEventListener('email-shield-workspace-restored', (event) => {
    const detail = event instanceof CustomEvent ? event.detail : null;
    if (!detail || detail.liveReattachUpdate === true) return;
    if (detail.presentation?.status === 'running') adopt(detail);
  });

  window.addEventListener('email-shield-account-selection-changed', () => {
    if (!adopted) return;
    const selected = selectedAccountId();
    if (selected === adopted.accountId) {
      setStatus(`Reattached to the running ${adopted.type} scan…`, 'running');
    } else {
      setStatus('A scan is still running for another connected mailbox. Return to that mailbox to watch progress or stop it.', 'running');
    }
    setRunningControls(true);
  });

  window.addEventListener('email-shield-session-expired', () => {
    finishAdoption();
  });

  document.getElementById('stopScanBtn')?.addEventListener('click', async (event) => {
    if (!adopted) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    if (stopInFlight) return;

    const selected = selectedAccountId();
    if (selected !== adopted.accountId) {
      const confirmed = window.confirm('The selected mailbox changed. Stop the scan that is still running for the previously selected mailbox?');
      if (!confirmed) return;
    }

    stopInFlight = true;
    setRunningControls(true);
    setStatus('Stopping the reattached scan and finalizing its protected checkpoint…', 'running');
    try {
      const response = await fetch(`/api/accounts/${encodeURIComponent(adopted.accountId)}/scan/stop`, { method: 'POST' });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(result.error || `Server returned HTTP ${response.status}`);
      if (result.active !== false) throw new Error('Email Shield did not confirm that the scan worker stopped.');
      const workspace = await loadWorkspace();
      if (adopted && presentationMatches(workspace)) renderAdoptedWorkspace(workspace);
      else finishAdoption();
    } catch (error) {
      stopInFlight = false;
      setRunningControls(true);
      setStatus(`Could not stop the running scan: ${error instanceof Error ? error.message : String(error)}`, 'error');
    }
  }, true);
})();
