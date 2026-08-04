(() => {
  const style = document.createElement('style');
  style.textContent = `
    .scan-monitor-status {
      display:flex;align-items:center;gap:9px;min-height:36px;margin-top:12px;padding:9px 12px;
      border:1px solid #2a2f3a;border-radius:6px;color:#8b93a3;font-size:12px;background:rgba(255,255,255,.015)
    }
    .scan-monitor-status.running::before {
      content:'';width:12px;height:12px;border:2px solid #2a2f3a;border-top-color:#3fb88a;
      border-radius:50%;animation:emailShieldSpin .8s linear infinite
    }
    .scan-monitor-status.error {color:#ff9a9f;border-color:rgba(226,61,79,.55)}
    .scan-monitor-status.complete {color:#3fb88a;border-color:rgba(63,184,138,.45)}
    @keyframes emailShieldSpin {to{transform:rotate(360deg)}}
  `;
  document.head.appendChild(style);

  const scanPanel = document.getElementById('scanPanel');
  const counters = document.getElementById('counters');
  const cards = document.getElementById('cards');
  const stopButton = document.getElementById('stopScanBtn');
  if (!scanPanel || !counters || !cards || !stopButton) return;

  const status = document.createElement('div');
  status.id = 'scanMonitorStatus';
  status.className = 'scan-monitor-status';
  status.setAttribute('role', 'status');
  status.setAttribute('aria-live', 'polite');
  status.textContent = 'Ready to scan.';
  counters.before(status);

  let source = null;
  let accountId = null;
  let receivedServerEvent = false;

  function setStatus(message, state = '') {
    status.textContent = message;
    status.className = `scan-monitor-status ${state}`.trim();
  }

  function selectedAccountId() {
    return document.querySelector('.account-chip.active')?.dataset.id || accountId;
  }

  function finish() {
    stopButton.disabled = true;
    source?.close();
    source = null;
  }

  function renderProgress(progress) {
    if (typeof window.renderCounters === 'function') window.renderCounters(progress.counters);
    else counters.textContent = `${progress.counters.examined} messages examined`;

    setStatus(`Scanning… ${progress.counters.examined} messages examined.`, 'running');
    if (progress.suspiciousCards?.length && typeof window.renderCard === 'function') {
      cards.innerHTML = progress.suspiciousCards.map(window.renderCard).join('') + cards.innerHTML;
      if (typeof window.wireCardActions === 'function') window.wireCardActions();
    }
  }

  function start(type) {
    accountId = selectedAccountId();
    if (!accountId) {
      setStatus('Select a connected account first.', 'error');
      return;
    }

    source?.close();
    counters.innerHTML = '';
    cards.innerHTML = '';
    stopButton.disabled = false;
    receivedServerEvent = false;
    setStatus(`Starting ${type} scan…`, 'running');

    const es = new EventSource(`/api/accounts/${encodeURIComponent(accountId)}/scan/${type}`);
    source = es;

    es.addEventListener('scan-started', () => {
      receivedServerEvent = true;
      setStatus('Scan worker started. Connecting to the provider…', 'running');
    });
    es.addEventListener('scan-status', (event) => {
      receivedServerEvent = true;
      try {
        const value = JSON.parse(event.data);
        setStatus(value.message || 'Scanning…', value.phase === 'complete' ? 'complete' : 'running');
      } catch {
        setStatus('Scanning…', 'running');
      }
    });
    es.onmessage = (event) => {
      receivedServerEvent = true;
      try { renderProgress(JSON.parse(event.data)); }
      catch (error) { setStatus(`Could not render scan progress: ${error.message}`, 'error'); }
    };
    es.addEventListener('scan-complete', () => {
      setStatus(counters.textContent.trim() ? 'Scan complete. Results are shown below.' : 'Scan complete. No readable messages were returned.', 'complete');
      finish();
    });
    es.addEventListener('scan-error', (event) => {
      let message = 'The scan failed.';
      try { message = JSON.parse(event.data).message || message; } catch {}
      setStatus(message, 'error');
      finish();
    });
    es.onerror = () => {
      if (es.readyState === EventSource.CLOSED) return;
      setStatus(
        receivedServerEvent
          ? 'The scan connection was interrupted. Check the terminal for details.'
          : 'Could not open the scan stream. Check the terminal for the server error.',
        'error',
      );
      finish();
    };
  }

  for (const [id, type] of [
    ['quickScanBtn', 'quick'],
    ['fullScanBtn', 'full'],
    ['spamScanBtn', 'spam'],
  ]) {
    document.getElementById(id)?.addEventListener('click', (event) => {
      event.preventDefault();
      event.stopImmediatePropagation();
      start(type);
    }, true);
  }

  stopButton.addEventListener('click', async (event) => {
    event.preventDefault();
    event.stopImmediatePropagation();
    const id = selectedAccountId();
    setStatus('Stopping scan…', 'running');
    try {
      if (id) await fetch(`/api/accounts/${encodeURIComponent(id)}/scan/stop`, { method: 'POST' });
      setStatus('Scan stopped.', 'complete');
    } catch (error) {
      setStatus(`Stop failed: ${error.message}`, 'error');
    } finally {
      finish();
    }
  }, true);
})();
