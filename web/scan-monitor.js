(() => {
  const installedModules = window.emailShieldInstalledModules ||= new Set();
  if (installedModules.has('scan-monitor')) return;
  installedModules.add('scan-monitor');

  const style = document.createElement('style');
  style.textContent = `
    .scan-monitor-status {
      display:flex;align-items:center;gap:9px;min-height:36px;margin-top:12px;padding:9px 12px;
      border:1px solid #2a2f3a;border-radius:6px;color:var(--text-muted);font-size:12px;background:rgba(255,255,255,.015)
    }
    .scan-monitor-status.running::before {
      content:'';width:12px;height:12px;border:2px solid #2a2f3a;border-top-color:#3fb88a;
      border-radius:50%;animation:emailShieldSpin .8s linear infinite
    }
    .scan-monitor-status.error {color:#ff9a9f;border-color:rgba(226,61,79,.55)}
    .scan-monitor-status.complete {color:#3fb88a;border-color:rgba(63,184,138,.45)}
    .scan-diagnostics {margin:10px 0 14px;border:1px solid #2a2f3a;border-radius:6px;background:rgba(255,255,255,.01)}
    .scan-diagnostics summary {cursor:pointer;padding:9px 12px;color:var(--text-muted);font-size:12px;user-select:none}
    .scan-diagnostics-note {padding:0 12px 8px;color:var(--text-faint);font-size:11px}
    .scan-diagnostics-scroll {overflow:auto;max-height:340px;border-top:1px solid #2a2f3a}
    .scan-diagnostics table {width:100%;border-collapse:collapse;font-size:11px}
    .scan-diagnostics th,.scan-diagnostics td {padding:7px 9px;border-bottom:1px solid #2a2f3a;text-align:left;vertical-align:top}
    .scan-diagnostics th {position:sticky;top:0;background:#1b1f27;color:var(--text-muted);font-weight:600}
    .scan-diagnostics td {color:#c9ced8}
    .scan-diagnostics .diag-safe {color:#3fb88a}
    .scan-diagnostics .diag-review {color:#e8b23d}
    .scan-diagnostics .diag-high_risk {color:#e8632e}
    .scan-diagnostics .diag-confirmed_threat {color:#e23d4f}
    .scan-diagnostics .diag-unknown {color:var(--text-muted)}
    .trash-action-status,.policy-action-status {margin-top:9px;font-size:11px;color:var(--text-muted)}
    .trash-action-status.success,.policy-action-status.success {color:#3fb88a}
    .trash-action-status.error,.policy-action-status.error {color:#ff9a9f}
    .card.trash-moved {opacity:.72;border-style:dashed}
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
  status.setAttribute('aria-atomic', 'true');
  status.textContent = 'Ready to scan. Running scans continue locally across a page refresh; protected scan history is shown below.';
  counters.before(status);

  const diagnostics = document.createElement('details');
  diagnostics.id = 'scanDiagnosticAudit';
  diagnostics.className = 'scan-diagnostics';
  diagnostics.open = false;
  diagnostics.innerHTML = `
    <summary>Technical scan details (0)</summary>
    <div class="scan-diagnostics-note">Local privacy-safe results. Shows verdict, subject, sender and inspection notes—never message bodies, raw HTML, credentials, unsubscribe destinations, or attachment content.</div>
    <div class="scan-diagnostics-scroll"><table>
      <caption class="visually-hidden">Privacy-safe scanned message results</caption>
      <thead><tr><th scope="col">Verdict</th><th scope="col">Score</th><th scope="col">Subject</th><th scope="col">Sender</th><th scope="col">Parse</th><th scope="col">Evidence / notes</th></tr></thead>
      <tbody></tbody>
    </table></div>`;
  cards.before(diagnostics);

  let source = null;
  let accountId = null;
  let receivedServerEvent = false;
  let diagnosticRows = [];
  let sessionExpired = false;

  window.addEventListener('email-shield-session-expired', () => {
    sessionExpired = true;
    finish();
  });

  function historyChanged() {
    window.dispatchEvent(new CustomEvent('email-shield-scan-history-changed'));
  }

  function policyChanged() {
    // Personal Policy owns its refresh lifecycle. One semantic event avoids
    // racing an event-triggered load against a synthetic Refresh-button load.
    window.dispatchEvent(new CustomEvent('email-shield-policy-changed'));
  }

  function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, (character) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    })[character]);
  }

  function setStatus(message, state = '') {
    status.textContent = message;
    status.className = `scan-monitor-status ${state}`.trim();
  }

  function selectedAccountId() {
    return document.querySelector('.account-chip.active')?.dataset.id || accountId;
  }

  function finish() {
    stopButton.disabled = true;
    scanPanel.setAttribute('aria-busy', 'false');
    source?.close();
    source = null;
  }

  async function validateProtectedScanSession(id) {
    const response = await fetch('/api/accounts', {
      method: 'GET',
      headers: { Accept: 'application/json' },
      cache: 'no-store',
    });
    const body = await response.json().catch(() => null);
    if (!response.ok) {
      throw new Error(body?.error || 'The protected local session expired. Reload Email Shield.');
    }
    if (!Array.isArray(body) || !body.some((account) => account?.accountId === id)) {
      throw new Error('The selected account no longer exists in this Email Shield process. Reload and reconnect it.');
    }
  }

  function renderDiagnostics() {
    diagnostics.querySelector('summary').textContent = `Technical scan details (${diagnosticRows.length})`;
    const tbody = diagnostics.querySelector('tbody');
    tbody.innerHTML = diagnosticRows.map((item) => {
      const evidenceCodes = item.evidenceCodes?.length ? item.evidenceCodes.join(', ') : 'none';
      const evidence = item.verdict === 'safe' && Number(item.score) > 0
        ? `context only: ${evidenceCodes}`
        : evidenceCodes;
      const allNotes = [...(item.parseNotes || []), ...(item.decisionNotes || [])];
      const notes = allNotes.length ? [...new Set(allNotes)].join(' | ') : 'none';
      const review = item.reviewAction || {};
      const unsubscribe = item.unsubscribeAction || {};
      return `<tr data-message-row="true"
        data-review-token="${escapeHtml(review.token || '')}"
        data-already-approved="${review.alreadyApproved === true ? 'true' : 'false'}"
        data-sender-trusted="${review.senderTrusted === true ? 'true' : 'false'}"
        data-can-report-spam="${review.canReportSpam === true ? 'true' : 'false'}"
        data-unsubscribe-available="${unsubscribe.available === true ? 'true' : 'false'}"
        data-unsubscribe-token="${escapeHtml(unsubscribe.token || '')}"
        data-unsubscribe-key="${escapeHtml(unsubscribe.actionKey || '')}"
        data-unsubscribe-method="${escapeHtml(unsubscribe.method || 'none')}"
        data-unsubscribe-done="${unsubscribe.alreadyUnsubscribed === true ? 'true' : 'false'}">
        <td class="diag-${escapeHtml(item.verdict)}">${escapeHtml(item.verdict)}</td>
        <td>${escapeHtml(item.score)}</td>
        <td class="diag-subject">${escapeHtml(item.subject)}</td>
        <td class="diag-sender">${escapeHtml(item.fromAddress || item.fromDomain || 'unknown')}</td>
        <td>${escapeHtml(item.parseStatus)}</td>
        <td><strong>${escapeHtml(evidence)}</strong><br>${escapeHtml(notes)}</td>
      </tr>`;
    }).join('');
  }

  function renderProgress(progress) {
    if (typeof window.renderCounters === 'function') window.renderCounters(progress.counters);
    else counters.textContent = `${progress.counters.examined} messages examined`;

    setStatus(`Scanning… ${progress.counters.examined} messages examined. Last completed page is protected for resume.`, 'running');
    if (progress.diagnosticSummaries?.length) {
      diagnosticRows.push(...progress.diagnosticSummaries);
      renderDiagnostics();
    }
    if (progress.suspiciousCards?.length && typeof window.renderCard === 'function') {
      cards.innerHTML = progress.suspiciousCards.map(window.renderCard).join('') + cards.innerHTML;
    }
  }

  window.addEventListener('email-shield-workspace-restored', (event) => {
    const detail = event instanceof CustomEvent ? event.detail : null;
    const presentation = detail?.presentation;
    if (!presentation || detail.selectedAccountId !== selectedAccountId()) return;
    diagnosticRows = Array.isArray(presentation.diagnosticSummaries)
      ? presentation.diagnosticSummaries.slice(-500)
      : [];
    renderDiagnostics();
    if (presentation.counters && typeof window.renderCounters === 'function') {
      window.renderCounters(presentation.counters);
    }
    if (Array.isArray(presentation.suspiciousCards) && typeof window.renderCard === 'function') {
      cards.innerHTML = presentation.suspiciousCards.slice(0, 200).map(window.renderCard).join('');
    }
    const restoredAt = Number(presentation.updatedAt);
    const time = Number.isFinite(restoredAt)
      ? (window.emailShieldI18n?.formatDate(restoredAt) || new Date(restoredAt).toLocaleString())
      : 'this process';
    setStatus(`Restored the last privacy-bounded ${presentation.type || 'mailbox'} scan view from ${time}. Status: ${presentation.status || 'unknown'}.`, presentation.status === 'completed' ? 'complete' : '');
  });

  async function start(type, options = {}) {
    const resumeScanId = typeof options?.resumeScanId === 'string' ? options.resumeScanId : null;
    const requestedAccountId = selectedAccountId();
    accountId = requestedAccountId;
    if (!requestedAccountId) {
      setStatus('Select a connected account first.', 'error');
      return;
    }

    source?.close();
    scanPanel.setAttribute('aria-busy', 'true');
    receivedServerEvent = false;
    sessionExpired = false;
    stopButton.disabled = true;
    setStatus(`Authorizing ${resumeScanId ? 'resumed ' : ''}${type} scan…`, 'running');

    try {
      await validateProtectedScanSession(requestedAccountId);
    } catch (error) {
      finish();
      const message = sessionExpired
        ? 'The protected local session expired after the Email Shield process restarted. Reload the dashboard before scanning.'
        : error instanceof Error ? error.message : String(error);
      setStatus(message, 'error');
      return;
    }

    if (selectedAccountId() !== requestedAccountId) {
      finish();
      setStatus('The selected account changed before the scan started. Start the scan again.', 'error');
      return;
    }

    if (!resumeScanId) {
      counters.innerHTML = '';
      cards.innerHTML = '';
      diagnosticRows = [];
      renderDiagnostics();
    }
    stopButton.disabled = false;
    setStatus(`${resumeScanId ? 'Resuming' : 'Starting'} ${type} scan…`, 'running');

    const streamPath = resumeScanId
      ? `/api/accounts/${encodeURIComponent(requestedAccountId)}/scan/resume/${encodeURIComponent(resumeScanId)}`
      : `/api/accounts/${encodeURIComponent(requestedAccountId)}/scan/${encodeURIComponent(type)}`;
    const es = new EventSource(streamPath);
    source = es;

    es.addEventListener('scan-started', (event) => {
      receivedServerEvent = true;
      let value = { resumed: Boolean(resumeScanId), counters: null };
      try { value = JSON.parse(event.data); } catch {}
      if (value.resumed === true && value.counters) {
        if (typeof window.renderCounters === 'function') window.renderCounters(value.counters);
        else counters.textContent = `${Number(value.counters.examined || 0)} messages examined`;
        setStatus(`Resumed ${type} scan after ${Number(value.counters.examined || 0)} examined message(s). Continuing from the last confirmed provider page…`, 'running');
      } else {
        setStatus('Scan worker started. Connecting to the provider…', 'running');
      }
      historyChanged();
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
      setStatus(counters.textContent.trim() ? 'Scan complete. Results remain available in the optional lists below and the privacy-reduced history record is saved.' : 'Scan complete. No additional readable messages were returned.', 'complete');
      finish();
      historyChanged();
    });
    es.addEventListener('scan-error', (event) => {
      let value = { message: 'The scan failed.', status: 'failed' };
      try { value = JSON.parse(event.data); } catch {}
      const stopped = value.status === 'stopped';
      setStatus(value.message || (stopped ? 'Scan stopped.' : 'The scan failed.'), stopped ? 'complete' : 'error');
      finish();
      historyChanged();
    });
    es.onerror = () => {
      if (es.readyState === EventSource.CLOSED) return;
      setStatus(
        sessionExpired
          ? 'The protected local session expired. Reload Email Shield before scanning.'
          : receivedServerEvent
            ? 'The dashboard lost the live scan stream. The Worker continues locally and its protected progress is available in Scan history.'
            : 'Could not open the scan stream. Check Scan history for an existing running or resumable scan.',
        'error',
      );
      finish();
      historyChanged();
    };
  }

  async function handlePolicyAction(event) {
    const button = event.target instanceof Element
      ? event.target.closest('[data-action="block-sender"],[data-action="block-domain"]')
      : null;
    if (!(button instanceof HTMLButtonElement) || button.disabled) return;

    event.preventDefault();
    event.stopImmediatePropagation();

    const id = selectedAccountId();
    const token = button.dataset.reviewToken;
    const action = button.dataset.action || '';
    const isSender = action === 'block-sender';
    const scope = isSender ? 'sender' : 'domain';
    const card = button.closest('.card');
    const subject = card?.querySelector('.card-subject')?.textContent?.trim() || '(no subject)';
    const sender = card?.querySelector('.card-from')?.textContent?.trim() || 'unknown sender';

    if (!id || !token) {
      setStatus(`Block ${scope} failed: the selected account or protected message action is missing.`, 'error');
      return;
    }

    const consequence = isSender
      ? 'Email Shield will save an account-local block for the exact sender and attempt to move this current message to Trash. Future messages from this exact address will be Confirmed Threat.'
      : 'Email Shield will save an account-local domain block and attempt to move this current message to Trash. Future messages from this domain will be Confirmed Threat. Shared consumer-mail domains are rejected server-side.';
    const confirmed = window.confirm(
      `Block this ${scope} for the selected account?\n\n${subject}\n${sender}\n\n${consequence}\n\nIf the provider Trash move fails, the saved protection rule still remains active.`,
    );
    if (!confirmed) return;

    const previousText = button.textContent;
    button.disabled = true;
    button.textContent = 'Blocking…';
    let actionStatus = card?.querySelector('.policy-action-status');
    if (!actionStatus && card) {
      actionStatus = document.createElement('div');
      actionStatus.className = 'policy-action-status';
      actionStatus.setAttribute('role', 'status');
      card.appendChild(actionStatus);
    }
    if (actionStatus) {
      actionStatus.className = 'policy-action-status';
      actionStatus.textContent = `Saving an account-scoped ${scope} block and requesting the current-message Trash move…`;
    }

    try {
      const response = await fetch(`/api/accounts/${encodeURIComponent(id)}/messages/block-${scope}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token }),
      });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(result.error || `Server returned HTTP ${response.status}`);
      if (result.blocked !== true || result.scope !== scope || result.accountId !== id || result.token !== token) {
        throw new Error('The server did not confirm the protected account-scoped block.');
      }

      // Synchronize the exact protected capability, not browser-displayed sender
      // text. Sender/domain identity is server-derived from this opaque token.
      document.querySelectorAll(`[data-action="block-${scope}"][data-review-token="${CSS.escape(token)}"]`).forEach((candidate) => {
        candidate.disabled = true;
        candidate.textContent = isSender ? 'Sender blocked ✓' : 'Domain blocked ✓';
      });

      if (result.movedCurrent === true) {
        document.querySelectorAll(`[data-action="trash"][data-review-token="${CSS.escape(token)}"]`).forEach((candidate) => {
          candidate.disabled = true;
          candidate.textContent = 'Moved to Trash ✓';
        });
        card?.classList.add('trash-moved');
      }

      if (actionStatus) {
        actionStatus.className = result.movedCurrent === true ? 'policy-action-status success' : 'policy-action-status error';
        actionStatus.textContent = result.movedCurrent === true
          ? `${isSender ? 'Sender' : 'Domain'} block saved and the provider confirmed this message moved to Trash.`
          : `${isSender ? 'Sender' : 'Domain'} block saved. The current message could not be moved to Trash: ${result.moveError || 'provider move not confirmed'}.`;
      }
      setStatus(
        result.movedCurrent === true
          ? `${isSender ? 'Sender' : 'Domain'} block saved. The current message was moved to Trash.`
          : `${isSender ? 'Sender' : 'Domain'} block saved. Current-message Trash move needs a retry.`,
        result.movedCurrent === true ? 'complete' : 'error',
      );
      policyChanged();
    } catch (error) {
      button.disabled = false;
      button.textContent = previousText || `Block ${scope}`;
      const message = error instanceof Error ? error.message : String(error);
      if (actionStatus) {
        actionStatus.className = 'policy-action-status error';
        actionStatus.textContent = `Block failed: ${message}`;
      }
      setStatus(`Block ${scope} failed: ${message}`, 'error');
    }
  }

  async function handleTrashAction(event) {
    const button = event.target instanceof Element
      ? event.target.closest('[data-action="trash"]')
      : null;
    if (!(button instanceof HTMLButtonElement) || button.disabled) return;

    event.preventDefault();
    event.stopImmediatePropagation();

    const id = selectedAccountId();
    const token = button.dataset.reviewToken;
    const card = button.closest('.card');
    const subject = card?.querySelector('.card-subject')?.textContent?.trim() || '(no subject)';
    const sender = card?.querySelector('.card-from')?.textContent?.trim() || 'unknown sender';

    if (!id || !token) {
      setStatus('Move failed: the account or protected action token is missing.', 'error');
      return;
    }

    const confirmed = window.confirm(
      `Move exactly this message to the provider Trash folder?\n\n${subject}\n${sender}\n\nThis is reversible from Trash.`,
    );
    if (!confirmed) return;

    const previousText = button.textContent;
    button.disabled = true;
    button.textContent = 'Moving…';
    let actionStatus = card?.querySelector('.trash-action-status');
    if (!actionStatus && card) {
      actionStatus = document.createElement('div');
      actionStatus.className = 'trash-action-status';
      actionStatus.setAttribute('role', 'status');
      card.appendChild(actionStatus);
    }
    if (actionStatus) {
      actionStatus.className = 'trash-action-status';
      actionStatus.textContent = 'Requesting a reversible provider Trash move…';
    }

    try {
      const response = await fetch(`/api/accounts/${encodeURIComponent(id)}/messages/trash`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token }),
      });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(result.error || `Server returned HTTP ${response.status}`);
      const failedReason = Array.isArray(result.failed) && result.failed.length
        ? result.failed[0]?.reason
        : null;
      if (result.success !== true || result.accountId !== id || result.token !== token || result.requested !== 1 || result.moved !== 1 || failedReason) {
        throw new Error(failedReason || `Provider reported moved ${result.moved ?? 0} of ${result.requested ?? 1}.`);
      }

      button.textContent = 'Moved to Trash ✓';
      card?.classList.add('trash-moved');
      if (actionStatus) {
        actionStatus.className = 'trash-action-status success';
        actionStatus.textContent = 'Provider confirmed that exactly one message was moved to Trash.';
      }
      setStatus('Exactly one message was moved to the provider Trash folder.', 'complete');
    } catch (error) {
      button.disabled = false;
      button.textContent = previousText || 'Move to Trash';
      const message = error instanceof Error ? error.message : String(error);
      if (actionStatus) {
        actionStatus.className = 'trash-action-status error';
        actionStatus.textContent = `Move failed: ${message}`;
      }
      setStatus(`Move failed: ${message}`, 'error');
    }
  }

  document.addEventListener('click', handlePolicyAction, true);
  document.addEventListener('click', handleTrashAction, true);

  Object.defineProperty(window, 'emailShieldStartScan', {
    value: (type, options = {}) => start(type, options),
    writable: false,
    configurable: false,
    enumerable: false,
  });

  for (const [id, type] of [
    ['quickScanBtn', 'quick'],
    ['fullScanBtn', 'full'],
    ['spamScanBtn', 'spam'],
  ]) {
    document.getElementById(id)?.addEventListener('click', (event) => {
      event.preventDefault();
      event.stopImmediatePropagation();
      void start(type);
    }, true);
  }

  stopButton.addEventListener('click', async (event) => {
    event.preventDefault();
    event.stopImmediatePropagation();
    const id = selectedAccountId();
    if (!id) {
      setStatus('Stop failed: no connected mailbox is selected for this scan.', 'error');
      return;
    }
    setStatus('Stopping scan and finalizing the protected resume checkpoint…', 'running');
    let serverFinal = false;
    try {
      const response = await fetch(`/api/accounts/${encodeURIComponent(id)}/scan/stop`, { method: 'POST' });
      const result = await response.json().catch(() => ({}));
      serverFinal = result.active === false;
      if (!response.ok) throw new Error(result.error || `Server returned HTTP ${response.status}`);
      if (result.active !== false) throw new Error('Email Shield did not confirm that the scan worker stopped.');
      if (result.status === 'completed') {
        setStatus('The scan completed before the stop request took effect. Results and protected history are complete.', 'complete');
      } else if (result.stopped === true && result.historySaved === true && result.resumable === true) {
        const examined = Number(result.counters?.examined || 0);
        setStatus(`Scan stopped after ${examined} examined message(s). Resume will continue from the last confirmed provider page.`, 'complete');
      } else if (result.status === 'idle') {
        setStatus('No scan is currently running.', 'complete');
      } else {
        throw new Error('Email Shield stopped the worker but did not confirm a resumable protected checkpoint.');
      }
    } catch (error) {
      setStatus(`Stop failed: ${error instanceof Error ? error.message : String(error)}`, 'error');
    } finally {
      if (serverFinal) finish();
      historyChanged();
    }
  }, true);
})();