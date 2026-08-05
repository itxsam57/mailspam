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
    .scan-diagnostics {margin:10px 0 14px;border:1px solid #2a2f3a;border-radius:6px;background:rgba(255,255,255,.01)}
    .scan-diagnostics summary {cursor:pointer;padding:9px 12px;color:#8b93a3;font-size:12px;user-select:none}
    .scan-diagnostics-note {padding:0 12px 8px;color:#5b6272;font-size:11px}
    .scan-diagnostics-scroll {overflow:auto;max-height:340px;border-top:1px solid #2a2f3a}
    .scan-diagnostics table {width:100%;border-collapse:collapse;font-size:11px}
    .scan-diagnostics th,.scan-diagnostics td {padding:7px 9px;border-bottom:1px solid #2a2f3a;text-align:left;vertical-align:top}
    .scan-diagnostics th {position:sticky;top:0;background:#1b1f27;color:#8b93a3;font-weight:600}
    .scan-diagnostics td {color:#c9ced8}
    .scan-diagnostics .diag-safe {color:#3fb88a}
    .scan-diagnostics .diag-review {color:#e8b23d}
    .scan-diagnostics .diag-high_risk {color:#e8632e}
    .scan-diagnostics .diag-confirmed_threat {color:#e23d4f}
    .scan-diagnostics .diag-unknown {color:#8b93a3}
    .trash-action-status,.policy-action-status {margin-top:9px;font-size:11px;color:#8b93a3}
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
  status.textContent = 'Ready to scan.';
  counters.before(status);

  const diagnostics = document.createElement('details');
  diagnostics.id = 'scanDiagnosticAudit';
  diagnostics.className = 'scan-diagnostics';
  diagnostics.innerHTML = `
    <summary>Diagnostic audit (0 messages)</summary>
    <div class="scan-diagnostics-note">Local test view only. Shows metadata, verdicts, evidence codes, and parse notes—never message bodies, raw HTML, credentials, unsubscribe destinations, or attachment content.</div>
    <div class="scan-diagnostics-scroll"><table>
      <thead><tr><th>Verdict</th><th>Score</th><th>Subject</th><th>Sender</th><th>Parse</th><th>Evidence / notes</th></tr></thead>
      <tbody></tbody>
    </table></div>`;
  cards.before(diagnostics);

  let source = null;
  let accountId = null;
  let receivedServerEvent = false;
  let diagnosticRows = [];

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
    source?.close();
    source = null;
  }

  function renderDiagnostics() {
    diagnostics.querySelector('summary').textContent = `Diagnostic audit (${diagnosticRows.length} messages)`;
    const tbody = diagnostics.querySelector('tbody');
    tbody.innerHTML = diagnosticRows.map((item) => {
      const evidence = item.evidenceCodes?.length ? item.evidenceCodes.join(', ') : 'none';
      const notes = item.parseNotes?.length ? item.parseNotes.join(' | ') : 'none';
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

    setStatus(`Scanning… ${progress.counters.examined} messages examined.`, 'running');
    if (progress.diagnosticSummaries?.length) {
      diagnosticRows.push(...progress.diagnosticSummaries);
      renderDiagnostics();
    }
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
    diagnosticRows = [];
    diagnostics.open = false;
    renderDiagnostics();
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

  async function handlePolicyAction(event) {
    const button = event.target instanceof Element
      ? event.target.closest('[data-action="block-sender"],[data-action="block-domain"]')
      : null;
    if (!(button instanceof HTMLButtonElement) || button.disabled) return;

    event.preventDefault();
    event.stopImmediatePropagation();

    const id = selectedAccountId();
    const isSender = button.dataset.action === 'block-sender';
    const scope = isSender ? 'sender' : 'domain';
    const value = isSender ? button.dataset.address : button.dataset.domain;
    const card = button.closest('.card');
    const subject = card?.querySelector('.card-subject')?.textContent?.trim() || '(no subject)';

    if (!id || !value) {
      setStatus(`Block ${scope} failed: the selected account or value is missing.`, 'error');
      return;
    }

    const consequence = isSender
      ? 'Future messages from this exact address in the selected account will be Confirmed Threat.'
      : 'Future messages from every address on this domain in the selected account will be Confirmed Threat.';
    const confirmed = window.confirm(
      `Block this ${scope} for the selected account?\n\n${value}\nMessage: ${subject}\n\n${consequence}\nThis does not move or delete mail.`,
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
      actionStatus.textContent = `Saving an account-scoped ${scope} block…`;
    }

    try {
      const endpoint = isSender ? 'block-sender' : 'block-domain';
      const payload = isSender ? { address: value } : { domain: value };
      const response = await fetch(`/api/accounts/${encodeURIComponent(id)}/messages/${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(result.error || `Server returned HTTP ${response.status}`);
      if (result.blocked !== true || result.scope !== scope || result.accountId !== id) {
        throw new Error('The server did not confirm the expected account-scoped block.');
      }

      const normalizedValue = String(result.value || value).toLowerCase();
      cards.querySelectorAll(`[data-action="${isSender ? 'block-sender' : 'block-domain'}"]`).forEach((candidate) => {
        const candidateValue = String(isSender ? candidate.dataset.address : candidate.dataset.domain).toLowerCase();
        if (candidateValue === normalizedValue) {
          candidate.disabled = true;
          candidate.textContent = isSender ? 'Sender blocked ✓' : 'Domain blocked ✓';
        }
      });

      if (actionStatus) {
        actionStatus.className = 'policy-action-status success';
        actionStatus.textContent = `${isSender ? 'Sender' : 'Domain'} block saved for this connected account. Rescan to verify Confirmed Threat verdicts.`;
      }
      setStatus(`${isSender ? 'Sender' : 'Domain'} blocked for the selected account. Rescan to verify.`, 'complete');
    } catch (error) {
      button.disabled = false;
      button.textContent = previousText || (isSender ? 'Block sender' : 'Block domain');
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
    const providerNativeId = button.dataset.nativeId;
    const card = button.closest('.card');
    const subject = card?.querySelector('.card-subject')?.textContent?.trim() || '(no subject)';
    const sender = card?.querySelector('.card-from')?.textContent?.trim() || 'unknown sender';

    if (!id || !providerNativeId) {
      setStatus('Move failed: the account or provider message identifier is missing.', 'error');
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
        body: JSON.stringify({ providerNativeIds: [providerNativeId] }),
      });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(result.error || `Server returned HTTP ${response.status}`);
      const failedReason = Array.isArray(result.failed) && result.failed.length
        ? result.failed[0]?.reason
        : null;
      if (result.requested !== 1 || result.moved !== 1 || failedReason) {
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
