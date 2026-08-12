(() => {
  const installedModules = window.emailShieldInstalledModules ||= new Set();
  if (installedModules.has('protection-learning')) return;
  installedModules.add('protection-learning');

  const submittedPositiveFeedback = new Set();
  const reportTrashAttempts = new Set();

  function selectedAccountId() {
    return document.querySelector('.account-chip.active')?.dataset.id || null;
  }

  function setGlobalStatus(message, state = '') {
    const status = document.getElementById('scanMonitorStatus');
    if (!status) return;
    status.textContent = message;
    status.className = `scan-monitor-status ${state}`.trim();
  }

  function cardFor(button) {
    return button.closest('.card') || button.closest('[data-message-row="true"]');
  }

  function reviewToken(button) {
    return button.dataset.reviewToken || cardFor(button)?.dataset.reviewToken || '';
  }

  function actionStatus(card) {
    if (!card) return null;
    let status = card.querySelector('.policy-action-status,.review-action-status,.trash-action-status');
    if (status) return status;
    status = document.createElement('div');
    status.className = 'policy-action-status';
    status.setAttribute('role', 'status');
    card.appendChild(status);
    return status;
  }

  function disableTrash(card, text = 'Moved to Trash ✓') {
    card?.querySelectorAll('[data-action="trash"]').forEach((button) => {
      if (!(button instanceof HTMLButtonElement)) return;
      button.disabled = true;
      button.textContent = text;
    });
    card?.classList.add('trash-moved');
  }

  async function post(accountId, endpoint, body) {
    const response = await fetch(`/api/accounts/${encodeURIComponent(accountId)}/messages/${endpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.error || `Server returned HTTP ${response.status}`);
    return result;
  }

  async function submitLegitimateFeedback(accountId, token) {
    const key = `${accountId}:${token}`;
    if (submittedPositiveFeedback.has(key)) return;
    submittedPositiveFeedback.add(key);
    try {
      await post(accountId, 'legitimate-feedback', { token });
    } catch {
      // Learning is deliberately secondary to the user's local Safe/Trust
      // decision. A later fresh action can retry; never undo local protection
      // or expose message content because the shared feedback path is offline.
      submittedPositiveFeedback.delete(key);
    }
  }

  async function trashReportedMessage(accountId, token, card) {
    const key = `${accountId}:${token}`;
    if (reportTrashAttempts.has(key)) return;
    reportTrashAttempts.add(key);
    const status = actionStatus(card);
    try {
      const result = await post(accountId, 'trash', { token });
      if (result.success !== true || result.moved !== 1 || result.requested !== 1) {
        throw new Error('The provider did not confirm exactly one Trash move.');
      }
      disableTrash(card);
      if (status) {
        status.className = 'review-action-status success';
        status.textContent = 'Scam reported and this message moved to Trash. Future matching campaign messages are automatically trashed for this account.';
      }
      setGlobalStatus('Scam campaign protected locally and the current message moved to Trash.', 'complete');
    } catch (error) {
      reportTrashAttempts.delete(key);
      if (status) {
        status.className = 'review-action-status error';
        status.textContent = `Scam protection was saved, but the current message could not be moved to Trash: ${error instanceof Error ? error.message : String(error)}`;
      }
      setGlobalStatus('Scam protection is active, but the provider Trash move needs attention.', 'error');
    }
  }

  function observeSuccessfulReviewAction(button, accountId, token, kind) {
    const expected = kind === 'report'
      ? 'Campaign protected locally ✓'
      : kind === 'safe'
        ? 'Message marked Safe ✓'
        : 'Sender trusted ✓';
    const card = cardFor(button);
    let closed = false;
    const finish = () => {
      if (closed) return;
      if (button.textContent?.trim() !== expected) return;
      closed = true;
      observer.disconnect();
      clearTimeout(timeout);
      if (kind === 'report') void trashReportedMessage(accountId, token, card);
      else void submitLegitimateFeedback(accountId, token);
    };
    const observer = new MutationObserver(finish);
    observer.observe(button, { childList: true, subtree: true, characterData: true, attributes: true });
    const timeout = setTimeout(() => {
      closed = true;
      observer.disconnect();
    }, 45_000);
    finish();
  }

  window.addEventListener('click', async (event) => {
    const button = event.target instanceof Element
      ? event.target.closest('[data-action="block-sender"],[data-action="block-domain"]')
      : null;
    if (!(button instanceof HTMLButtonElement) || button.disabled) return;

    // Window capture runs before the legacy document-capture block handler.
    // Owning the event here ensures the browser never sends address/domain as
    // mutation authority; only the opaque scan action token is accepted.
    event.preventDefault();
    event.stopImmediatePropagation();

    const accountId = selectedAccountId();
    const token = reviewToken(button);
    const isSender = button.dataset.action === 'block-sender';
    const scope = isSender ? 'sender' : 'domain';
    const displayValue = isSender ? button.dataset.address : button.dataset.domain;
    const card = cardFor(button);
    const subject = card?.querySelector('.card-subject')?.textContent?.trim() || '(no subject)';

    if (!accountId || !token) {
      setGlobalStatus(`Block ${scope} failed: the protected scan action is missing. Rescan before trying again.`, 'error');
      return;
    }

    const consequence = isSender
      ? 'This message will move to Trash now. Future messages from this exact address will be Confirmed Threat and automatically moved to Trash when Email Shield protection scans them.'
      : 'This message will move to Trash now. Future messages from every address on this domain will be Confirmed Threat and automatically moved to Trash when Email Shield protection scans them. Shared consumer-mail domains cannot be blocked domain-wide.';
    if (!window.confirm(`Block this ${scope}?\n\n${displayValue || ''}\nMessage: ${subject}\n\n${consequence}`)) return;

    const previousText = button.textContent;
    const status = actionStatus(card);
    button.disabled = true;
    button.textContent = 'Blocking and moving…';
    if (status) {
      status.className = 'policy-action-status';
      status.textContent = `Saving the account-scoped ${scope} block and requesting the provider Trash move…`;
    }

    try {
      const result = await post(accountId, `block-${scope}`, { token });
      if (result.blocked !== true || result.scope !== scope || result.accountId !== accountId) {
        throw new Error('The server did not confirm the durable block.');
      }

      const normalizedValue = String(result.value || displayValue || '').toLowerCase();
      document.querySelectorAll(`[data-action="block-${scope}"]`).forEach((candidate) => {
        if (!(candidate instanceof HTMLButtonElement)) return;
        const candidateValue = String(isSender ? candidate.dataset.address : candidate.dataset.domain).toLowerCase();
        if (candidateValue !== normalizedValue) return;
        candidate.dataset.action = `unblock-${scope}`;
        candidate.disabled = false;
        candidate.textContent = isSender ? 'Unblock sender (blocked ✓)' : 'Unblock domain (blocked ✓)';
      });

      if (result.movedCurrent === true) {
        disableTrash(card);
        if (status) {
          status.className = 'policy-action-status success';
          status.textContent = `${isSender ? 'Sender' : 'Domain'} blocked. The current message was moved to Trash and future matches will be automatically trashed.`;
        }
        setGlobalStatus(`${isSender ? 'Sender' : 'Domain'} blocked and current message moved to Trash.`, 'complete');
      } else {
        if (status) {
          status.className = 'policy-action-status error';
          status.textContent = `${isSender ? 'Sender' : 'Domain'} block is active for future mail, but this message could not be moved to Trash: ${result.moveError || 'provider move not confirmed'}.`;
        }
        setGlobalStatus(`${isSender ? 'Sender' : 'Domain'} block is active; current Trash move needs attention.`, 'error');
      }
    } catch (error) {
      button.disabled = false;
      button.textContent = previousText || `Block ${scope}`;
      const message = error instanceof Error ? error.message : String(error);
      if (status) {
        status.className = 'policy-action-status error';
        status.textContent = `Block failed: ${message}`;
      }
      setGlobalStatus(`Block ${scope} failed: ${message}`, 'error');
    }
  }, true);

  window.addEventListener('click', (event) => {
    const button = event.target instanceof Element
      ? event.target.closest('[data-action="mark-safe"],[data-action="trust-sender"],[data-action="report-scam"]')
      : null;
    if (!(button instanceof HTMLButtonElement) || button.disabled) return;
    const accountId = selectedAccountId();
    const token = reviewToken(button);
    if (!accountId || !token) return;
    const kind = button.dataset.action === 'report-scam'
      ? 'report'
      : button.dataset.action === 'mark-safe' ? 'safe' : 'trust';
    observeSuccessfulReviewAction(button, accountId, token, kind);
  }, true);
})();
