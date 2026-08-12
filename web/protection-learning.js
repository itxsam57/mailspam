(() => {
  const installedModules = window.emailShieldInstalledModules ||= new Set();
  if (installedModules.has('protection-learning')) return;
  installedModules.add('protection-learning');

  const submittedPositiveFeedback = new Set();

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

  function disableSafeTrust(card) {
    card?.querySelectorAll('[data-action="mark-safe"],[data-action="trust-sender"]').forEach((button) => {
      if (button instanceof HTMLButtonElement) button.disabled = true;
    });
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

  async function familyAvailable() {
    try {
      const response = await fetch('/api/profile/v1/snapshot', { cache: 'no-store' });
      const result = await response.json().catch(() => ({}));
      return response.ok && result.signedIn === true && Boolean(result.family);
    } catch {
      return false;
    }
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

  function observeSuccessfulPositiveAction(button, accountId, token, kind) {
    const expected = kind === 'safe' ? 'Message marked Safe ✓' : 'Sender trusted ✓';
    let closed = false;
    const finish = () => {
      if (closed || button.textContent?.trim() !== expected) return;
      closed = true;
      observer.disconnect();
      clearTimeout(timeout);
      void submitLegitimateFeedback(accountId, token);
    };
    const observer = new MutationObserver(finish);
    observer.observe(button, { childList: true, subtree: true, characterData: true, attributes: true });
    const timeout = setTimeout(() => {
      closed = true;
      observer.disconnect();
    }, 45_000);
    finish();
  }

  function communityDeliveryMessage(result) {
    if (result.communityAccepted !== true) {
      return `Shared learning was not accepted${result.communityError ? `: ${result.communityError}` : ''}. Local protection is still active.`;
    }
    if (result.delivery === 'remote_shared') {
      return `Shared network status: ${result.status}; ${result.independentReporters} independent reporter(s).`;
    }
    if (result.delivery === 'queued_remote') {
      return 'The encrypted privacy-reduced report is queued and will retry when the configured shared service is reachable.';
    }
    if (result.delivery === 'embedded_local') {
      return `Local test-network status: ${result.status}; ${result.independentReporters} local reporter proof(s). Other installations are not protected until a central community service is configured.`;
    }
    return 'Local protection is active; no cross-user delivery scope was returned.';
  }

  function familyDeliveryMessage(result) {
    if (result.family?.shared === true) {
      return `Family Shield: ${result.family.status || 'protected'} for this private Shield Circle.`;
    }
    if (result.family?.error) {
      return `Family Shield sharing needs attention: ${result.family.error}. Local protection remains active.`;
    }
    return 'This mailbox is not currently linked to an active Family Shield circle.';
  }

  async function handleReportScam(button, accountId, token, card) {
    const subject = card?.querySelector('.card-subject,.safe-subject,.diag-subject')?.textContent?.trim() || '(no subject)';
    const sender = card?.querySelector('.card-from,.safe-sender,.diag-sender')?.textContent?.trim() || 'unknown sender';
    const familyNote = await familyAvailable()
      ? ' Because this mailbox can be linked to Family Shield, the privacy-reduced campaign fingerprint will also enter the private Shield Circle automatically; no email content is shared.'
      : '';
    const explanation = `Email Shield will save this campaign as a local threat, move this message to Trash now, and automatically Trash future matching campaign mail for this account. Only privacy-reduced campaign indicators are submitted to community learning. Other users are affected only after independent quality thresholds: warning-level campaigns are quarantined to Spam/Junk; globally confirmed threats are moved to Trash.${familyNote}`;
    if (!window.confirm(`Report this scam campaign to Email Shield?\n\n${subject}\n${sender}\n\n${explanation}`)) return;

    let blockSender = false;
    if (button.dataset.sender) {
      blockSender = window.confirm('Also block this exact sender address for your mailbox?\n\nChoose Cancel when the sender is a shared delivery platform. The campaign itself will still be protected locally and future matching campaign mail will be trashed.');
    }

    const previousText = button.textContent;
    const status = actionStatus(card);
    button.disabled = true;
    button.textContent = 'Protecting and moving…';
    if (status) {
      status.className = 'review-action-status';
      status.textContent = 'Saving local campaign protection, moving the current message to Trash, and sharing privacy-reduced protection with eligible Family/community layers…';
    }

    try {
      const result = await post(accountId, 'report-scam', { token, blockSender });
      if (result.success !== true || result.localProtected !== true || result.accountId !== accountId || result.token !== token) {
        throw new Error('The server did not confirm durable local campaign protection.');
      }

      document.querySelectorAll(`[data-action="report-scam"][data-review-token="${CSS.escape(token)}"]`).forEach((candidate) => {
        if (!(candidate instanceof HTMLButtonElement)) return;
        candidate.disabled = true;
        candidate.textContent = 'Campaign protected locally ✓';
      });
      card?.classList.add('community-reported');
      disableSafeTrust(card);

      if (result.senderBlocked === true && button.dataset.sender) {
        const normalizedSender = String(button.dataset.sender).toLowerCase();
        document.querySelectorAll('[data-action="block-sender"]').forEach((candidate) => {
          if (!(candidate instanceof HTMLButtonElement)) return;
          if (String(candidate.dataset.address || '').toLowerCase() !== normalizedSender) return;
          candidate.dataset.action = 'unblock-sender';
          candidate.disabled = false;
          candidate.textContent = 'Unblock sender (blocked ✓)';
        });
      }

      if (result.movedCurrent === true) disableTrash(card);
      const communityState = communityDeliveryMessage(result);
      const familyState = familyDeliveryMessage(result);
      const moveState = result.movedCurrent === true
        ? 'The current message was moved to Trash.'
        : `Local protection is active, but the current provider Trash move needs attention${result.moveError ? `: ${result.moveError}` : '.'}`;
      if (status) {
        status.className = result.movedCurrent === true && result.communityAccepted === true && !result.family?.error
          ? 'review-action-status success'
          : 'review-action-status error';
        status.textContent = `Matching campaign messages are protected locally and future matches will auto-Trash. ${moveState} ${familyState} ${communityState}${result.senderBlocked ? ' The exact sender is also blocked.' : ''}`;
      }
      const complete = result.movedCurrent === true && result.communityAccepted === true && !result.family?.error;
      setGlobalStatus(
        complete
          ? `Scam campaign protected and current message moved to Trash. ${result.family?.shared ? 'Family Shield updated.' : 'Community evidence accepted.'}`
          : 'Scam campaign protection is active; one external protection step needs attention.',
        complete ? 'complete' : 'error',
      );
      if (result.family?.shared) window.dispatchEvent(new CustomEvent('email-shield-family-changed'));
    } catch (error) {
      button.disabled = false;
      button.textContent = previousText || 'Report Scam to Email Shield';
      const message = error instanceof Error ? error.message : String(error);
      if (status) {
        status.className = 'review-action-status error';
        status.textContent = `Report failed before durable local protection was confirmed: ${message}`;
      }
      setGlobalStatus(`Report Scam failed: ${message}`, 'error');
    }
  }

  window.addEventListener('click', async (event) => {
    const button = event.target instanceof Element
      ? event.target.closest('[data-action="block-sender"],[data-action="block-domain"],[data-action="report-scam"]')
      : null;
    if (!(button instanceof HTMLButtonElement) || button.disabled) return;

    // Window capture runs before the legacy document-capture handlers. Durable
    // protection actions are therefore authorized only by the opaque server
    // scan token; browser-supplied sender/domain/message identity is never the
    // source of authority.
    event.preventDefault();
    event.stopImmediatePropagation();

    const accountId = selectedAccountId();
    const token = reviewToken(button);
    const card = cardFor(button);
    if (!accountId || !token) {
      setGlobalStatus('Protection action failed: the protected scan action is missing. Rescan before trying again.', 'error');
      return;
    }

    if (button.dataset.action === 'report-scam') {
      await handleReportScam(button, accountId, token, card);
      return;
    }

    const isSender = button.dataset.action === 'block-sender';
    const scope = isSender ? 'sender' : 'domain';
    const displayValue = isSender ? button.dataset.address : button.dataset.domain;
    const subject = card?.querySelector('.card-subject')?.textContent?.trim() || '(no subject)';
    const consequence = isSender
      ? 'This message will move to Trash now. Future messages from this exact address will be Confirmed Threat and automatically moved to Trash when Email Shield protection scans them.'
      : 'This message will move to Trash now. Future messages from every address on this domain will be Confirmed Threat and automatically moved to Trash when Email Shield protection scans them. Shared consumer-mail domains cannot be blocked domain-wide.';
    if (!window.confirm(`Block this ${scope}?\n\n${displayValue || ''}\nMessage: ${subject}\n\n${consequence}`)) return;

    let shareWithFamily = false;
    if (await familyAvailable()) {
      shareWithFamily = window.confirm(`Also share this blocked campaign with your private Family Shield circle?\n\nChoose OK only when you believe it should protect family members too. Cancel keeps the ${scope} block personal. Email content is never shared.`);
    }

    const previousText = button.textContent;
    const status = actionStatus(card);
    button.disabled = true;
    button.textContent = 'Blocking and moving…';
    if (status) {
      status.className = 'policy-action-status';
      status.textContent = `Saving the account-scoped ${scope} block and requesting the provider Trash move…`;
    }

    try {
      const result = await post(accountId, `block-${scope}`, { token, shareWithFamily });
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

      const familyState = result.family?.shared
        ? ` Family Shield updated (${result.family.status || 'warning'}).`
        : result.family?.error
          ? ` Family sharing failed: ${result.family.error}. The personal block is still active.`
          : '';
      if (result.movedCurrent === true) {
        disableTrash(card);
        if (status) {
          status.className = result.family?.error ? 'policy-action-status error' : 'policy-action-status success';
          status.textContent = `${isSender ? 'Sender' : 'Domain'} blocked. The current message was moved to Trash and future personal matches will be automatically trashed.${familyState}`;
        }
        setGlobalStatus(`${isSender ? 'Sender' : 'Domain'} blocked and current message moved to Trash.${result.family?.shared ? ' Family Shield updated.' : ''}`, result.family?.error ? 'error' : 'complete');
      } else {
        if (status) {
          status.className = 'policy-action-status error';
          status.textContent = `${isSender ? 'Sender' : 'Domain'} block is active for future mail, but this message could not be moved to Trash: ${result.moveError || 'provider move not confirmed'}.${familyState}`;
        }
        setGlobalStatus(`${isSender ? 'Sender' : 'Domain'} block is active; current Trash move needs attention.`, 'error');
      }
      if (result.family?.shared) window.dispatchEvent(new CustomEvent('email-shield-family-changed'));
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
      ? event.target.closest('[data-action="mark-safe"],[data-action="trust-sender"]')
      : null;
    if (!(button instanceof HTMLButtonElement) || button.disabled) return;
    const accountId = selectedAccountId();
    const token = reviewToken(button);
    if (!accountId || !token) return;
    const kind = button.dataset.action === 'mark-safe' ? 'safe' : 'trust';
    observeSuccessfulPositiveAction(button, accountId, token, kind);
  }, true);
})();
