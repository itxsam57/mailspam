(() => {
  const installedModules = window.emailShieldInstalledModules ||= new Set();
  if (installedModules.has('review-actions')) return;
  installedModules.add('review-actions');

  const originalRenderCard = window.renderCard;
  if (typeof originalRenderCard !== 'function') return;

  const style = document.createElement('style');
  style.textContent = `
    .review-action-status {display:block;margin-top:7px;font-size:11px;color:var(--text-muted)}
    .review-action-status.success {color:#3fb88a}
    .review-action-status.error {color:#ff9a9f}
    .card.review-approved,.card.spam-moved,.card.community-reported {opacity:.82;border-style:dashed}
    .safe-row-actions {display:flex;gap:6px;flex-wrap:wrap;min-width:240px}
    .safe-row-actions button {font-size:10px;padding:4px 7px}
  `;
  document.head.appendChild(style);

  function selectedAccountId() {
    return document.querySelector('.account-chip.active')?.dataset.id || null;
  }

  function setGlobalStatus(message, state = '') {
    const status = document.getElementById('scanMonitorStatus');
    if (!status) return;
    status.textContent = message;
    status.className = `scan-monitor-status ${state}`.trim();
  }

  function escapeAttribute(value) {
    return String(value ?? '').replace(/[&<>"']/g, (character) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    })[character]);
  }

  window.renderCard = function renderCardWithReviewActions(result) {
    const html = originalRenderCard(result);
    const action = result?.reviewAction;
    if (!action?.token) return html;

    const template = document.createElement('template');
    template.innerHTML = String(html).trim();
    const card = template.content.firstElementChild;
    const actions = card?.querySelector('.card-actions');
    if (!card || !actions) return html;

    const sender = result?.envelope?.from?.address || '';
    const campaignProtected = action.scamAlreadyReported === true;
    const senderBlock = actions.querySelector('[data-action="block-sender"]');
    const domainBlock = actions.querySelector('[data-action="block-domain"]');
    const trash = actions.querySelector('[data-action="trash"]');

    // Every message mutation is authorized by the same opaque review token.
    // The browser-rendered sender/domain strings are presentation only and must
    // never become the authority for a policy mutation.
    if (senderBlock instanceof HTMLButtonElement) {
      senderBlock.dataset.reviewToken = action.token;
      if (action.senderBlocked === true) {
        senderBlock.textContent = 'Sender blocked ✓';
        senderBlock.disabled = true;
      }
    }
    if (domainBlock instanceof HTMLButtonElement) {
      domainBlock.dataset.reviewToken = action.token;
      if (action.domainBlocked === true) {
        domainBlock.textContent = 'Domain blocked ✓';
        domainBlock.disabled = true;
      }
    }
    if (trash instanceof HTMLButtonElement) {
      trash.dataset.reviewToken = action.token;
      delete trash.dataset.nativeId;
    }

    const reportScam = document.createElement('button');
    reportScam.dataset.action = 'report-scam';
    reportScam.dataset.reviewToken = action.token;
    reportScam.dataset.sender = sender;
    reportScam.textContent = campaignProtected ? 'Campaign protected locally ✓' : 'Report Scam to Email Shield';
    reportScam.disabled = campaignProtected;
    actions.appendChild(reportScam);

    if (action.canMoveToSpam) {
      const moveSpam = document.createElement('button');
      moveSpam.dataset.action = 'move-spam';
      moveSpam.dataset.reviewToken = action.token;
      moveSpam.textContent = 'Move to Spam/Junk';
      actions.appendChild(moveSpam);
    }

    if (campaignProtected) {
      const protectedState = document.createElement('button');
      protectedState.disabled = true;
      protectedState.textContent = 'Local scam rule active — Safe/Trust disabled';
      actions.appendChild(protectedState);
      card.classList.add('community-reported');
    } else {
      if (!action.alreadyApproved) {
        const markSafe = document.createElement('button');
        markSafe.dataset.action = 'mark-safe';
        markSafe.dataset.reviewToken = action.token;
        markSafe.textContent = 'Mark this message Safe';
        actions.appendChild(markSafe);
      } else {
        const approved = document.createElement('button');
        approved.disabled = true;
        approved.textContent = 'Message marked Safe ✓';
        actions.appendChild(approved);
      }

      if (sender && !action.senderTrusted) {
        const trust = document.createElement('button');
        trust.dataset.action = 'trust-sender';
        trust.dataset.reviewToken = action.token;
        trust.dataset.sender = sender;
        trust.textContent = 'Trust sender';
        actions.appendChild(trust);
      } else if (sender) {
        const trusted = document.createElement('button');
        trusted.disabled = true;
        trusted.textContent = 'Sender trusted ✓';
        actions.appendChild(trusted);
      }
    }

    card.dataset.reviewToken = escapeAttribute(action.token);
    return card.outerHTML;
  };

  function containerFor(button) {
    return button.closest('.card') || button.closest('[data-message-row="true"]');
  }

  function messageLabel(container) {
    const subject = container?.querySelector('.card-subject,.safe-subject,.diag-subject')?.textContent?.trim() || '(no subject)';
    const sender = container?.querySelector('.card-from,.safe-sender,.diag-sender')?.textContent?.trim() || 'unknown sender';
    return { subject, sender };
  }

  function statusFor(container) {
    if (!container) return null;
    let status = container.querySelector('.review-action-status');
    if (status) return status;
    status = document.createElement('span');
    status.className = 'review-action-status';
    status.setAttribute('role', 'status');
    if (container.matches('tr')) {
      const actionCell = container.querySelector('.safe-row-actions')?.parentElement || container.lastElementChild;
      actionCell?.appendChild(status);
    } else {
      container.appendChild(status);
    }
    return status;
  }

  function disableConflictingDecisions(token) {
    document.querySelectorAll(`[data-review-token="${CSS.escape(token)}"]`).forEach((candidate) => {
      if (candidate.dataset.action === 'mark-safe' || candidate.dataset.action === 'trust-sender') candidate.disabled = true;
    });
  }

  function communityDeliveryMessage(result) {
    if (result.delivery === 'remote_shared') {
      return `Shared network status: ${result.status}; ${result.independentReporters} independent reporter(s).`;
    }
    if (result.delivery === 'queued_remote') {
      return 'The encrypted privacy-reduced report is queued and will retry when the configured shared service is reachable.';
    }
    if (result.delivery === 'embedded_local') {
      return `Local test-network status: ${result.status}; ${result.independentReporters} local reporter proof(s). Other installations are not protected until a central community service is configured.`;
    }
    return 'The server did not identify whether this report reached a shared or local-only community service.';
  }

  document.addEventListener('click', async (event) => {
    const button = event.target instanceof Element
      ? event.target.closest('[data-action="mark-safe"],[data-action="trust-sender"],[data-action="move-spam"],[data-action="report-scam"]')
      : null;
    if (!(button instanceof HTMLButtonElement) || button.disabled) return;

    event.preventDefault();
    event.stopImmediatePropagation();

    const accountId = selectedAccountId();
    const token = button.dataset.reviewToken;
    const actionName = button.dataset.action;
    const container = containerFor(button);
    const { subject, sender } = messageLabel(container);
    const status = statusFor(container);

    if (!accountId || !token) {
      setGlobalStatus('Message action failed: the selected account or action token is missing.', 'error');
      return;
    }

    const isMarkSafe = actionName === 'mark-safe';
    const isMoveSpam = actionName === 'move-spam';
    const isReportScam = actionName === 'report-scam';
    let blockSender = false;
    let promptTitle;
    let explanation;

    if (isReportScam) {
      promptTitle = 'Report this scam campaign to Email Shield';
      explanation = 'Email Shield will protect matching campaign messages in this mailbox immediately. If a shared community service is configured, only privacy-reduced indicators are submitted to it; otherwise the report remains in the local test network. It will not upload the message body, subject, mailbox address, contacts, credentials, provider ID, or raw private URLs. One report cannot globally block a sender; independent reports and evidence thresholds are required.';
    } else if (isMoveSpam) {
      promptTitle = 'Move exactly this message to provider Spam/Junk';
      explanation = 'This affects only the selected mailbox message. It does not create Email Shield community protection and does not automatically block the sender.';
    } else if (isMarkSafe) {
      promptTitle = 'Mark this exact message Safe';
      explanation = 'Only this exact message will be approved for this connected account. The sender and domain will not be trusted.';
    } else {
      promptTitle = 'Trust this exact sender';
      explanation = 'Future messages from this exact sender address in this connected account will receive personal trust. Structural checks and confirmed signed threats still run.';
    }

    const confirmed = window.confirm(`${promptTitle}?\n\n${subject}\n${sender}\n\n${explanation}`);
    if (!confirmed) return;
    if (isReportScam && button.dataset.sender) {
      blockSender = window.confirm('Also block this exact sender address for your mailbox?\n\nChoose Cancel when the sender is a shared delivery platform such as a reporting or newsletter service. The campaign itself will still be protected locally.');
    }

    const previousText = button.textContent;
    button.disabled = true;
    button.textContent = isReportScam ? 'Saving protection…' : isMoveSpam ? 'Moving…' : isMarkSafe ? 'Saving…' : 'Trusting…';
    if (status) {
      status.className = 'review-action-status';
      status.textContent = isReportScam
        ? 'Saving local campaign protection and submitting or queuing privacy-reduced evidence when a shared service is configured…'
        : isMoveSpam
          ? 'Requesting an exact provider Spam/Junk move…'
          : isMarkSafe
            ? 'Saving an account-scoped exact-message exception…'
            : 'Saving an account-scoped trusted sender…';
    }

    try {
      const endpoint = isReportScam ? 'report-scam' : isMoveSpam ? 'report-spam' : isMarkSafe ? 'mark-safe' : 'trust-sender';
      const response = await fetch(`/api/accounts/${encodeURIComponent(accountId)}/messages/${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(isReportScam ? { token, blockSender } : { token }),
      });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(result.error || `Server returned HTTP ${response.status}`);

      if (isReportScam) {
        if (result.success !== true || result.localProtected !== true || result.accepted !== true || result.accountId !== accountId || result.token !== token) {
          throw new Error('The server did not confirm local protection and community report acceptance.');
        }
        if (!['embedded_local', 'remote_shared', 'queued_remote'].includes(result.delivery)) {
          throw new Error('The server did not return a trustworthy community delivery scope.');
        }
        document.querySelectorAll(`[data-action="report-scam"][data-review-token="${CSS.escape(token)}"]`).forEach((candidate) => {
          candidate.disabled = true;
          candidate.textContent = 'Campaign protected locally ✓';
        });
        disableConflictingDecisions(token);
        container?.classList.add('community-reported');
        const communityState = communityDeliveryMessage(result);
        if (status) {
          status.className = 'review-action-status success';
          status.textContent = `Matching campaign messages are now protected locally. ${communityState}${result.senderBlocked ? ' The exact sender was also blocked for this mailbox.' : ''}`;
        }
        const globalMessage = result.delivery === 'remote_shared'
          ? 'Scam campaign protected locally and accepted by the configured shared community service.'
          : result.delivery === 'queued_remote'
            ? 'Scam campaign protected locally; the shared report is encrypted and queued for retry.'
            : 'Scam campaign protected locally. This installation is using the local test network, not a cross-user service.';
        setGlobalStatus(globalMessage, 'complete');
        return;
      }

      if (isMoveSpam) {
        if (
          result.success !== true || result.accountId !== accountId || result.token !== token ||
          result.requested !== 1 || result.reported !== 1 ||
          !['provider_spam_label', 'junk_folder_move', 'fixture_junk_move'].includes(result.mode)
        ) throw new Error('The provider did not confirm exactly one Spam/Junk move.');
        document.querySelectorAll(`[data-action="move-spam"][data-review-token="${CSS.escape(token)}"]`).forEach((candidate) => {
          candidate.disabled = true;
          candidate.textContent = 'Moved to Spam/Junk ✓';
        });
        container?.classList.add('spam-moved');
        if (status) {
          status.className = 'review-action-status success';
          status.textContent = 'The provider confirmed that exactly one message was placed in Spam/Junk. This did not submit community intelligence.';
        }
        setGlobalStatus('Exactly one message was moved to provider Spam/Junk.', 'complete');
        return;
      }

      if (result.accountId !== accountId || (isMarkSafe ? result.markedSafe !== true : result.trusted !== true)) {
        throw new Error('The server did not confirm the expected review action.');
      }

      if (isMarkSafe) {
        button.textContent = 'Message marked Safe ✓';
        container?.classList.add('review-approved');
        document.querySelectorAll(`[data-action="mark-safe"][data-review-token="${CSS.escape(token)}"]`).forEach((candidate) => {
          candidate.disabled = true;
          candidate.textContent = 'Message marked Safe ✓';
        });
        if (status) {
          status.className = 'review-action-status success';
          status.textContent = 'Exact-message approval saved. Rescan to recalculate the authoritative verdict and counters.';
        }
        setGlobalStatus('Exact message marked Safe for this account. Rescan to verify.', 'complete');
      } else {
        const trustedSender = String(result.value || button.dataset.sender || '').toLowerCase();
        document.querySelectorAll('[data-action="trust-sender"]').forEach((candidate) => {
          if (String(candidate.dataset.sender || '').toLowerCase() === trustedSender) {
            candidate.disabled = true;
            candidate.textContent = 'Sender trusted ✓';
          }
        });
        button.textContent = 'Sender trusted ✓';
        if (status) {
          status.className = 'review-action-status success';
          status.textContent = 'Trusted sender saved for this account. Rescan to apply it to matching messages.';
        }
        setGlobalStatus('Sender trusted for the selected account. Rescan to verify.', 'complete');
      }
    } catch (error) {
      button.disabled = false;
      button.textContent = previousText || (isReportScam ? 'Report Scam to Email Shield' : isMoveSpam ? 'Move to Spam/Junk' : isMarkSafe ? 'Mark this message Safe' : 'Trust sender');
      const message = error instanceof Error ? error.message : String(error);
      if (status) {
        status.className = 'review-action-status error';
        status.textContent = `Message action failed: ${message}`;
      }
      setGlobalStatus(`Message action failed: ${message}`, 'error');
    }
  }, true);
})();
