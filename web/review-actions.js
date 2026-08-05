(() => {
  const originalRenderCard = window.renderCard;
  if (typeof originalRenderCard !== 'function') return;

  const style = document.createElement('style');
  style.textContent = `
    .review-action-status {display:block;margin-top:7px;font-size:11px;color:#8b93a3}
    .review-action-status.success {color:#3fb88a}
    .review-action-status.error {color:#ff9a9f}
    .card.review-approved {opacity:.82;border-style:dashed}
    .safe-row-actions {display:flex;gap:6px;flex-wrap:wrap;min-width:210px}
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

  document.addEventListener('click', async (event) => {
    const button = event.target instanceof Element
      ? event.target.closest('[data-action="mark-safe"],[data-action="trust-sender"]')
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
      setGlobalStatus('Review action failed: the selected account or action token is missing.', 'error');
      return;
    }

    const isMarkSafe = actionName === 'mark-safe';
    const explanation = isMarkSafe
      ? 'Only this exact message will be approved for this connected account. The sender and domain will not be trusted.'
      : 'Future messages from this exact sender address in this connected account will receive personal trust. Structural checks and confirmed signed threats still run.';
    const confirmed = window.confirm(
      `${isMarkSafe ? 'Mark this exact message Safe' : 'Trust this exact sender'}?\n\n${subject}\n${sender}\n\n${explanation}`,
    );
    if (!confirmed) return;

    const previousText = button.textContent;
    button.disabled = true;
    button.textContent = isMarkSafe ? 'Saving…' : 'Trusting…';
    if (status) {
      status.className = 'review-action-status';
      status.textContent = isMarkSafe
        ? 'Saving an account-scoped exact-message exception…'
        : 'Saving an account-scoped trusted sender…';
    }

    try {
      const endpoint = isMarkSafe ? 'mark-safe' : 'trust-sender';
      const response = await fetch(`/api/accounts/${encodeURIComponent(accountId)}/messages/${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token }),
      });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(result.error || `Server returned HTTP ${response.status}`);
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
      button.textContent = previousText || (isMarkSafe ? 'Mark this message Safe' : 'Trust sender');
      const message = error instanceof Error ? error.message : String(error);
      if (status) {
        status.className = 'review-action-status error';
        status.textContent = `Review action failed: ${message}`;
      }
      setGlobalStatus(`Review action failed: ${message}`, 'error');
    }
  }, true);
})();
