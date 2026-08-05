(() => {
  const safeAuditScript = document.createElement('script');
  safeAuditScript.src = '/safe-audit.js';
  safeAuditScript.async = false;
  document.head.appendChild(safeAuditScript);

  const originalRenderCard = window.renderCard;
  if (typeof originalRenderCard !== 'function') return;

  const style = document.createElement('style');
  style.textContent = `
    .unsubscribe-action-status {display:block;margin-top:7px;font-size:11px;color:#8b93a3}
    .unsubscribe-action-status.success {color:#3fb88a}
    .unsubscribe-action-status.error {color:#ff9a9f}
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

  function labelFor(action) {
    if (action.alreadyUnsubscribed && action.method === 'one_click_post') return 'Unsubscribed ✓';
    if (action.method === 'link_only') return 'Open unsubscribe page';
    if (action.method === 'mailto') return 'Email unsubscribe request';
    return 'Unsubscribe';
  }

  window.renderCard = function renderCardWithUnsubscribe(result) {
    const html = originalRenderCard(result);
    const action = result?.unsubscribeAction;
    if (!action?.available || !action.token || !action.actionKey || !['one_click_post', 'link_only', 'mailto'].includes(action.method)) {
      return html;
    }

    const template = document.createElement('template');
    template.innerHTML = String(html).trim();
    const card = template.content.firstElementChild;
    const actions = card?.querySelector('.card-actions');
    if (!card || !actions) return html;

    const button = document.createElement('button');
    button.dataset.action = 'unsubscribe';
    button.dataset.unsubscribeToken = action.token;
    button.dataset.unsubscribeKey = action.actionKey;
    button.dataset.unsubscribeMethod = action.method;
    button.textContent = labelFor(action);
    button.disabled = Boolean(action.alreadyUnsubscribed && action.method === 'one_click_post');
    actions.appendChild(button);
    return card.outerHTML;
  };

  const reviewScript = document.createElement('script');
  reviewScript.src = '/review-actions.js';
  reviewScript.async = false;
  document.head.appendChild(reviewScript);

  function actionContainer(button) {
    return button.closest('.card') || button.closest('[data-message-row="true"]');
  }

  function actionStatusFor(container) {
    if (!container) return null;
    let actionStatus = container.querySelector('.unsubscribe-action-status');
    if (actionStatus) return actionStatus;
    const existingStatus = container.querySelector('[data-action-status]');
    if (existingStatus) {
      existingStatus.classList.add('unsubscribe-action-status');
      return existingStatus;
    }
    actionStatus = document.createElement('span');
    actionStatus.className = 'unsubscribe-action-status';
    actionStatus.setAttribute('role', 'status');
    if (container.matches('tr')) container.lastElementChild?.appendChild(actionStatus);
    else container.appendChild(actionStatus);
    return actionStatus;
  }

  document.addEventListener('click', async (event) => {
    const button = event.target instanceof Element
      ? event.target.closest('[data-action="unsubscribe"]')
      : null;
    if (!(button instanceof HTMLButtonElement) || button.disabled) return;

    event.preventDefault();
    event.stopImmediatePropagation();

    const accountId = selectedAccountId();
    const token = button.dataset.unsubscribeToken;
    const actionKey = button.dataset.unsubscribeKey;
    const method = button.dataset.unsubscribeMethod;
    const container = actionContainer(button);
    const subject = container?.querySelector('.card-subject,.safe-subject,.diag-subject')?.textContent?.trim() || '(no subject)';
    const sender = container?.querySelector('.card-from,.safe-sender,.diag-sender')?.textContent?.trim() || 'unknown sender';

    if (!accountId || !token || !actionKey || !method) {
      setGlobalStatus('Unsubscribe failed: the selected account or action token is missing.', 'error');
      return;
    }

    const explanation = method === 'one_click_post'
      ? 'Email Shield will send the message-authorized RFC 8058 request without opening the destination.'
      : method === 'link_only'
        ? 'The service unsubscribe page will open in a new browser tab. Complete any confirmation shown there.'
        : 'Your default email application will open a pre-addressed unsubscribe request. You must send it.';
    const confirmed = window.confirm(
      `Continue with this unsubscribe option?\n\n${subject}\n${sender}\n\n${explanation}`,
    );
    if (!confirmed) return;

    const pendingWindow = method === 'link_only'
      ? window.open('about:blank', '_blank', 'noopener,noreferrer')
      : null;
    const previousText = button.textContent;
    button.disabled = true;
    button.textContent = method === 'one_click_post' ? 'Unsubscribing…' : 'Preparing…';

    const actionStatus = actionStatusFor(container);
    if (actionStatus) {
      actionStatus.className = 'unsubscribe-action-status';
      actionStatus.textContent = method === 'one_click_post'
        ? 'Sending the bounded one-click request…'
        : 'Resolving the message-authorized unsubscribe action…';
    }

    try {
      const response = await fetch(`/api/accounts/${encodeURIComponent(accountId)}/messages/unsubscribe`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token }),
      });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(result.error || `Server returned HTTP ${response.status}`);
      if (result.success !== true || result.accountId !== accountId || result.actionKey !== actionKey) {
        throw new Error('The server did not confirm the expected unsubscribe action.');
      }

      if (result.manualAction === true) {
        if (result.method !== method || typeof result.target !== 'string') {
          throw new Error('The server returned an unexpected manual unsubscribe action.');
        }
        if (method === 'link_only') {
          if (pendingWindow && !pendingWindow.closed) pendingWindow.location.replace(result.target);
          else window.open(result.target, '_blank', 'noopener,noreferrer');
          button.textContent = 'Open unsubscribe page again';
          if (actionStatus) {
            actionStatus.className = 'unsubscribe-action-status success';
            actionStatus.textContent = 'The service unsubscribe page was opened. Complete any confirmation on that page.';
          }
        } else {
          const anchor = document.createElement('a');
          anchor.href = result.target;
          anchor.style.display = 'none';
          document.body.appendChild(anchor);
          anchor.click();
          anchor.remove();
          button.textContent = 'Open email request again';
          if (actionStatus) {
            actionStatus.className = 'unsubscribe-action-status success';
            actionStatus.textContent = 'A pre-addressed unsubscribe email was opened. Send it to complete the request.';
          }
        }
        button.disabled = false;
        setGlobalStatus('The available unsubscribe option was opened.', 'complete');
        return;
      }

      document.querySelectorAll('[data-action="unsubscribe"]').forEach((candidate) => {
        if (candidate.dataset.unsubscribeKey === actionKey) {
          candidate.disabled = true;
          candidate.textContent = 'Unsubscribed ✓';
        }
      });

      if (actionStatus) {
        actionStatus.className = 'unsubscribe-action-status success';
        actionStatus.textContent = result.alreadyUnsubscribed
          ? 'This campaign was already recorded as unsubscribed for the selected account.'
          : `The endpoint confirmed one-click unsubscribe${result.status ? ` with HTTP ${result.status}` : ''}, and the encrypted local status was saved.`;
      }
      setGlobalStatus('One-click unsubscribe was confirmed and saved. Matching duplicate buttons were synchronized.', 'complete');
    } catch (error) {
      if (pendingWindow && !pendingWindow.closed) pendingWindow.close();
      button.disabled = false;
      button.textContent = previousText || 'Unsubscribe';
      const message = error instanceof Error ? error.message : String(error);
      if (actionStatus) {
        actionStatus.className = 'unsubscribe-action-status error';
        actionStatus.textContent = `Unsubscribe failed: ${message}`;
      }
      setGlobalStatus(`Unsubscribe failed: ${message}`, 'error');
    }
  }, true);
})();
