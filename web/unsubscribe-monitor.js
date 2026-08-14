(() => {
  const installedModules = window.emailShieldInstalledModules ||= new Set();
  if (installedModules.has('unsubscribe-monitor')) return;
  installedModules.add('unsubscribe-monitor');

  const originalRenderCard = window.renderCard;
  if (typeof originalRenderCard !== 'function') return;

  const style = document.createElement('style');
  style.textContent = `
    .unsubscribe-action-status {display:block;margin-top:7px;font-size:11px;color:var(--text-muted)}
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

  function refreshConsumerActivity() {
    document.getElementById('consumerRefreshActivity')?.click();
  }

  function refreshPersonalPolicy() {
    window.dispatchEvent(new CustomEvent('email-shield-policy-changed'));
    document.getElementById('policyRefresh')?.click();
  }

  async function recordManualActivity(accountId, token, actionKey, method) {
    const response = await fetch(`/api/consumer/v1/accounts/${encodeURIComponent(accountId)}/unsubscribe-activity`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token }),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || `Activity returned HTTP ${response.status}`);
    if (body.recorded !== true || body.accountId !== accountId || body.actionKey !== actionKey || body.method !== method || body.completionVerified !== false) {
      throw new Error('Email Shield could not verify the manual unsubscribe activity record.');
    }
    refreshConsumerActivity();
  }

  function labelFor(action) {
    if (action.alreadyUnsubscribed && action.method === 'one_click_post') return 'Unsubscribed ✓';
    if (action.method === 'link_only') return 'Open unsubscribe page (not confirmed)';
    if (action.method === 'mailto') return 'Open unsubscribe email (not confirmed)';
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
      ? 'Email Shield will send the message-authorized RFC 8058 request without opening the destination. A successful endpoint response can be recorded as confirmed.'
      : method === 'link_only'
        ? 'The service unsubscribe page will open in a new browser tab. Email Shield can record only that the page opened; completion remains unconfirmed until the external service provides a verifiable result.'
        : 'Your default email application will open a pre-addressed unsubscribe request. Email Shield can record only that the request opened; you must send it and completion remains unconfirmed.';
    const confirmed = window.confirm(
      `Continue with this unsubscribe option?\n\n${subject}\n${sender}\n\n${explanation}`,
    );
    if (!confirmed) return;

    const pendingWindow = method === 'link_only'
      ? window.open('about:blank', '_blank')
      : null;
    if (pendingWindow) {
      try {
        pendingWindow.opener = null;
        const referrerPolicy = pendingWindow.document.createElement('meta');
        referrerPolicy.name = 'referrer';
        referrerPolicy.content = 'no-referrer';
        pendingWindow.document.head?.appendChild(referrerPolicy);
      } catch {}
    }
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
          if (!pendingWindow || pendingWindow.closed) {
            throw new Error('The browser blocked the unsubscribe tab. Allow pop-ups for Email Shield and try again.');
          }
          pendingWindow.location.replace(result.target);
          button.textContent = 'Open unsubscribe page again (not confirmed)';
          if (actionStatus) {
            actionStatus.className = 'unsubscribe-action-status success';
            actionStatus.textContent = 'The service unsubscribe page was opened and can be recorded in Activity. Completion is still unconfirmed.';
          }
        } else {
          const anchor = document.createElement('a');
          anchor.href = result.target;
          anchor.style.display = 'none';
          document.body.appendChild(anchor);
          anchor.click();
          anchor.remove();
          button.textContent = 'Open unsubscribe email again (not confirmed)';
          if (actionStatus) {
            actionStatus.className = 'unsubscribe-action-status success';
            actionStatus.textContent = 'A pre-addressed unsubscribe email was opened. Completion is still unconfirmed until you send it and the external service processes it.';
          }
        }
        button.disabled = false;
        try {
          await recordManualActivity(accountId, token, actionKey, method);
          setGlobalStatus('Manual unsubscribe handoff recorded in Activity. It is intentionally not counted as a Confirmed unsubscribe.', 'complete');
        } catch (activityError) {
          const detail = activityError instanceof Error ? activityError.message : String(activityError);
          setGlobalStatus(`The unsubscribe option opened, but Activity could not be saved: ${detail}`, 'error');
        }
        return;
      }

      document.querySelectorAll('[data-action="unsubscribe"]').forEach((candidate) => {
        if (candidate.dataset.unsubscribeKey === actionKey) {
          candidate.disabled = true;
          candidate.textContent = 'Unsubscribed ✓';
        }
      });

      refreshConsumerActivity();
      refreshPersonalPolicy();
      if (actionStatus) {
        actionStatus.className = 'unsubscribe-action-status success';
        actionStatus.textContent = result.alreadyUnsubscribed
          ? 'This campaign was already recorded as a confirmed unsubscribe for the selected account.'
          : `The endpoint confirmed one-click unsubscribe${result.status ? ` with HTTP ${result.status}` : ''}, and the encrypted local confirmed status was saved.`;
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