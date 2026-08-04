(() => {
  const originalRenderCard = window.renderCard;
  if (typeof originalRenderCard !== 'function') return;

  const style = document.createElement('style');
  style.textContent = `
    .unsubscribe-action-status {margin-top:9px;font-size:11px;color:#8b93a3}
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

  window.renderCard = function renderCardWithUnsubscribe(result) {
    const html = originalRenderCard(result);
    const action = result?.unsubscribeAction;
    if (!action?.available || action.method !== 'one_click_post' || !action.token || !action.actionKey) {
      return html;
    }

    const template = document.createElement('template');
    template.innerHTML = String(html).trim();
    const card = template.content.firstElementChild;
    const actions = card?.querySelector('.card-actions');
    if (!card || !actions) return html;

    const button = document.createElement('button');
    button.dataset.action = 'unsubscribe-one-click';
    button.dataset.unsubscribeToken = action.token;
    button.dataset.unsubscribeKey = action.actionKey;
    button.textContent = action.alreadyUnsubscribed ? 'Unsubscribed ✓' : 'Unsubscribe';
    button.disabled = Boolean(action.alreadyUnsubscribed);
    actions.appendChild(button);
    return card.outerHTML;
  };

  document.addEventListener('click', async (event) => {
    const button = event.target instanceof Element
      ? event.target.closest('[data-action="unsubscribe-one-click"]')
      : null;
    if (!(button instanceof HTMLButtonElement) || button.disabled) return;

    event.preventDefault();
    event.stopImmediatePropagation();

    const accountId = selectedAccountId();
    const token = button.dataset.unsubscribeToken;
    const actionKey = button.dataset.unsubscribeKey;
    const card = button.closest('.card');
    const subject = card?.querySelector('.card-subject')?.textContent?.trim() || '(no subject)';
    const sender = card?.querySelector('.card-from')?.textContent?.trim() || 'unknown sender';

    if (!accountId || !token || !actionKey) {
      setGlobalStatus('Unsubscribe failed: the selected account or action token is missing.', 'error');
      return;
    }

    const confirmed = window.confirm(
      `Send the message-authorized one-click unsubscribe request?\n\n${subject}\n${sender}\n\nEmail Shield will send the RFC 8058 form POST to the HTTPS destination declared in this message. It will not open the link in your browser.`,
    );
    if (!confirmed) return;

    const previousText = button.textContent;
    button.disabled = true;
    button.textContent = 'Unsubscribing…';

    let actionStatus = card?.querySelector('.unsubscribe-action-status');
    if (!actionStatus && card) {
      actionStatus = document.createElement('div');
      actionStatus.className = 'unsubscribe-action-status';
      actionStatus.setAttribute('role', 'status');
      card.appendChild(actionStatus);
    }
    if (actionStatus) {
      actionStatus.className = 'unsubscribe-action-status';
      actionStatus.textContent = 'Sending a bounded RFC 8058 one-click request…';
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

      document.querySelectorAll('[data-action="unsubscribe-one-click"]').forEach((candidate) => {
        if (candidate.dataset.unsubscribeKey === actionKey) {
          candidate.disabled = true;
          candidate.textContent = 'Unsubscribed ✓';
        }
      });

      if (actionStatus) {
        actionStatus.className = 'unsubscribe-action-status success';
        actionStatus.textContent = result.alreadyUnsubscribed
          ? 'This campaign was already unsubscribed during the current app session.'
          : `The endpoint confirmed one-click unsubscribe${result.status ? ` with HTTP ${result.status}` : ''}.`;
      }
      setGlobalStatus('One-click unsubscribe was confirmed. Matching duplicate buttons were synchronized.', 'complete');
    } catch (error) {
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
