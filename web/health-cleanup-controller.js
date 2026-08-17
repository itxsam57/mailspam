(() => {
  const installedModules = window.emailShieldInstalledModules ||= new Set();
  if (installedModules.has('health-cleanup-controller')) return;
  installedModules.add('health-cleanup-controller');

  const state = {
    accountId: null,
    subscriptions: [],
    cleanupGroups: new Map(),
  };

  function selectedAccountId() {
    const selected = window.emailShieldAccountSelection?.currentId?.();
    return typeof selected === 'string' && selected ? selected : null;
  }

  function setHealthStatus(message, error = false) {
    const status = document.getElementById('consumerHealthStatus');
    if (!status) return;
    if (status.textContent !== message) status.textContent = message;
    status.style.color = error ? 'var(--confirmed)' : '';
  }

  function healthAccountIdFromUrl(input) {
    try {
      const raw = typeof input === 'string' ? input : input?.url;
      if (!raw) return null;
      const url = new URL(raw, location.href);
      const match = url.pathname.match(/^\/api\/consumer\/v1\/accounts\/([^/]+)\/health$/);
      return match ? decodeURIComponent(match[1]) : null;
    } catch {
      return null;
    }
  }

  function cleanupMap(result) {
    const inbox = result?.inboxHealth;
    const subscriptions = Array.isArray(inbox?.subscriptions) ? inbox.subscriptions.slice(0, 20) : [];
    const groups = Array.isArray(inbox?.cleanupGroups) ? inbox.cleanupGroups : [];
    return {
      subscriptions,
      cleanupGroups: new Map(groups
        .filter((group) => group && typeof group.key === 'string')
        .map((group) => [group.key, group])),
    };
  }

  function reconcileRows() {
    if (!state.accountId || selectedAccountId() !== state.accountId) return;
    const rows = [...document.querySelectorAll('#consumerSubscriptions .consumer-list-item')];
    rows.forEach((row, index) => {
      const item = state.subscriptions[index];
      if (!item || typeof item.key !== 'string') return;
      const group = state.cleanupGroups.get(item.key);
      const oldCount = Number(group?.messagesOlderThan30Days || 0);
      const controls = row.lastElementChild;
      const legacyButton = controls?.querySelector('button');
      const info = row.firstElementChild;
      let eligibility = info?.querySelector('.health-cleanup-eligibility');
      if (!eligibility && info) {
        eligibility = document.createElement('div');
        eligibility.className = 'hint health-cleanup-eligibility';
        info.appendChild(eligibility);
      }
      const eligibilityText = `${oldCount} message(s) older than 30 days`;
      if (eligibility && eligibility.textContent !== eligibilityText) eligibility.textContent = eligibilityText;

      if (!group || oldCount <= 0) {
        legacyButton?.remove();
        if (controls && !controls.querySelector('.health-cleanup-none')) {
          const none = document.createElement('span');
          none.className = 'hint health-cleanup-none';
          none.textContent = 'No old mail to clean';
          controls.appendChild(none);
        }
        return;
      }

      controls?.querySelector('.health-cleanup-none')?.remove();
      if (legacyButton instanceof HTMLButtonElement) {
        legacyButton.dataset.healthCleanupKey = item.key;
        legacyButton.dataset.healthCleanupCount = String(oldCount);
        if (legacyButton.textContent !== 'Clean old mail') legacyButton.textContent = 'Clean old mail';
      }
    });
  }

  const originalFetch = window.fetch.bind(window);
  window.fetch = async (...args) => {
    const response = await originalFetch(...args);
    const accountId = healthAccountIdFromUrl(args[0]);
    const method = String(args[1]?.method || 'GET').toUpperCase();
    if (accountId && method === 'POST' && response.ok) {
      const clone = response.clone();
      void clone.json().then((result) => {
        if (selectedAccountId() !== accountId) return;
        const mapped = cleanupMap(result);
        state.accountId = accountId;
        state.subscriptions = mapped.subscriptions;
        state.cleanupGroups = mapped.cleanupGroups;
        queueMicrotask(reconcileRows);
      }).catch(() => undefined);
    }
    return response;
  };

  const observer = new MutationObserver(() => reconcileRows());
  const subscriptionRoot = document.getElementById('consumerSubscriptions');
  if (subscriptionRoot) observer.observe(subscriptionRoot, { childList: true, subtree: true });

  document.addEventListener('click', async (event) => {
    const button = event.target instanceof Element
      ? event.target.closest('#consumerSubscriptions button[data-health-cleanup-key]')
      : null;
    if (!(button instanceof HTMLButtonElement) || button.disabled) return;

    // This controller is the sole destructive Health-cleanup owner. Stop the
    // legacy row listener before it can submit its stale total-subscription
    // selector or preserve the only age-eligible message.
    event.preventDefault();
    event.stopImmediatePropagation();

    const accountId = selectedAccountId();
    const key = button.dataset.healthCleanupKey || '';
    const group = state.cleanupGroups.get(key);
    const oldCount = Number(group?.messagesOlderThan30Days || 0);
    if (!accountId || accountId !== state.accountId || !group || oldCount <= 0) {
      setHealthStatus('Health cleanup eligibility changed. Run Health again before moving mail.', true);
      return;
    }

    const label = button.closest('.consumer-list-item')?.querySelector('strong')?.textContent?.trim() || 'this sender';
    if (!window.confirm(`Move ${oldCount} matching message(s) older than 30 days from ${label} to Trash?`)) return;
    const confirmation = window.prompt('Type MOVE TO TRASH to confirm');
    if (confirmation !== 'MOVE TO TRASH' || selectedAccountId() !== accountId) return;

    button.disabled = true;
    button.textContent = 'Cleaning…';
    try {
      const response = await originalFetch(`/api/consumer/v1/accounts/${encodeURIComponent(accountId)}/cleanup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          senderAddress: group.senderAddress,
          senderDomain: group.senderDomain,
          olderThanDays: 30,
          keepNewest: false,
          confirmation,
        }),
      });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(result.error || `Cleanup failed (${response.status}).`);
      if (selectedAccountId() !== accountId) return;
      setHealthStatus(result.movedToTrash > 0
        ? `${result.movedToTrash} message(s) moved to Trash. Refreshing Health…`
        : 'No matching mail older than 30 days remained. Refreshing Health…');
      document.getElementById('consumerRunHealth')?.click();
      document.getElementById('consumerRefreshActivity')?.click();
    } catch (error) {
      if (selectedAccountId() !== accountId) return;
      button.disabled = false;
      button.textContent = 'Clean old mail';
      setHealthStatus(error instanceof Error ? error.message : String(error), true);
    }
  }, true);
})();
