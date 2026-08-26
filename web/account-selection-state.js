(() => {
  const installedModules = window.emailShieldInstalledModules ||= new Set();
  if (installedModules.has('account-selection-state')) return;
  installedModules.add('account-selection-state');

  const originalSelect = window.selectAccount;
  if (typeof originalSelect !== 'function') {
    throw new Error('Email Shield account selection owner is unavailable.');
  }

  const accountsList = document.getElementById('accountsList');
  if (!accountsList) {
    throw new Error('Email Shield connected-account list is unavailable.');
  }

  const SETTLE_RETRY_MS = 50;
  const SETTLE_TIMEOUT_MS = 5_000;
  let selectedId = accountsList.querySelector('.account-chip.active')?.dataset.id || null;
  let generation = 0;
  let settleAttempt = 0;

  function publishSelectionChange(previousId, accountId) {
    window.dispatchEvent(new CustomEvent('email-shield-account-selection-changed', {
      detail: Object.freeze({
        previousAccountId: previousId,
        accountId,
        generation,
      }),
    }));
  }

  function publishSelectionSettled(snapshot) {
    window.dispatchEvent(new CustomEvent('email-shield-account-selection-settled', {
      detail: Object.freeze({
        accountId: snapshot.id,
        generation: snapshot.generation,
      }),
    }));
  }

  function reflectSelection(id) {
    const normalized = typeof id === 'string' && id.trim() ? id : null;
    const previousId = selectedId;
    const changed = normalized !== selectedId;
    if (changed) generation += 1;
    selectedId = normalized;

    accountsList.querySelectorAll('.account-chip[data-id]').forEach((row) => {
      const active = normalized !== null && row.dataset.id === normalized;
      row.classList.toggle('active', active);
      const button = row.querySelector('button[data-select]');
      if (button instanceof HTMLButtonElement) {
        button.setAttribute('aria-pressed', String(active));
        if (active) button.setAttribute('aria-current', 'true');
        else button.removeAttribute('aria-current');
      }
    });

    if (changed) publishSelectionChange(previousId, normalized);
    return changed;
  }

  function capture() {
    return Object.freeze({ id: selectedId, generation });
  }

  function matches(snapshot) {
    return Boolean(
      snapshot
      && snapshot.id === selectedId
      && snapshot.generation === generation
    );
  }

  async function waitForPersistedSelection(snapshot, attempt) {
    if (!snapshot?.id || !matches(snapshot) || attempt !== settleAttempt) return;
    const deadline = Date.now() + SETTLE_TIMEOUT_MS;
    while (Date.now() < deadline) {
      if (!matches(snapshot) || attempt !== settleAttempt) return;
      try {
        const response = await fetch('/api/accounts/workspace', {
          headers: { Accept: 'application/json' },
          cache: 'no-store',
        });
        const workspace = await response.json().catch(() => ({}));
        if (
          response.ok
          && workspace?.selectedAccountId === snapshot.id
          && matches(snapshot)
          && attempt === settleAttempt
        ) {
          publishSelectionSettled(snapshot);
          return;
        }
      } catch {
        // The local workspace write may still be in flight. Keep the selection
        // unsettled rather than publishing a false account ownership boundary.
      }
      await new Promise((resolve) => setTimeout(resolve, SETTLE_RETRY_MS));
    }
  }

  function settleWhenPersisted(snapshot = capture()) {
    const attempt = ++settleAttempt;
    void waitForPersistedSelection(snapshot, attempt);
  }

  // The legacy shell still owns account list construction/persistence. This
  // wrapper establishes one synchronous selection boundary before those async
  // effects run. The legacy bootstrap also has lexical selection call sites
  // that cannot be wrapped here, so the MutationObserver below reconciles those
  // paths. A selection is considered settled only after the protected server
  // workspace confirms the same account; this prevents a fast workspace read
  // from racing ahead of the fire-and-forget persistence write.
  window.selectAccount = function emailShieldSelectAccountState(id, options = {}) {
    reflectSelection(id);
    const snapshot = capture();
    const result = originalSelect.call(this, id, options);
    Promise.resolve(result).then(() => {
      if (matches(snapshot)) settleWhenPersisted(snapshot);
    }).catch(() => undefined);
    return result;
  };

  // refreshAccounts() rebuilds the account-chip DOM after connect/disconnect
  // and after lexical legacy selectAccount() calls. Reconcile that authoritative
  // list so removing the selected mailbox cannot leave a ghost account ID, and
  // establish the same persisted-settlement boundary for paths that bypass the
  // window.selectAccount wrapper.
  new MutationObserver(() => {
    const activeId = accountsList.querySelector('.account-chip.active')?.dataset.id || null;
    if (activeId !== selectedId) {
      reflectSelection(activeId);
      if (activeId) settleWhenPersisted(capture());
    }
  }).observe(accountsList, { childList: true, subtree: true });

  Object.defineProperty(window, 'emailShieldAccountSelection', {
    value: Object.freeze({
      currentId: () => selectedId,
      generation: () => generation,
      capture,
      matches,
      reflect: (id) => reflectSelection(id),
    }),
    writable: false,
    configurable: false,
  });
})();