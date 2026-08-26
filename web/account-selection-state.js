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

  function publishSelectionPersistenceFailure(snapshot, message) {
    window.dispatchEvent(new CustomEvent('email-shield-account-selection-persistence-failed', {
      detail: Object.freeze({
        accountId: snapshot?.id ?? null,
        generation: snapshot?.generation ?? generation,
        message,
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

  async function persistSelection(snapshot, attempt) {
    if (!snapshot?.id || !matches(snapshot) || attempt !== settleAttempt) return false;
    try {
      const response = await fetch('/api/accounts/workspace', {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ accountId: snapshot.id }),
      });
      const workspace = await response.json().catch(() => ({}));
      if (!response.ok || workspace?.selectedAccountId !== snapshot.id) {
        const message = workspace?.error || `Workspace selection returned HTTP ${response.status}.`;
        if (matches(snapshot) && attempt === settleAttempt) publishSelectionPersistenceFailure(snapshot, message);
        return false;
      }
      if (!matches(snapshot) || attempt !== settleAttempt) return false;
      publishSelectionSettled(snapshot);
      return true;
    } catch (error) {
      if (matches(snapshot) && attempt === settleAttempt) {
        publishSelectionPersistenceFailure(
          snapshot,
          error instanceof Error ? error.message : String(error),
        );
      }
      return false;
    }
  }

  function settleWhenPersisted(snapshot = capture()) {
    const attempt = ++settleAttempt;
    return persistSelection(snapshot, attempt);
  }

  // Account-selection-state owns the persistence transaction. The legacy shell
  // still owns visual account-list construction, but its fire-and-forget
  // workspace write is explicitly suppressed here. A generation becomes
  // settled only when this exact protected POST confirms the same account. This
  // avoids polling one process-global workspace value that another legitimate
  // browser tab may change immediately afterward.
  window.selectAccount = function emailShieldSelectAccountState(id, options = {}) {
    reflectSelection(id);
    const snapshot = capture();
    const result = originalSelect.call(this, id, { ...options, remember: false });
    if (options.remember === false || !snapshot.id) return result;
    void settleWhenPersisted(snapshot);
    return result;
  };

  // refreshAccounts() rebuilds the account-chip DOM after connect/disconnect.
  // Reconcile that list so removing the selected mailbox cannot leave a ghost
  // account ID. Persistence remains owned by the explicit selection transaction
  // above; DOM reconstruction never manufactures a second workspace write.
  new MutationObserver(() => {
    const activeId = accountsList.querySelector('.account-chip.active')?.dataset.id || null;
    if (activeId !== selectedId) reflectSelection(activeId);
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