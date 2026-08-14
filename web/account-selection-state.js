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

  function publishSelectionChange(previousId, accountId) {
    window.dispatchEvent(new CustomEvent('email-shield-account-selection-changed', {
      detail: Object.freeze({
        previousAccountId: previousId,
        accountId,
        generation,
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

  // The legacy shell still owns account list construction/persistence. This
  // wrapper establishes one synchronous selection boundary before those async
  // effects run, so scan/action modules never have to infer selection from a
  // DOM refresh that may still be in flight. A monotonically increasing
  // generation also rejects A -> B -> A stale async responses that an ID-only
  // comparison would incorrectly accept.
  window.selectAccount = function emailShieldSelectAccountState(id, options = {}) {
    reflectSelection(id);
    return originalSelect.call(this, id, options);
  };

  // refreshAccounts() rebuilds the account-chip DOM after connect/disconnect.
  // Reconcile that authoritative list after each rebuild so removing the
  // selected mailbox cannot leave a ghost account ID in account-scoped modules.
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