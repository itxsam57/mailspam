(() => {
  const installedModules = window.emailShieldInstalledModules ||= new Set();
  if (installedModules.has('account-selection-state')) return;
  installedModules.add('account-selection-state');

  const originalSelect = window.selectAccount;
  if (typeof originalSelect !== 'function') {
    throw new Error('Email Shield account selection owner is unavailable.');
  }

  let selectedId = document.querySelector('#accountsList .account-chip.active')?.dataset.id || null;

  function reflectSelection(id) {
    const normalized = typeof id === 'string' && id.trim() ? id : null;
    selectedId = normalized;
    const list = document.getElementById('accountsList');
    if (!list) return;

    list.querySelectorAll('.account-chip[data-id]').forEach((row) => {
      const active = normalized !== null && row.dataset.id === normalized;
      row.classList.toggle('active', active);
      const button = row.querySelector('button[data-select]');
      if (button instanceof HTMLButtonElement) {
        button.setAttribute('aria-pressed', String(active));
        if (active) button.setAttribute('aria-current', 'true');
        else button.removeAttribute('aria-current');
      }
    });
  }

  // The legacy shell still owns account list construction/persistence. This
  // wrapper establishes one synchronous selection boundary before those async
  // effects run, so scan/action modules never have to infer selection from a
  // DOM refresh that may still be in flight.
  window.selectAccount = function emailShieldSelectAccountState(id, options = {}) {
    reflectSelection(id);
    return originalSelect.call(this, id, options);
  };

  Object.defineProperty(window, 'emailShieldAccountSelection', {
    value: Object.freeze({
      currentId: () => selectedId,
      reflect: (id) => reflectSelection(id),
    }),
    writable: false,
    configurable: false,
  });
})();
