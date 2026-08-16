(() => {
  const accountsList = document.getElementById('accountsList');
  if (!(accountsList instanceof HTMLElement)) return;

  function wireDisconnectControls() {
    for (const chip of accountsList.querySelectorAll('.account-chip[data-id]')) {
      if (!(chip instanceof HTMLElement) || chip.querySelector('[data-disconnect]')) continue;
      const accountId = chip.dataset.id;
      if (!accountId) continue;

      const controls = chip.querySelector('button[data-select]')?.parentElement === chip
        ? chip
        : null;
      if (!controls) continue;

      const button = document.createElement('button');
      button.type = 'button';
      button.dataset.disconnect = accountId;
      button.textContent = 'Disconnect';
      button.title = 'Remove this account from Email Shield';
      window.emailShieldRuntimeTrace?.registerControl(button, 'account.disconnect', 'account.disconnect', 'account_disconnect');
      button.addEventListener('click', async () => {
        if (!window.confirm('Disconnect this account from Email Shield? OAuth providers may also have their Email Shield authorization revoked.')) return;
        button.disabled = true;
        const original = button.textContent;
        button.textContent = 'Disconnecting…';
        try {
          const response = await fetch(`/api/accounts/${encodeURIComponent(accountId)}`, { method: 'DELETE' });
          if (!response.ok) {
            const body = await response.json().catch(() => ({}));
            throw new Error(body.error || 'Account disconnect was not confirmed.');
          }
          window.emailShieldRuntimeTrace?.checkpoint('account.disconnect.ui_confirmed');
          // Reload the protected local dashboard so no stale scan/action token or
          // selected-account state survives a successful credential teardown.
          window.location.reload();
        } catch (error) {
          window.emailShieldRuntimeTrace?.checkpoint('account.disconnect.ui_confirmed', 'failed', { errorCode: 'disconnect_failed' });
          button.disabled = false;
          button.textContent = original;
          window.alert(error instanceof Error ? error.message : String(error));
        }
      });
      controls.append(button);
    }
  }

  const observer = new MutationObserver(wireDisconnectControls);
  observer.observe(accountsList, { childList: true, subtree: true });
  wireDisconnectControls();
})();
