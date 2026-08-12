(() => {
  async function restore() {
    try {
      const response = await fetch('/api/accounts/workspace', {
        headers: { Accept: 'application/json' },
        cache: 'no-store',
      });
      const workspace = await response.json().catch(() => ({}));
      if (!response.ok || typeof workspace.selectedAccountId !== 'string') return;

      const select = window.emailShieldSelectAccount;
      if (typeof select !== 'function') return;
      for (let attempt = 0; attempt < 20; attempt += 1) {
        if (document.querySelector(`.account-chip[data-id="${CSS.escape(workspace.selectedAccountId)}"]`)) break;
        await new Promise((resolve) => requestAnimationFrame(resolve));
      }
      if (!document.querySelector(`.account-chip[data-id="${CSS.escape(workspace.selectedAccountId)}"]`)) return;
      select(workspace.selectedAccountId, { remember: false });
      window.dispatchEvent(new CustomEvent('email-shield-workspace-restored', { detail: workspace }));
    } catch {
      // Workspace presentation is optional process memory; account use remains available.
    }
  }

  void restore();
})();
