(() => {
  async function restore() {
    const trace = window.emailShieldRuntimeTrace;
    trace?.automaticRoot('system.workspace.restore', 'workspace.restore');
    trace?.checkpoint('workspace.restore.started', 'started', {
      component: 'workspace_restore',
      step: 'restore_started',
    });
    const complete = (outcome = 'success', step = 'restore_completed') => {
      trace?.checkpoint('workspace.restore.completed', outcome, {
        component: 'workspace_restore',
        step,
      });
    };
    const restoreSelectionSnapshot = window.emailShieldAccountSelection?.capture?.() ?? null;
    try {
      const response = await fetch('/api/accounts/workspace', {
        headers: { Accept: 'application/json' },
        cache: 'no-store',
      });
      const workspace = await response.json().catch(() => ({}));
      if (!response.ok || typeof workspace.selectedAccountId !== 'string') {
        complete('success', 'no_persisted_selection');
        return;
      }

      const select = window.emailShieldSelectAccount;
      if (typeof select !== 'function') {
        complete('incomplete', 'selector_unavailable');
        return;
      }
      for (let attempt = 0; attempt < 20; attempt += 1) {
        if (document.querySelector(`.account-chip[data-id="${CSS.escape(workspace.selectedAccountId)}"]`)) break;
        await new Promise((resolve) => requestAnimationFrame(resolve));
      }
      if (!document.querySelector(`.account-chip[data-id="${CSS.escape(workspace.selectedAccountId)}"]`)) {
        complete('incomplete', 'selected_account_not_rendered');
        return;
      }

      // Startup restore is allowed to hydrate the protected selection only while
      // this tab has not made a newer selection decision. A user/tab selection
      // can settle the process-global protected workspace while this restore is
      // still waiting for account-chip rendering. Replaying the older workspace
      // snapshot afterward would split browser-local and protected ownership.
      const currentSelectionSnapshot = window.emailShieldAccountSelection?.capture?.() ?? null;
      if (
        restoreSelectionSnapshot
        && currentSelectionSnapshot
        && currentSelectionSnapshot.generation !== restoreSelectionSnapshot.generation
      ) {
        complete('success', 'newer_tab_selection_preserved');
        return;
      }

      select(workspace.selectedAccountId, { remember: false });
      window.dispatchEvent(new CustomEvent('email-shield-workspace-restored', { detail: workspace }));
      complete('success', 'selection_restored');
    } catch {
      complete('failed', 'restore_failed');
      // Workspace presentation is optional process memory; account use remains available.
    }
  }

  void restore();
})();
