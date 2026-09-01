(() => {
  async function waitForRenderedAccountIds() {
    for (let attempt = 0; attempt < 20; attempt += 1) {
      const accountIds = [...document.querySelectorAll('.account-chip[data-id]')]
        .map((row) => row.dataset.id)
        .filter((id) => typeof id === 'string' && id);
      if (accountIds.length > 0) return accountIds;
      await new Promise((resolve) => requestAnimationFrame(resolve));
    }
    return [];
  }

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
      if (!response.ok) {
        complete('incomplete', 'workspace_unavailable');
        return;
      }

      const select = window.emailShieldSelectAccount;
      if (typeof select !== 'function') {
        complete('incomplete', 'selector_unavailable');
        return;
      }

      const accountIds = await waitForRenderedAccountIds();

      // Startup restore is allowed to hydrate selection only while this tab has
      // not made a newer selection decision. A user/tab selection can settle
      // while account chips are rendering, so preserve that newer decision.
      const currentSelectionSnapshot = window.emailShieldAccountSelection?.capture?.() ?? null;
      if (
        restoreSelectionSnapshot
        && currentSelectionSnapshot
        && currentSelectionSnapshot.generation !== restoreSelectionSnapshot.generation
      ) {
        complete('success', 'newer_tab_selection_preserved');
        return;
      }

      if (typeof workspace.selectedAccountId !== 'string') {
        if (accountIds.length !== 1) {
          complete('success', 'no_persisted_selection');
          return;
        }
        if (accountIds.length === 1) {
          select(accountIds[0], { remember: false });
          complete('success', 'single_restored_account_selected');
          return;
        }
      }

      if (!accountIds.includes(workspace.selectedAccountId)) {
        complete('incomplete', 'selected_account_not_rendered');
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
