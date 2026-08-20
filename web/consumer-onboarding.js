(() => {
  const installedModules = window.emailShieldInstalledModules ||= new Set();
  if (installedModules.has('consumer-onboarding')) return;
  installedModules.add('consumer-onboarding');

  const STEP_IDS = [
    'account_ready',
    'mailbox_connected',
    'permissions_reviewed',
    'first_scan_completed',
    'sensitivity_chosen',
    'continuous_protection_configured',
    'family_option_reviewed',
    'consumer_home_ready',
  ];
  const LEGACY_MARKER = 'consumer_intro';
  const runtimeTrace = window.emailShieldRuntimeTrace;
  const state = {
    profileSignedIn: false,
    mailboxId: null,
    completed: new Set(),
    dismissed: false,
    loading: false,
    refreshQueued: false,
  };

  const style = document.createElement('style');
  style.textContent = `
    .first-run-panel{order:-50}.first-run-head{display:flex;justify-content:space-between;gap:14px;align-items:flex-start}.first-run-head h2{margin:0 0 5px;font-size:17px}.first-run-head p{margin:0;color:var(--text-muted);font-size:12px;line-height:1.55;max-width:760px}.first-run-progress{font-size:11px;color:var(--text-muted);white-space:nowrap}.first-run-list{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px;margin-top:14px}.first-run-step{border:1px solid var(--border);border-radius:9px;background:var(--panel-raised);padding:12px;display:flex;gap:10px;align-items:flex-start}.first-run-step[data-complete="true"]{border-color:rgba(63,184,138,.45)}.first-run-number{width:24px;height:24px;flex:0 0 24px;border:1px solid var(--border);border-radius:50%;display:grid;place-items:center;font-size:10px}.first-run-step[data-complete="true"] .first-run-number{color:var(--safe)}.first-run-copy{min-width:0;flex:1}.first-run-copy strong{display:block;font-size:12px;margin-bottom:3px}.first-run-copy p{margin:0;color:var(--text-muted);font-size:11px;line-height:1.45}.first-run-actions{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}.first-run-actions button{font-size:10px;padding:6px 9px}.first-run-note{margin-top:12px;padding:10px;border:1px dashed var(--border);border-radius:8px;color:var(--text-muted);font-size:11px;line-height:1.5}.first-run-note[hidden]{display:none!important}@media(max-width:760px){.first-run-list{grid-template-columns:1fr}.first-run-head{flex-direction:column}.first-run-progress{white-space:normal}}
  `;
  document.head.append(style);

  function activeMailboxId() {
    return document.querySelector('#accountsList .account-chip.active')?.dataset.id
      || document.querySelector('#accountsList [aria-current="true"]')?.closest('.account-chip')?.dataset.id
      || null;
  }

  function route(name) {
    if (typeof window.emailShieldNavigate === 'function' && window.emailShieldNavigate(name)) return;
    const button = document.querySelector(`.app-nav [data-route-target="${name}"], .app-nav [data-route="${name}"]`);
    if (button instanceof HTMLButtonElement) button.click();
  }

  function requestMailboxSetup(reason) {
    route('settings');
    status.textContent = 'This setup item needs a connected, selected mailbox. Choose a provider in Mailboxes & Settings to continue.';
    window.dispatchEvent(new CustomEvent('email-shield-provider-setup-requested', {
      detail: { reason },
    }));
  }

  async function readJson(response, label) {
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || `${label} failed (${response.status}).`);
    return body;
  }

  const home = window.emailShieldRouter?.routeStack?.('home')
    || document.querySelector('.app-route[data-route="home"] .shell-panel-stack')
    || document.querySelector('[data-app-route="home"]')
    || document.querySelector('main');
  if (!home) return;
  const panel = document.createElement('section');
  panel.className = 'panel first-run-panel';
  panel.id = 'consumerFirstRun';
  panel.setAttribute('aria-labelledby', 'consumerFirstRunHeading');
  panel.innerHTML = `
    <div class="first-run-head"><div><h2 id="consumerFirstRunHeading">Finish protection setup</h2><p>Eight clear steps take Email Shield from local Scam Check to continuous mailbox and optional Family protection. Private mailbox content stays with your provider and on this device.</p></div><span id="consumerFirstRunProgress" class="first-run-progress" role="status" aria-live="polite"></span></div>
    <div id="consumerFirstRunList" class="first-run-list"></div>
    <div id="consumerPermissionNote" class="first-run-note" hidden><strong>Permission promise</strong><br>Gmail uses browser OAuth. iCloud, Yahoo and other IMAP providers use only the credentials required by that provider. Secrets stay in the operating-system credential vault. Email Shield requests mail access to inspect and perform the actions you explicitly enable; it does not upload mailbox bodies to the account, Family or Community services. You can disconnect a mailbox independently of your Email Shield account.</div>
    <div id="consumerFirstRunStatus" class="hint" role="status" aria-live="polite" style="margin-top:10px"></div>`;
  home.prepend(panel);
  const list = panel.querySelector('#consumerFirstRunList');
  const progress = panel.querySelector('#consumerFirstRunProgress');
  const status = panel.querySelector('#consumerFirstRunStatus');
  const permissionNote = panel.querySelector('#consumerPermissionNote');

  const definitions = [
    ['account_ready', 'Create or sign in', 'Use an Email Shield account for cross-device entitlement and Family features. Scam Check remains available locally before you sign in.', 'account'],
    ['mailbox_connected', 'Connect a mailbox', 'Requires a connected, selected mailbox. Choose Gmail, iCloud, Yahoo or another IMAP provider. Each mailbox remains independently removable.', 'connect'],
    ['permissions_reviewed', 'Review permissions', 'Requires a connected, selected mailbox. See exactly why provider access is requested and what Email Shield never uploads.', 'permissions'],
    ['first_scan_completed', 'Run the first protection scan', 'Requires a connected, selected mailbox. Complete at least one protection scan so the dashboard has an observed baseline.', 'scan'],
    ['sensitivity_chosen', 'Choose protection sensitivity', 'Requires a connected, selected mailbox. Explicitly save High Protection, Balanced or Low Noise. Hard threats and authentication contradictions can never be disabled.', 'sensitivity'],
    ['continuous_protection_configured', 'Enable continuous protection', 'Requires a connected, selected mailbox. Enable background protection. Near-real-time provider events use the same protected scan pipeline when available and the schedule remains a fallback.', 'background'],
    ['family_option_reviewed', 'Review Family Shield', 'Requires a connected, selected mailbox to save this setup choice. Create or join a Shield Circle if useful, or explicitly skip it. Family members cannot browse one another’s mail by default.', 'family'],
    ['consumer_home_ready', 'Confirm your protection home', 'Requires a connected, selected mailbox and completed steps 1–7. Return Home so protection status, activity, Family state and connection problems are easy to find.', 'home'],
  ];

  for (const [id, title, copy, action] of definitions) {
    const item = document.createElement('div');
    item.className = 'first-run-step';
    item.dataset.step = id;
    item.dataset.complete = 'false';
    item.innerHTML = `<span class="first-run-number">${STEP_IDS.indexOf(id) + 1}</span><div class="first-run-copy"><strong>${title}</strong><p>${copy}</p><div class="first-run-actions"></div></div>`;
    const actions = item.querySelector('.first-run-actions');
    if (id === 'sensitivity_chosen') {
      for (const [profile, label] of [['high_protection', 'High Protection'], ['balanced', 'Balanced'], ['low_noise', 'Low Noise']]) {
        const choice = document.createElement('button');
        choice.type = 'button';
        choice.textContent = label;
        choice.addEventListener('click', () => { void chooseSensitivity(profile); });
        actions.append(choice);
      }
    } else {
      const go = document.createElement('button');
      go.type = 'button';
      go.textContent = action === 'permissions' ? 'Review' : action === 'home' ? 'Check Home' : 'Open';
      if (action === 'permissions') {
        runtimeTrace?.registerControl(go, 'onboarding.permissions.review', 'onboarding.permissions.review', 'onboarding_permissions');
      } else if (action === 'home') {
        runtimeTrace?.registerControl(go, 'onboarding.complete', 'onboarding.complete', 'onboarding_completion');
      }
      go.addEventListener('click', () => { void handleAction(action); });
      actions.append(go);
    }
    if (id === 'account_ready') {
      const local = document.createElement('button');
      local.type = 'button';
      local.textContent = 'Use local Scam Check';
      local.addEventListener('click', () => route('scan'));
      actions.append(local);
    }
    if (id === 'family_option_reviewed') {
      const skip = document.createElement('button');
      skip.type = 'button';
      skip.textContent = 'Not now';
      runtimeTrace?.registerControl(skip, 'onboarding.family.skip', 'onboarding.family.skip', 'onboarding_family');
      skip.addEventListener('click', async () => {
        const id = await ensureBoundMailbox();
        if (!id) { requestMailboxSetup('family'); return; }
        state.completed.add('family_option_reviewed');
        await persistProgress(false, id).catch(showError);
        render();
        runtimeTrace?.checkpoint('onboarding.family.skip.ui_confirmed', 'success', {
          component: 'consumer_onboarding',
          step: 'family_skip_saved',
        });
      });
      actions.append(skip);
    }
    list.append(item);
  }

  function showError(error) { status.textContent = error instanceof Error ? error.message : String(error); }

  function synchronizeLocalSteps() {
    if (state.profileSignedIn) state.completed.add('account_ready');
    else state.completed.delete('account_ready');
    if (state.mailboxId && state.mailboxId === activeMailboxId()) state.completed.add('mailbox_connected');
    else state.completed.delete('mailbox_connected');
  }

  function coreReadyForHome() { return STEP_IDS.slice(0, 7).every((id) => state.completed.has(id)); }

  function render() {
    synchronizeLocalSteps();
    if (state.dismissed && state.completed.has('consumer_home_ready')) { panel.hidden = true; return; }
    panel.hidden = false;
    for (const element of list.querySelectorAll('.first-run-step')) {
      const complete = state.completed.has(element.dataset.step);
      element.dataset.complete = String(complete);
      const number = element.querySelector('.first-run-number');
      if (number) number.textContent = complete ? '✓' : String(STEP_IDS.indexOf(element.dataset.step) + 1);
    }
    progress.textContent = `${STEP_IDS.filter((id) => state.completed.has(id)).length} of ${STEP_IDS.length} setup steps complete`;
    status.textContent = coreReadyForHome() ? 'Core setup is ready. Check Home to finish onboarding.' : 'Complete the remaining items; local Scam Check stays available before mailbox setup.';
  }

  async function persistProgress(dismissed, expectedMailboxId = state.mailboxId) {
    const activeId = activeMailboxId();
    if (!expectedMailboxId || state.mailboxId !== expectedMailboxId || activeId !== expectedMailboxId) return false;
    const completedSteps = [LEGACY_MARKER, ...STEP_IDS.filter((step) => state.completed.has(step))];
    const response = await fetch(`/api/consumer/v1/accounts/${encodeURIComponent(expectedMailboxId)}/onboarding`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ completedSteps, dismissed }),
    });
    await readJson(response, 'Saving onboarding progress');
    if (state.mailboxId === expectedMailboxId && activeMailboxId() === expectedMailboxId) state.dismissed = dismissed;
    return true;
  }

  async function ensureBoundMailbox() {
    const id = activeMailboxId();
    if (!id) {
      status.textContent = 'Connect and select a mailbox before saving setup progress.';
      return null;
    }
    if (state.mailboxId !== id) await refresh();
    if (state.mailboxId !== id || activeMailboxId() !== id) {
      status.textContent = 'Mailbox selection changed. Setup state was refreshed without copying progress between accounts.';
      return null;
    }
    return id;
  }

  async function chooseSensitivity(profile) {
    const id = await ensureBoundMailbox();
    if (!id) { requestMailboxSetup('sensitivity'); return; }
    try {
      await readJson(await fetch(`/api/consumer/v1/accounts/${encodeURIComponent(id)}/sensitivity`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ profile }),
      }), 'Saving protection sensitivity');
      if (state.mailboxId !== id || activeMailboxId() !== id) { void refresh(); return; }
      state.completed.add('sensitivity_chosen');
      await persistProgress(false, id);
      render();
    } catch (error) { showError(error); }
  }

  async function handleAction(action) {
    status.textContent = '';
    if (action === 'connect') {
      requestMailboxSetup('connect');
      return;
    }
    if (action === 'permissions') {
      const id = await ensureBoundMailbox();
      if (!id) { requestMailboxSetup('permissions'); return; }
      permissionNote.hidden = false;
      state.completed.add('permissions_reviewed');
      await persistProgress(false, id).catch(showError);
      render();
      runtimeTrace?.checkpoint('onboarding.permissions.review.ui_confirmed', 'success', {
        component: 'consumer_onboarding',
        step: 'permission_promise_visible',
      });
      return;
    }
    if (action === 'scan') {
      const id = await ensureBoundMailbox();
      if (!id) { requestMailboxSetup('scan'); return; }
      route('scan');
      return;
    }
    if (action === 'background') {
      const id = await ensureBoundMailbox();
      if (!id) { requestMailboxSetup('background'); return; }
      route('protection');
      document.querySelector('#backgroundProtection')?.scrollIntoView({ block: 'center' });
      status.textContent = 'Enable Background Protection. This step completes only after the enabled state is observed.';
      return;
    }
    if (action === 'family') {
      const id = await ensureBoundMailbox();
      if (!id) { requestMailboxSetup('family'); return; }
      route('family');
      state.completed.add('family_option_reviewed');
      await persistProgress(false, id).catch(showError);
      render();
      return;
    }
    if (action === 'home') {
      const id = await ensureBoundMailbox();
      if (!id) { requestMailboxSetup('home'); return; }
      synchronizeLocalSteps();
      if (!coreReadyForHome()) { status.textContent = 'Home cannot be marked ready until steps 1–7 are complete.'; render(); return; }
      route('home');
      state.completed.add('consumer_home_ready');
      try {
        await persistProgress(true, id);
        status.textContent = 'Protection setup complete.';
        runtimeTrace?.checkpoint('onboarding.complete.ui_confirmed', 'success', {
          component: 'consumer_onboarding',
          step: 'setup_complete_visible',
        });
      } catch (error) {
        state.completed.delete('consumer_home_ready');
        showError(error);
      }
      render();
      return;
    }
    route(action);
  }

  async function refresh() {
    if (state.loading) { state.refreshQueued = true; return; }
    state.loading = true;
    state.refreshQueued = false;
    const requestedMailboxId = activeMailboxId();
    try {
      const profile = await readJson(await fetch('/api/profile/v1/snapshot', { cache: 'no-store' }), 'Account status');
      if (activeMailboxId() !== requestedMailboxId) { state.refreshQueued = true; return; }
      state.profileSignedIn = profile.signedIn === true;

      if (!requestedMailboxId) {
        state.mailboxId = null;
        state.completed = new Set();
        state.dismissed = false;
        return;
      }

      const [consumer, scanHistory, background] = await Promise.all([
        readJson(await fetch(`/api/consumer/v1/accounts/${encodeURIComponent(requestedMailboxId)}/state`, { cache: 'no-store' }), 'Onboarding state'),
        readJson(await fetch(`/api/accounts/${encodeURIComponent(requestedMailboxId)}/scan-history`, { cache: 'no-store' }), 'Scan history'),
        readJson(await fetch(`/api/accounts/${encodeURIComponent(requestedMailboxId)}/background-protection`, { cache: 'no-store' }), 'Background protection'),
      ]);
      if (activeMailboxId() !== requestedMailboxId) { state.refreshQueued = true; return; }

      const saved = Array.isArray(consumer?.onboarding?.completedSteps) ? consumer.onboarding.completedSteps : [];
      const completed = new Set(saved.filter((step) => STEP_IDS.includes(step)));
      if (profile.signedIn === true) completed.add('account_ready'); else completed.delete('account_ready');
      completed.add('mailbox_connected');
      // This is a monotonic historical milestone. Current history can prove it
      // happened, but bounded history retention must never revoke persisted
      // completion after the original completed record ages out.
      if (Array.isArray(scanHistory?.history) && scanHistory.history.some((record) => record?.status === 'completed')) completed.add('first_scan_completed');
      if (background?.enabled === true) completed.add('continuous_protection_configured');
      else completed.delete('continuous_protection_configured');

      state.mailboxId = requestedMailboxId;
      state.completed = completed;
      state.dismissed = Boolean(consumer?.onboarding?.dismissedAt) && completed.has('consumer_home_ready');

      const observedChanged = STEP_IDS.some((step) => completed.has(step) !== saved.includes(step));
      if (!saved.includes(LEGACY_MARKER) || observedChanged) await persistProgress(state.dismissed, requestedMailboxId);
    } catch (error) { showError(error); }
    finally {
      state.loading = false;
      render();
      if (state.refreshQueued || activeMailboxId() !== requestedMailboxId) queueMicrotask(() => { void refresh(); });
    }
  }

  window.addEventListener('email-shield-profile-changed', () => { void refresh(); });
  window.addEventListener('email-shield-family-changed', () => {
    if (state.mailboxId && state.mailboxId === activeMailboxId()) {
      state.completed.add('family_option_reviewed');
      void persistProgress(false, state.mailboxId).finally(render);
    } else void refresh();
  });
  window.addEventListener('email-shield-scan-history-changed', () => { void refresh(); });
  const accounts = document.querySelector('#accountsList');
  if (accounts) new MutationObserver(() => { void refresh(); }).observe(accounts, { childList: true, subtree: true, attributes: true, attributeFilter: ['class', 'aria-current'] });
  const scanHistory = document.querySelector('#scanHistoryList');
  if (scanHistory) new MutationObserver(() => { void refresh(); }).observe(scanHistory, { childList: true, subtree: true, characterData: true });
  const backgroundToggle = document.querySelector('#backgroundToggle');
  if (backgroundToggle) new MutationObserver(() => { void refresh(); }).observe(backgroundToggle, { attributes: true, attributeFilter: ['aria-pressed'] });
  window.setInterval(() => { if (!state.dismissed) void refresh(); }, 15_000);
  void refresh();
})();