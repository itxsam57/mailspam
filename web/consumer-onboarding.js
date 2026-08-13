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

  const state = {
    profileSignedIn: false,
    completed: new Set(),
    dismissed: false,
    loading: false,
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
    const button = document.querySelector(`.app-nav [data-route="${name}"]`);
    if (button instanceof HTMLButtonElement) button.click();
  }

  async function readJson(response, label) {
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || `${label} failed (${response.status}).`);
    return body;
  }

  const home = document.querySelector('[data-app-route="home"]') || document.querySelector('.app-route[data-route="home"]') || document.querySelector('main');
  if (!home) return;

  const panel = document.createElement('section');
  panel.className = 'panel first-run-panel';
  panel.id = 'consumerFirstRun';
  panel.setAttribute('aria-labelledby', 'consumerFirstRunHeading');
  panel.innerHTML = `
    <div class="first-run-head">
      <div><h2 id="consumerFirstRunHeading">Finish protection setup</h2><p>Eight clear steps take Email Shield from local Scam Check to continuous mailbox and optional Family protection. Private mailbox content stays with your provider and on this device.</p></div>
      <span id="consumerFirstRunProgress" class="first-run-progress" role="status" aria-live="polite"></span>
    </div>
    <div id="consumerFirstRunList" class="first-run-list"></div>
    <div id="consumerPermissionNote" class="first-run-note" hidden><strong>Permission promise</strong><br>Gmail and Microsoft use browser OAuth. iCloud, Yahoo and other IMAP providers use only the credentials required by that provider. Secrets stay in the operating-system credential vault. Email Shield requests mail access to inspect and perform the actions you explicitly enable; it does not upload mailbox bodies to the account, Family or Community services. You can disconnect a mailbox independently of your Email Shield account.</div>
    <div id="consumerFirstRunStatus" class="hint" role="status" aria-live="polite" style="margin-top:10px"></div>`;
  home.prepend(panel);

  const list = panel.querySelector('#consumerFirstRunList');
  const progress = panel.querySelector('#consumerFirstRunProgress');
  const status = panel.querySelector('#consumerFirstRunStatus');
  const permissionNote = panel.querySelector('#consumerPermissionNote');

  const definitions = [
    ['account_ready', 'Create or sign in', 'Use an Email Shield account for cross-device entitlement and Family features. Scam Check remains available locally before you sign in.', 'account'],
    ['mailbox_connected', 'Connect a mailbox', 'Choose Gmail, Microsoft, iCloud, Yahoo or another IMAP provider. Each mailbox remains independently removable.', 'settings'],
    ['permissions_reviewed', 'Review permissions', 'See exactly why provider access is requested and what Email Shield never uploads.', 'permissions'],
    ['first_scan_completed', 'Run the first protection scan', 'Complete at least one real or fixture protection scan so the dashboard has an observed baseline.', 'scan'],
    ['sensitivity_chosen', 'Choose protection sensitivity', 'Select High Protection, Balanced or Low Noise. Hard threats and authentication contradictions can never be disabled.', 'sensitivity'],
    ['continuous_protection_configured', 'Configure continuous protection', 'Enable or deliberately review background protection. Near-real-time provider events use the same protected scan pipeline when available.', 'background'],
    ['family_option_reviewed', 'Review Family Shield', 'Create or join a Shield Circle if useful, or explicitly skip it. Family members cannot browse one another’s mail by default.', 'family'],
    ['consumer_home_ready', 'Confirm your protection home', 'Return Home and confirm status, recent activity, waiting actions, Family state and broken connections are visible from the consumer surfaces.', 'home'],
  ];

  for (const [id, title, copy, action] of definitions) {
    const item = document.createElement('div');
    item.className = 'first-run-step';
    item.dataset.step = id;
    item.dataset.complete = 'false';
    const index = STEP_IDS.indexOf(id) + 1;
    item.innerHTML = `<span class="first-run-number">${index}</span><div class="first-run-copy"><strong>${title}</strong><p>${copy}</p><div class="first-run-actions"></div></div>`;
    const actions = item.querySelector('.first-run-actions');
    const go = document.createElement('button');
    go.type = 'button';
    go.textContent = action === 'permissions' ? 'Review' : action === 'home' ? 'Check Home' : 'Open';
    go.addEventListener('click', () => { void handleAction(id, action); });
    actions.append(go);
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
      skip.addEventListener('click', async () => {
        state.completed.add('family_option_reviewed');
        await persistProgress(false);
        render();
      });
      actions.append(skip);
    }
    list.append(item);
  }

  function liveFacts() {
    const mailbox = activeMailboxId();
    const signedInPanel = document.querySelector('#accountSignedIn');
    const scanDone = Boolean(document.querySelector('#scanHistoryList .scan-history-status.completed'));
    const sensitivityText = document.querySelector('#consumerSensitivityStatus')?.textContent || '';
    const backgroundToggle = document.querySelector('#backgroundToggle');
    const backgroundReviewed = state.completed.has('continuous_protection_configured')
      || (backgroundToggle instanceof HTMLButtonElement && backgroundToggle.getAttribute('aria-pressed') === 'true');
    return {
      mailbox,
      account: state.profileSignedIn || (signedInPanel instanceof HTMLElement && !signedInPanel.hidden),
      scanDone,
      sensitivityChosen: state.completed.has('sensitivity_chosen') || /protection|balanced|noise/i.test(sensitivityText),
      backgroundReviewed,
    };
  }

  function synchronizeObservedSteps() {
    const facts = liveFacts();
    if (facts.account) state.completed.add('account_ready');
    else state.completed.delete('account_ready');
    if (facts.mailbox) state.completed.add('mailbox_connected');
    else state.completed.delete('mailbox_connected');
    if (facts.scanDone) state.completed.add('first_scan_completed');
    if (facts.sensitivityChosen) state.completed.add('sensitivity_chosen');
    if (facts.backgroundReviewed) state.completed.add('continuous_protection_configured');
  }

  function coreReadyForHome() {
    return STEP_IDS.slice(0, 7).every((id) => state.completed.has(id));
  }

  function render() {
    synchronizeObservedSteps();
    if (state.dismissed && state.completed.has('consumer_home_ready')) {
      panel.hidden = true;
      return;
    }
    panel.hidden = false;
    for (const element of list.querySelectorAll('.first-run-step')) {
      const complete = state.completed.has(element.dataset.step);
      element.dataset.complete = String(complete);
      const number = element.querySelector('.first-run-number');
      if (number) number.textContent = complete ? '✓' : String(STEP_IDS.indexOf(element.dataset.step) + 1);
    }
    const count = STEP_IDS.filter((id) => state.completed.has(id)).length;
    progress.textContent = `${count} of ${STEP_IDS.length} setup steps complete`;
    status.textContent = coreReadyForHome()
      ? 'Core setup is ready. Check Home to finish onboarding.'
      : 'Complete the remaining items in order; you can still use local Scam Check at any time.';
  }

  async function persistProgress(dismissed) {
    const id = activeMailboxId();
    if (!id) return;
    const completedSteps = STEP_IDS.filter((step) => state.completed.has(step));
    const response = await fetch(`/api/consumer/v1/accounts/${encodeURIComponent(id)}/onboarding`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ completedSteps, dismissed }),
    });
    await readJson(response, 'Saving onboarding progress');
    state.dismissed = dismissed;
  }

  async function handleAction(id, action) {
    status.textContent = '';
    if (action === 'permissions') {
      permissionNote.hidden = false;
      state.completed.add('permissions_reviewed');
      await persistProgress(false).catch((error) => { status.textContent = error.message || String(error); });
      render();
      return;
    }
    if (action === 'sensitivity') {
      route('settings');
      document.querySelector('#consumerSafetyToolsPanel')?.scrollIntoView({ block: 'start' });
      status.textContent = 'Choose High Protection, Balanced or Low Noise. The step completes after the setting is observed.';
      return;
    }
    if (action === 'background') {
      route('settings');
      document.querySelector('#backgroundProtection')?.scrollIntoView({ block: 'center' });
      state.completed.add('continuous_protection_configured');
      await persistProgress(false).catch((error) => { status.textContent = error.message || String(error); });
      render();
      return;
    }
    if (action === 'family') {
      route('family');
      state.completed.add('family_option_reviewed');
      await persistProgress(false).catch((error) => { status.textContent = error.message || String(error); });
      render();
      return;
    }
    if (action === 'home') {
      synchronizeObservedSteps();
      if (!coreReadyForHome()) {
        status.textContent = 'Home cannot be marked ready until steps 1–7 are complete.';
        render();
        return;
      }
      route('home');
      state.completed.add('consumer_home_ready');
      try {
        await persistProgress(true);
        status.textContent = 'Protection setup complete.';
      } catch (error) {
        state.completed.delete('consumer_home_ready');
        status.textContent = error.message || String(error);
      }
      render();
      return;
    }
    route(action);
  }

  async function refresh() {
    if (state.loading) return;
    state.loading = true;
    try {
      const profile = await readJson(await fetch('/api/profile/v1/snapshot', { cache: 'no-store' }), 'Account status');
      state.profileSignedIn = profile.signedIn === true;
      const id = activeMailboxId();
      if (id) {
        const consumer = await readJson(await fetch(`/api/consumer/v1/accounts/${encodeURIComponent(id)}/state`, { cache: 'no-store' }), 'Onboarding state');
        const saved = Array.isArray(consumer?.onboarding?.completedSteps) ? consumer.onboarding.completedSteps : [];
        for (const step of saved) if (STEP_IDS.includes(step)) state.completed.add(step);
        state.dismissed = Boolean(consumer?.onboarding?.dismissedAt) && state.completed.has('consumer_home_ready');
      }
    } catch (error) {
      status.textContent = error instanceof Error ? error.message : String(error);
    } finally {
      state.loading = false;
      render();
    }
  }

  panel.addEventListener('click', () => { setTimeout(() => { void refresh(); }, 350); });
  window.addEventListener('email-shield-profile-changed', () => { void refresh(); });
  window.addEventListener('email-shield-family-changed', () => { state.completed.add('family_option_reviewed'); void persistProgress(false).finally(render); });
  const accounts = document.querySelector('#accountsList');
  if (accounts) new MutationObserver(() => { void refresh(); }).observe(accounts, { childList: true, subtree: true, attributes: true, attributeFilter: ['class', 'aria-current'] });
  const scanHistory = document.querySelector('#scanHistoryList');
  if (scanHistory) new MutationObserver(() => { synchronizeObservedSteps(); void persistProgress(false).finally(render); }).observe(scanHistory, { childList: true, subtree: true, characterData: true });
  const sensitivity = document.querySelector('#consumerSensitivityStatus');
  if (sensitivity) new MutationObserver(() => { synchronizeObservedSteps(); void persistProgress(false).finally(render); }).observe(sensitivity, { childList: true, subtree: true, characterData: true });
  window.setInterval(() => { if (!state.dismissed) void refresh(); }, 15_000);
  void refresh();
})();