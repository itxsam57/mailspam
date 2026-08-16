(() => {
  const installed = window.emailShieldInstalledModules ||= new Set();
  if (installed.has('family-guardian-preferences')) return;
  installed.add('family-guardian-preferences');

  const CATEGORIES = [
    ['banking', 'Banking'],
    ['crypto_investment', 'Crypto & investments'],
    ['gift_card', 'Gift cards'],
    ['government_legal', 'Government / legal'],
    ['delivery_payment', 'Delivery & fees'],
    ['romance', 'Romance'],
    ['job_task', 'Jobs & task scams'],
    ['remote_access_support', 'Remote-access support'],
    ['account_takeover', 'Account takeover'],
    ['shopping', 'Shopping'],
    ['other', 'Other'],
  ];
  let loaded = false;
  let dirty = true;

  function checkpoint(workflowId, checkpointId, outcome = 'success', errorCode) {
    const trace = window.emailShieldRuntimeTrace;
    if (trace?.currentWorkflowId?.() !== workflowId) return;
    trace.checkpoint(checkpointId, outcome, errorCode ? { errorCode } : undefined);
  }

  function registerPreferenceEdit(control) {
    if (!(control instanceof Element)) return;
    window.emailShieldRuntimeTrace?.registerControl(control, 'family.guardian_preferences.edit', 'family.guardian_preferences.edit', 'family_guardian_preferences_edit');
    control.addEventListener('change', () => checkpoint('family.guardian_preferences.edit', 'family.guardian_preferences.edit.ui_confirmed'));
  }

  async function responseJson(response) {
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || `Request failed (${response.status}).`);
    return body;
  }

  async function load() {
    const host = document.getElementById('consumerFamilyGuardianPanel');
    if (!host) return;
    let panel = document.getElementById('consumerFamilyPreferences');
    if (!panel) {
      panel = document.createElement('div');
      panel.id = 'consumerFamilyPreferences';
      panel.className = 'consumer-card';
      panel.innerHTML = `
        <h3>Guardian alert preferences</h3>
        <p>These settings control alerts only. They never weaken Family Shield verdicts, quarantine, Trash actions, or Community consensus.</p>
        <div class="consumer-actions">
          <label><input id="familyGuardianPaused" type="checkbox"> Pause Guardian alerts</label>
          <label><input id="familyGuardianHighRisk" type="checkbox"> High-risk-member mode</label>
        </div>
        <p class="hint">High-risk-member mode is always opt-in. It increases alert attention only; it does not expose a family member's mailbox content.</p>
        <div id="familyGuardianCategories" class="consumer-list"></div>
        <div class="consumer-actions"><button id="familyGuardianSave" type="button">Save Guardian preferences</button></div>
        <div id="familyGuardianPreferenceStatus" class="hint" role="status" aria-live="polite"></div>`;
      host.append(panel);
      registerPreferenceEdit(document.getElementById('familyGuardianPaused'));
      registerPreferenceEdit(document.getElementById('familyGuardianHighRisk'));
    }

    const status = document.getElementById('familyGuardianPreferenceStatus');
    try {
      const body = await responseJson(await fetch('/api/consumer/v1/family/preferences'));
      const preferences = body.preferences;
      const paused = document.getElementById('familyGuardianPaused');
      const highRisk = document.getElementById('familyGuardianHighRisk');
      if (paused instanceof HTMLInputElement) paused.checked = preferences.notificationsPaused === true;
      if (highRisk instanceof HTMLInputElement) highRisk.checked = preferences.highRiskMemberMode === true;
      const categories = document.getElementById('familyGuardianCategories');
      categories?.replaceChildren();
      for (const [key, label] of CATEGORIES) {
        const row = document.createElement('div');
        row.className = 'consumer-list-item';
        const labelElement = document.createElement('strong');
        labelElement.textContent = label;
        const select = document.createElement('select');
        select.dataset.guardianCategory = key;
        select.setAttribute('aria-label', `${label} Guardian alerts`);
        select.innerHTML = '<option value="all">All matching alerts</option><option value="high_only">High-risk only</option><option value="off">Off</option>';
        select.value = preferences.categories?.[key] || 'high_only';
        registerPreferenceEdit(select);
        row.append(labelElement, select);
        categories?.append(row);
      }
      if (!body.available && status) status.textContent = 'Create or join a Family Shield circle before saving Guardian preferences.';
      else if (status) status.textContent = 'Preferences are stored using a hashed internal account key; no mailbox identity or message content is stored here.';
      loaded = true;
      dirty = false;
    } catch (error) {
      dirty = true;
      if (status) status.textContent = error instanceof Error ? error.message : String(error);
    }
  }

  async function save() {
    const status = document.getElementById('familyGuardianPreferenceStatus');
    try {
      const paused = document.getElementById('familyGuardianPaused');
      const highRisk = document.getElementById('familyGuardianHighRisk');
      const categories = {};
      document.querySelectorAll('[data-guardian-category]').forEach((select) => {
        if (select instanceof HTMLSelectElement) categories[select.dataset.guardianCategory] = select.value;
      });
      const result = await responseJson(await fetch('/api/consumer/v1/family/preferences', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          notificationsPaused: paused instanceof HTMLInputElement && paused.checked,
          highRiskMemberMode: highRisk instanceof HTMLInputElement && highRisk.checked,
          categories,
        }),
      }));
      if (status) status.textContent = result.saved ? 'Family Guardian preferences saved.' : 'Preferences were not saved.';
      if (result.saved) {
        dirty = false;
        checkpoint('family.guardian_preferences', 'family.guardian_preferences.ui_confirmed');
      } else {
        checkpoint('family.guardian_preferences', 'family.guardian_preferences.ui_confirmed', 'failed', 'guardian_preferences_not_saved');
      }
    } catch (error) {
      if (status) status.textContent = error instanceof Error ? error.message : String(error);
      checkpoint('family.guardian_preferences', 'family.guardian_preferences.ui_confirmed', 'failed', 'guardian_preferences_failed');
    }
  }

  function familyVisible() {
    const host = document.getElementById('consumerFamilyGuardianPanel');
    const route = host?.closest('.app-route');
    return route ? !route.hidden && route.dataset.route === 'family' : location.hash === '#family';
  }

  function loadWhenVisible() {
    if (familyVisible() && (!loaded || dirty)) void load();
  }

  document.addEventListener('click', (event) => {
    if (event.target instanceof HTMLElement && event.target.id === 'familyGuardianSave') void save();
  });
  window.addEventListener('email-shield-profile-changed', () => { dirty = true; loadWhenVisible(); });
  window.addEventListener('email-shield-family-changed', () => { dirty = true; loadWhenVisible(); });
  window.addEventListener('email-shield-route-changed', (event) => {
    if (event.detail?.route === 'family') loadWhenVisible();
  });
  if (location.hash === '#family') queueMicrotask(loadWhenVisible);
})();
