(() => {
  const installedModules = window.emailShieldInstalledModules ||= new Set();
  if (installedModules.has('consumer-product')) return;
  installedModules.add('consumer-product');

  const state = {
    accountId: null,
    consumer: null,
    health: null,
    healthAccountId: null,
    family: null,
    radar: null,
  };
  let healthRequestGeneration = 0;

  const style = document.createElement('style');
  style.textContent = `
    .consumer-provider-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;margin:12px 0}
    .consumer-provider{display:flex;align-items:center;justify-content:space-between;gap:12px;text-align:left;padding:14px;border:1px solid var(--border);border-radius:9px;background:var(--panel-raised)}
    .consumer-provider strong{display:block;font-size:13px}.consumer-provider span{display:block;color:var(--text-muted);font-size:11px;margin-top:3px}
    .consumer-provider.primary-provider{border-color:rgba(63,184,138,.55)}
    .consumer-status-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin:12px 0}
    .consumer-stat{padding:13px;border:1px solid var(--border);border-radius:8px;background:var(--panel-raised)}
    .consumer-stat span{display:block;font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--text-faint)}
    .consumer-stat strong{display:block;margin-top:5px;font-size:15px}
    .consumer-section{display:flex;flex-direction:column;gap:12px}.consumer-card{padding:14px;border:1px solid var(--border);border-radius:9px;background:var(--panel-raised)}
    .consumer-card h3{margin:0 0 6px;font-size:13px}.consumer-card p{margin:0;color:var(--text-muted);font-size:12px;line-height:1.5}
    .consumer-actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}.consumer-list{display:flex;flex-direction:column;gap:8px;margin-top:10px}
    .consumer-list-item{padding:10px;border-top:1px solid var(--border);display:flex;justify-content:space-between;gap:12px;align-items:flex-start}.consumer-list-item:first-child{border-top:0}
    .consumer-list-item strong{font-size:12px}.consumer-list-item .hint{margin-top:3px}.consumer-chip{display:inline-flex;padding:3px 7px;border-radius:999px;background:rgba(108,118,132,.15);font-size:10px;margin:2px 4px 2px 0}
    .consumer-chip.warning{background:rgba(232,178,61,.14);color:var(--review)}.consumer-chip.critical{background:rgba(226,61,79,.14);color:var(--confirmed)}.consumer-chip.ok{background:rgba(63,184,138,.14);color:var(--safe)}
    .consumer-danger{border-color:rgba(226,61,79,.45)}
    .consumer-onboarding{position:fixed;inset:0;z-index:120;background:rgba(5,7,10,.78);display:flex;align-items:center;justify-content:center;padding:20px}
    .consumer-onboarding-card{width:min(620px,100%);max-height:90vh;overflow:auto;background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:22px;box-shadow:0 24px 80px rgba(0,0,0,.4)}
    .consumer-onboarding-card h2{font-size:19px;text-transform:none;letter-spacing:0;color:var(--text);margin-bottom:8px}.consumer-onboarding-card p{color:var(--text-muted);line-height:1.6;font-size:13px}
    .consumer-step{padding:12px 0;border-top:1px solid var(--border)}.consumer-step:first-of-type{border-top:0}.consumer-step strong{display:block;margin-bottom:4px}
    .consumer-two{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.consumer-input{width:100%}
    #modeSelectFieldConsumerHidden,#modeSelectConsumerHidden{display:none!important}
    @media(max-width:760px){.consumer-provider-grid,.consumer-two{grid-template-columns:1fr}.consumer-status-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
    @media(max-width:460px){.consumer-status-grid{grid-template-columns:1fr}}
  `;
  document.head.appendChild(style);

  function activeMailboxId() {
    const selection = window.emailShieldAccountSelection?.currentId?.();
    if (typeof selection === 'string' && selection) return selection;
    return document.querySelector('#accountsList .account-chip.active')?.dataset.id
      || document.querySelector('#accountsList [aria-current="true"]')?.closest('.account-chip')?.dataset.id
      || null;
  }

  function clearAccountScopedViews() {
    state.consumer = null;
    state.health = null;
    state.healthAccountId = null;
    document.getElementById('consumerHealthSummary')?.replaceChildren();
    document.getElementById('consumerSubscriptions')?.replaceChildren();
    document.getElementById('consumerMailboxSecurity')?.replaceChildren();
    document.getElementById('consumerFootprint')?.replaceChildren();
    document.getElementById('consumerActivityList')?.replaceChildren();
    const sensitivity = document.getElementById('consumerSensitivityStatus');
    if (sensitivity) sensitivity.textContent = '';
  }

  function bindSelectedAccount(id) {
    const normalized = typeof id === 'string' && id ? id : null;
    if (state.accountId === normalized) return;
    state.accountId = normalized;
    clearAccountScopedViews();
  }

  function stillSelected(id) {
    return Boolean(id && state.accountId === id && activeMailboxId() === id);
  }

  async function json(response) {
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || `Request failed (${response.status}).`);
    return body;
  }

  async function post(path, body = {}) {
    return json(await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }));
  }

  function selectedSessionOrThrow() {
    const id = activeMailboxId();
    if (!id) throw new Error('Connect or select a mailbox first.');
    bindSelectedAccount(id);
    return id;
  }

  function routePanel(route) {
    return document.querySelector(`[data-app-route="${route}"]`);
  }

  function addPanelAfter(anchor, panel) {
    if (anchor?.parentElement) anchor.insertAdjacentElement('afterend', panel);
    else document.querySelector('main')?.appendChild(panel);
  }

  const nav = document.querySelector('.app-nav');
  if (nav) {
    const labels = new Map([
      ['home', 'Home'],
      ['scan', 'Check & Scan'],
      ['protection', 'Health'],
      ['family', 'Family'],
      ['history', 'Activity'],
      ['account', 'Account'],
      ['settings', 'Settings'],
    ]);
    nav.querySelectorAll('[data-route]').forEach((button) => {
      const route = button.dataset.route;
      if (route === 'community') button.hidden = true;
      else if (labels.has(route)) button.textContent = labels.get(route);
    });
  }

  const connectPanel = document.querySelector('[aria-labelledby="connectHeading"]');
  if (connectPanel) {
    const providerSelect = document.getElementById('providerSelect');
    const modeSelect = document.getElementById('modeSelect');
    const connectBtn = document.getElementById('connectBtn');
    const credentialFields = document.getElementById('credentialFields');
    const row = providerSelect?.closest('.row');
    if (modeSelect instanceof HTMLSelectElement) {
      modeSelect.value = 'live';
      const field = modeSelect.closest('label');
      if (field) field.hidden = true;
    }
    if (providerSelect instanceof HTMLSelectElement) {
      const field = providerSelect.closest('label');
      if (field) field.hidden = true;
    }
    if (connectBtn instanceof HTMLButtonElement) connectBtn.hidden = true;

    const consumerIntro = document.createElement('div');
    consumerIntro.className = 'consumer-card';
    consumerIntro.innerHTML = `<h3>Protect a mailbox</h3><p>Sign in once. Email Shield keeps the provider authorization in your operating system's protected credential vault and restores protection automatically when the app starts again.</p>`;
    const grid = document.createElement('div');
    grid.className = 'consumer-provider-grid';
    const providers = [
      ['gmail', 'Continue with Google', 'Gmail · browser OAuth', true],
      ['outlook', 'Continue with Microsoft', 'Outlook / Hotmail / Microsoft 365 · browser OAuth', true],
      ['icloud', 'Add iCloud Mail', 'Apple Account email + app-specific password', false],
      ['yahoo', 'Add Yahoo Mail', 'Yahoo email + app password', false],
      ['imap', 'Other email provider', 'Advanced IMAP setup', false],
    ];
    for (const [value, title, description, primary] of providers) {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = `consumer-provider${primary ? ' primary-provider' : ''}`;
      button.innerHTML = `<div><strong>${title}</strong><span>${description}</span></div><span aria-hidden="true">›</span>`;
      button.addEventListener('click', () => {
        if (!(providerSelect instanceof HTMLSelectElement) || !(modeSelect instanceof HTMLSelectElement) || !(connectBtn instanceof HTMLButtonElement)) return;
        providerSelect.value = value;
        modeSelect.value = 'live';
        providerSelect.dispatchEvent(new Event('change', { bubbles: true }));
        modeSelect.dispatchEvent(new Event('change', { bubbles: true }));
        setTimeout(() => {
          connectBtn.hidden = false;
          if (value === 'gmail' || value === 'outlook') {
            connectBtn.click();
            connectBtn.hidden = true;
          } else {
            connectBtn.textContent = 'Connect mailbox';
            connectBtn.hidden = false;
            credentialFields?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
          }
        }, 0);
      });
      grid.append(button);
    }
    consumerIntro.append(grid);

    if (new URLSearchParams(location.search).get('developer') === '1') {
      const dev = document.createElement('details');
      dev.className = 'consumer-card';
      dev.innerHTML = '<summary>Developer acceptance controls</summary><p class="hint">Fixture mailboxes are isolated synthetic test data. These controls are hidden in the normal consumer journey.</p>';
      const fixture = document.createElement('button');
      fixture.type = 'button';
      fixture.textContent = 'Use fixture mode';
      fixture.addEventListener('click', () => {
        if (modeSelect instanceof HTMLSelectElement) {
          modeSelect.value = 'fixture';
          modeSelect.dispatchEvent(new Event('change', { bubbles: true }));
        }
        if (connectBtn instanceof HTMLButtonElement) connectBtn.hidden = false;
        if (providerSelect instanceof HTMLSelectElement) providerSelect.closest('label')?.removeAttribute('hidden');
      });
      dev.append(fixture);
      consumerIntro.append(dev);
    }
    row?.insertAdjacentElement('beforebegin', consumerIntro);
  }

  const health = document.createElement('section');
  health.className = 'panel consumer-section';
  health.id = 'consumerHealthPanel';
  health.dataset.appRoute = 'protection';
  health.innerHTML = `
    <div><h2>Health</h2><p class="hint">Local mailbox organization plus compromise indicators. Unsupported provider-security checks are shown as unavailable—not as safe.</p></div>
    <div class="consumer-actions"><button id="consumerRunHealth" class="primary" type="button">Check Inbox & Mailbox Health</button><button id="consumerRefreshHealth" type="button">Refresh view</button></div>
    <div id="consumerHealthStatus" class="hint" role="status" aria-live="polite"></div>
    <div id="consumerHealthSummary" class="consumer-status-grid"></div>
    <div class="consumer-two"><div class="consumer-card"><h3>Subscriptions & cleanup</h3><div id="consumerSubscriptions" class="consumer-list"></div></div><div class="consumer-card"><h3>Mailbox security</h3><div id="consumerMailboxSecurity" class="consumer-list"></div></div></div>
    <div class="consumer-card"><h3>Digital Account Footprint</h3><p>Local discovery from authenticated account/welcome/security/receipt messages. This is not uploaded and is not claimed to be a complete account registry.</p><div id="consumerFootprint" class="consumer-list"></div></div>
  `;
  addPanelAfter(routePanel('protection'), health);

  const activity = document.createElement('section');
  activity.className = 'panel consumer-section';
  activity.id = 'consumerActivityPanel';
  activity.dataset.appRoute = 'history';
  activity.innerHTML = `
    <div><h2>Protection Activity</h2><p class="hint">Privacy-safe local history of what Email Shield checked, protected, changed or could not verify.</p></div>
    <div class="consumer-actions"><button id="consumerRefreshActivity" type="button">Refresh</button><button id="consumerClearActivity" type="button">Clear local activity</button></div>
    <div id="consumerActivityStatus" class="hint" role="status" aria-live="polite"></div><div id="consumerActivityList" class="consumer-list"></div>
  `;
  addPanelAfter(routePanel('history'), activity);

  const familyGuardian = document.createElement('section');
  familyGuardian.className = 'panel consumer-section';
  familyGuardian.id = 'consumerFamilyGuardianPanel';
  familyGuardian.dataset.appRoute = 'family';
  familyGuardian.innerHTML = `
    <div><h2>Family Guardian</h2><p class="hint">Aggregate family protection and verified campaign awareness. Member mailbox content stays private.</p></div>
    <div class="consumer-actions"><button id="consumerRefreshFamily" type="button">Refresh Family Guardian</button></div>
    <div id="consumerFamilySummary" class="consumer-status-grid"></div>
    <div class="consumer-card"><h3>Scam campaign radar</h3><p>Only verified signed network intelligence is shown. If the feed cannot be verified, the radar becomes unavailable rather than stale-green.</p><div id="consumerRadar" class="consumer-list"></div></div>
  `;
  addPanelAfter(routePanel('family'), familyGuardian);

  const tools = document.createElement('section');
  tools.className = 'panel consumer-section';
  tools.id = 'consumerSafetyToolsPanel';
  tools.dataset.appRoute = 'settings';
  tools.innerHTML = `
    <div><h2>Safety Tools & Privacy</h2><p class="hint">Explicit checks only. Email Shield does not upload browser history, mailbox content or passwords.</p></div>
    <div class="consumer-two">
      <div class="consumer-card"><h3>Protection sensitivity</h3><p>Changes how much borderline activity asks for your attention. Hard threat/authentication rules stay locked.</p><div class="consumer-actions"><button data-consumer-sensitivity="high_protection">High protection</button><button data-consumer-sensitivity="balanced">Balanced</button><button data-consumer-sensitivity="low_noise">Low noise</button></div><div id="consumerSensitivityStatus" class="hint"></div></div>
      <div class="consumer-card"><h3>Notification privacy</h3><p>Default notifications are generic. Richer local previews are optional and remain device-local.</p><label class="row"><input id="consumerRicherNotifications" type="checkbox"> Allow richer local notification text</label></div>
      <div class="consumer-card"><h3>Check a destination</h3><label class="field"><span>Website URL</span><input id="consumerBrowserUrl" class="consumer-input" type="url" placeholder="https://example.com"></label><div class="consumer-actions"><button id="consumerCheckBrowser" type="button">Check before opening</button></div><div id="consumerBrowserResult" class="hint"></div></div>
      <div class="consumer-card"><h3>Payment / callback / remote-access check</h3><textarea id="consumerInterventionText" class="consumer-input" rows="5" maxlength="32000" placeholder="Paste the suspicious request or conversation"></textarea><div class="consumer-actions"><button id="consumerCheckIntervention" type="button">Check interaction</button></div><div id="consumerInterventionResult" class="hint"></div></div>
      <div class="consumer-card"><h3>Exposure check</h3><p>Optional privacy-preserving lookup. Only a short hash prefix leaves the device when a vetted service is configured.</p><label class="field"><span>Email</span><input id="consumerExposureEmail" class="consumer-input" type="email"></label><div class="consumer-actions"><button id="consumerCheckExposure" type="button">Check exposure</button></div><div id="consumerExposureResult" class="hint"></div></div>
      <div class="consumer-card"><h3>Support bundle</h3><p>Exports runtime/provider/aggregate operational diagnostics only—never credentials, tokens, subjects, senders, URLs, family private data or device keys.</p><div class="consumer-actions"><button id="consumerSupportBundle" type="button">Export privacy-safe support bundle</button></div></div>
    </div>
  `;
  addPanelAfter(routePanel('settings'), tools);

  function setHealthStatus(message, error = false) {
    const el = document.getElementById('consumerHealthStatus');
    if (el) { el.textContent = message; el.style.color = error ? 'var(--confirmed)' : ''; }
  }

  function renderHealth(result, accountId) {
    if (!stillSelected(accountId)) return;
    state.health = result;
    state.healthAccountId = accountId;
    const inbox = result?.inboxHealth || {};
    const mailbox = result?.mailboxHealth || {};
    const footprint = result?.digitalFootprint || {};
    const summary = document.getElementById('consumerHealthSummary');
    if (summary) summary.innerHTML = `
      <div class="consumer-stat"><span>Inspected</span><strong>${Number(inbox.inspectedMessages || 0)}</strong></div>
      <div class="consumer-stat"><span>Subscriptions</span><strong>${Array.isArray(inbox.subscriptions) ? inbox.subscriptions.length : 0}</strong></div>
      <div class="consumer-stat"><span>Mailbox state</span><strong>${String(mailbox.state || 'unknown').replace(/_/g,' ')}</strong></div>
      <div class="consumer-stat"><span>Account footprint</span><strong>${Array.isArray(footprint.entries) ? footprint.entries.length : 0}</strong></div>`;
    const subscriptions = document.getElementById('consumerSubscriptions');
    if (subscriptions) {
      subscriptions.replaceChildren();
      for (const item of (inbox.subscriptions || []).slice(0, 20)) {
        const row = document.createElement('div'); row.className = 'consumer-list-item';
        const info = document.createElement('div'); info.innerHTML = `<strong>${escapeHtml(item.displayName || item.senderDomain || 'Subscription')}</strong><div class="hint">${Number(item.messages || 0)} message(s) · ${item.unsubscribeAvailable ? 'unsubscribe available' : 'no verified unsubscribe control'}</div>`;
        const controls = document.createElement('div');
        const cleanup = document.createElement('button'); cleanup.type = 'button'; cleanup.textContent = 'Clean old mail';
        cleanup.addEventListener('click', async () => {
          if (!stillSelected(accountId)) {
            setHealthStatus('Mailbox selection changed. Run Health again before cleaning mail.', true);
            return;
          }
          if (!confirm(`Move older matching mail from ${item.displayName || item.senderDomain || 'this sender'} to Trash?`)) return;
          const confirmation = prompt('Type MOVE TO TRASH to confirm');
          if (confirmation !== 'MOVE TO TRASH' || !stillSelected(accountId)) return;
          try {
            const cleanupResult = await post(`/api/consumer/v1/accounts/${encodeURIComponent(accountId)}/cleanup`, {
              senderAddress: item.senderAddress,
              senderDomain: item.senderDomain,
              olderThanDays: 30,
              keepNewest: true,
              confirmation,
            });
            if (!stillSelected(accountId)) return;
            setHealthStatus(`${cleanupResult.movedToTrash} message(s) moved to Trash.${cleanupResult.undoAvailable ? ' Undo is available in Activity for 30 minutes.' : ''}`);
            await loadActivity();
          } catch (error) {
            if (stillSelected(accountId)) setHealthStatus(error.message || String(error), true);
          }
        });
        controls.append(cleanup); row.append(info, controls); subscriptions.append(row);
      }
      if (!(inbox.subscriptions || []).length) subscriptions.innerHTML = '<div class="hint">No newsletter/subscription inventory yet. Run Health after connecting a mailbox.</div>';
    }
    const security = document.getElementById('consumerMailboxSecurity');
    if (security) {
      security.replaceChildren();
      for (const indicator of (mailbox.indicators || [])) {
        const row = document.createElement('div'); row.className='consumer-list-item';
        row.innerHTML = `<div><strong>${escapeHtml(indicator.title || indicator.code)}</strong><div class="hint">${escapeHtml(indicator.detail || '')}</div></div><span class="consumer-chip ${indicator.severity === 'critical' ? 'critical' : 'warning'}">${escapeHtml(indicator.severity)}</span>`;
        security.append(row);
      }
      for (const check of (mailbox.providerChecks || [])) {
        const row = document.createElement('div'); row.className='consumer-list-item';
        row.innerHTML = `<div><strong>${escapeHtml(String(check.id || '').replace(/_/g,' '))}</strong><div class="hint">${escapeHtml(check.detail || '')}</div></div><span class="consumer-chip ${check.state === 'checked' ? 'ok' : 'warning'}">${escapeHtml(String(check.state || '').replace(/_/g,' '))}</span>`;
        security.append(row);
      }
      if (!(mailbox.indicators || []).length && !(mailbox.providerChecks || []).length) security.innerHTML='<div class="hint">No Health result yet.</div>';
    }
    const footprintList = document.getElementById('consumerFootprint');
    if (footprintList) {
      footprintList.replaceChildren();
      for (const entry of (footprint.entries || []).slice(0, 30)) {
        const row=document.createElement('div'); row.className='consumer-list-item';
        row.innerHTML=`<div><strong>${escapeHtml(entry.serviceDomain)}</strong><div class="hint">${escapeHtml(String(entry.evidenceKind || '').replace(/_/g,' '))} · ${Number(entry.messages || 0)} evidence message(s)</div></div>`;
        footprintList.append(row);
      }
      if (!(footprint.entries || []).length) footprintList.innerHTML='<div class="hint">No authenticated account-footprint evidence found in the bounded sample.</div>';
    }
  }

  async function runHealth() {
    let id = null;
    const healthRequestGenerationAtStart = ++healthRequestGeneration;
    try {
      id = selectedSessionOrThrow();
      setHealthStatus('Inspecting bounded mailbox health locally…');
      const result = await post(`/api/consumer/v1/accounts/${encodeURIComponent(id)}/health`);
      if (healthRequestGenerationAtStart !== healthRequestGeneration) return;
      if (!stillSelected(id)) return;
      renderHealth(result, id);
      setHealthStatus('Health check complete. Unsupported provider checks remain explicitly marked unavailable.');
    } catch (error) {
      if (healthRequestGenerationAtStart !== healthRequestGeneration) return;
      if (!id || stillSelected(id)) setHealthStatus(error.message || String(error), true);
    }
  }

  async function loadConsumerState() {
    const id = activeMailboxId();
    if (!id) { bindSelectedAccount(null); return; }
    bindSelectedAccount(id);
    try {
      const consumer = await json(await fetch(`/api/consumer/v1/accounts/${encodeURIComponent(id)}/state`));
      if (!stillSelected(id)) return;
      state.consumer = consumer;
      const check=document.getElementById('consumerRicherNotifications'); if (check instanceof HTMLInputElement) check.checked=consumer.richerLocalNotifications===true;
      const status=document.getElementById('consumerSensitivityStatus'); if(status) status.textContent=`Current: ${String(consumer.sensitivity || 'balanced').replace(/_/g,' ')}`;
    } catch {}
  }

  async function loadActivity() {
    const id=activeMailboxId();
    if(!id) { bindSelectedAccount(null); return; }
    bindSelectedAccount(id);
    const list=document.getElementById('consumerActivityList'); if(!list) return;
    try {
      const body=await json(await fetch(`/api/consumer/v1/accounts/${encodeURIComponent(id)}/activity`));
      if (!stillSelected(id)) return;
      list.replaceChildren();
      for (const item of body.activity || []) {
        const row=document.createElement('div'); row.className='consumer-list-item';
        const info=document.createElement('div');
        info.innerHTML=`<strong>${escapeHtml(item.title)}</strong><div class="hint">${escapeHtml(item.detail || '')}</div><div class="hint">${new Date(item.createdAt).toLocaleString()}${item.provider ? ` · ${escapeHtml(item.provider)}` : ''}</div>`;
        const controls=document.createElement('div');
        if(item.undoAvailable){const undo=document.createElement('button');undo.type='button';undo.textContent='Undo';undo.addEventListener('click',async()=>{if(!stillSelected(id)){document.getElementById('consumerActivityStatus').textContent='Mailbox selection changed. Refresh Activity before using Undo.';return;}try{await post(`/api/consumer/v1/accounts/${encodeURIComponent(id)}/activity/${encodeURIComponent(item.activityId)}/undo`);if(stillSelected(id))await loadActivity();}catch(error){if(stillSelected(id))document.getElementById('consumerActivityStatus').textContent=error.message||String(error);}});controls.append(undo);}
        row.append(info,controls); list.append(row);
      }
      if (!(body.activity || []).length) list.innerHTML='<div class="hint">No local protection activity yet.</div>';
    } catch (error) { if(stillSelected(id)) document.getElementById('consumerActivityStatus').textContent=error.message||String(error); }
  }

  async function loadFamily() {
    try {
      const [family, radar]=await Promise.all([
        json(await fetch('/api/consumer/v1/family/summary')),
        json(await fetch('/api/consumer/v1/radar')),
      ]);
      state.family=family; state.radar=radar;
      const summary=document.getElementById('consumerFamilySummary');
      if(summary) summary.innerHTML=`<div class="consumer-stat"><span>Protected members</span><strong>${Number(family.membersProtected||0)}</strong></div><div class="consumer-stat"><span>Seats</span><strong>${Number(family.seatLimit||0)}</strong></div><div class="consumer-stat"><span>Warnings</span><strong>${Number(family.warningCampaigns||0)}</strong></div><div class="consumer-stat"><span>Confirmed</span><strong>${Number(family.confirmedCampaigns||0)}</strong></div>`;
      const radarList=document.getElementById('consumerRadar'); if(radarList){radarList.replaceChildren(); if(!radar.available)radarList.innerHTML=`<div class="hint">${escapeHtml(radar.reason||'Verified campaign intelligence is unavailable.')}</div>`; else for(const item of radar.advisories||[]){const row=document.createElement('div');row.className='consumer-list-item';row.innerHTML=`<div><strong>${escapeHtml(item.severity)} campaign advisory</strong><div class="hint">${escapeHtml(item.guidance)}</div></div><span class="consumer-chip ${item.severity==='confirmed'?'critical':'warning'}">${Number(item.independentReports||0)} reports</span>`;radarList.append(row);} if(radar.available&&!(radar.advisories||[]).length)radarList.innerHTML='<div class="hint">No verified multi-report campaign advisory is active.</div>';}
    } catch (error) { const radarList=document.getElementById('consumerRadar'); if(radarList) radarList.innerHTML=`<div class="hint">${escapeHtml(error.message||String(error))}</div>`; }
  }

  function downloadJson(name,data){const blob=new Blob([JSON.stringify(data,null,2)],{type:'application/json'});const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
  function escapeHtml(value){return String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}

  document.getElementById('consumerRunHealth')?.addEventListener('click',runHealth);
  document.getElementById('consumerRefreshHealth')?.addEventListener('click',()=>{const id=activeMailboxId();if(id&&state.health&&state.healthAccountId===id)renderHealth(state.health,id);});
  document.getElementById('consumerRefreshActivity')?.addEventListener('click',loadActivity);
  document.getElementById('consumerRefreshFamily')?.addEventListener('click',loadFamily);
  document.getElementById('consumerClearActivity')?.addEventListener('click',async()=>{const id=activeMailboxId();if(!id)return;const confirmation=prompt('Type CLEAR ACTIVITY to delete local activity history');if(confirmation!=='CLEAR ACTIVITY'||activeMailboxId()!==id)return;try{await json(await fetch(`/api/consumer/v1/accounts/${encodeURIComponent(id)}/activity`,{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({confirmation})}));if(activeMailboxId()===id)await loadActivity();}catch(error){if(activeMailboxId()===id)document.getElementById('consumerActivityStatus').textContent=error.message||String(error);}});
  document.querySelectorAll('[data-consumer-sensitivity]').forEach(button=>button.addEventListener('click',async()=>{const id=selectedSessionOrThrow();try{const consumer=await post(`/api/consumer/v1/accounts/${encodeURIComponent(id)}/sensitivity`,{profile:button.dataset.consumerSensitivity});if(stillSelected(id)){state.consumer=consumer;await loadConsumerState();}}catch(error){if(stillSelected(id))document.getElementById('consumerSensitivityStatus').textContent=error.message||String(error);}}));
  document.getElementById('consumerRicherNotifications')?.addEventListener('change',async(event)=>{const id=selectedSessionOrThrow();try{await post(`/api/consumer/v1/accounts/${encodeURIComponent(id)}/notifications`,{richerLocalNotifications:event.target.checked});}catch(error){if(stillSelected(id))event.target.checked=!event.target.checked;else void loadConsumerState();}});
  document.getElementById('consumerCheckBrowser')?.addEventListener('click',async()=>{const out=document.getElementById('consumerBrowserResult');try{const url=document.getElementById('consumerBrowserUrl').value;const result=await post('/api/consumer/v1/browser/check',{schemaVersion:1,url,context:'explicit_check'});out.textContent=`${result.disposition.toUpperCase()}: ${result.explanation}`;}catch(error){out.textContent=error.message||String(error);}});
  document.getElementById('consumerCheckIntervention')?.addEventListener('click',async()=>{const out=document.getElementById('consumerInterventionResult');try{const text=document.getElementById('consumerInterventionText').value;const result=await post('/api/consumer/v1/intervention/check',{text});out.textContent=result.recommendedAction;}catch(error){out.textContent=error.message||String(error);}});
  document.getElementById('consumerCheckExposure')?.addEventListener('click',async()=>{const out=document.getElementById('consumerExposureResult');try{const email=document.getElementById('consumerExposureEmail').value;if(!confirm('Check this email using the configured privacy-preserving exposure service? Only a short local hash prefix is sent.'))return;const result=await post('/api/consumer/v1/exposure/email',{email,consent:true});out.textContent=result.state==='unavailable'?result.limitations?.[0]||'Exposure service unavailable.':result.state==='exposed'?'Exposure evidence was found. Change reused credentials and review account security.':'No matching exposure was returned by the configured source. This is not proof the address was never exposed.';}catch(error){out.textContent=error.message||String(error);}});
  document.getElementById('consumerSupportBundle')?.addEventListener('click',async()=>{try{const bundle=await json(await fetch('/api/consumer/v1/support-bundle'));downloadJson(`email-shield-support-${new Date().toISOString().slice(0,10)}.json`,bundle);}catch(error){alert(error.message||String(error));}});

  window.addEventListener('email-shield-profile-changed',()=>{void loadConsumerState();void loadFamily();});
  const observer=new MutationObserver(()=>{const id=activeMailboxId();if(id!==state.accountId){bindSelectedAccount(id);if(id){void loadConsumerState();void loadActivity();}}}); observer.observe(document.getElementById('accountsList')||document.body,{childList:true,subtree:true,attributes:true,attributeFilter:['class','aria-current']});

  async function maybeOnboard(){
    const id=activeMailboxId();
    if(!id)return;
    bindSelectedAccount(id);
    await loadConsumerState();
    if(!stillSelected(id))return;
    if(state.consumer?.onboarding?.dismissedAt||state.consumer?.onboarding?.completedSteps?.includes('consumer_intro'))return;
    const overlay=document.createElement('div');overlay.className='consumer-onboarding';overlay.innerHTML=`<div class="consumer-onboarding-card"><h2>Email Shield is protecting this mailbox</h2><p>Your mailbox stays with your provider. Email Shield reads bounded mail locally when protection runs, keeps provider secrets in the operating system credential vault, and sends only privacy-reduced threat evidence when Community or Family sharing is enabled.</p><div class="consumer-step"><strong>1. Protection runs after restart</strong><p>Your approved mailbox connection is restored automatically while Email Shield is running.</p></div><div class="consumer-step"><strong>2. Hard threats stay hard</strong><p>Sensitivity changes borderline attention, not authentication failures, verified threats or your explicit Block/Catch & Trash rules.</p></div><div class="consumer-step"><strong>3. Unknown is not Safe</strong><p>If a provider check, exposure service or media detector is unavailable, Email Shield tells you it is unavailable instead of displaying a green result.</p></div><div class="consumer-actions"><button id="consumerOnboardingDone" class="primary" type="button">Got it — continue</button></div></div>`;
    document.body.append(overlay);
    overlay.querySelector('#consumerOnboardingDone')?.addEventListener('click',async()=>{
      if(!stillSelected(id)){overlay.remove();return;}
      try{await post(`/api/consumer/v1/accounts/${encodeURIComponent(id)}/onboarding`,{completedSteps:['consumer_intro'],dismissed:true});overlay.remove();if(stillSelected(id))await loadConsumerState();}catch(error){if(stillSelected(id))alert(error.message||String(error));}
    });
  }
  setTimeout(()=>{const id=activeMailboxId();bindSelectedAccount(id);void loadConsumerState();void loadActivity();void loadFamily();void maybeOnboard();},400);
})();