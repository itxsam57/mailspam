(() => {
  const installedModules = window.emailShieldInstalledModules ||= new Set();
  if (installedModules.has('account-plan')) return;
  installedModules.add('account-plan');

  const panel = document.createElement('section');
  panel.className = 'panel account-plan-panel';
  panel.id = 'accountPlanPanel';
  panel.dataset.appRoute = 'account';
  panel.setAttribute('aria-labelledby', 'accountPlanHeading');
  panel.innerHTML = `
    <div class="account-plan-heading-row">
      <div>
        <h2 id="accountPlanHeading">Email Shield Account & Plan</h2>
        <p class="account-plan-intro">Your Email Shield identity is separate from connected mail providers. Device identity is app-generated; hardware IDs, IMEI, serial numbers and advertising IDs are not used.</p>
      </div>
      <button id="accountPlanRefresh" type="button">Refresh</button>
    </div>
    <div id="accountPlanStatus" class="account-plan-status" role="status" aria-live="polite"></div>
    <div id="accountSignedOut">
      <div class="account-grid">
        <div class="account-card">
          <h3>Create account</h3>
          <label class="field" for="accountCreateUsername"><span>Username</span><input id="accountCreateUsername" autocomplete="username" maxlength="32" /></label>
          <label class="field" for="accountDeviceLabel"><span>This device name</span><input id="accountDeviceLabel" value="My desktop" maxlength="64" /></label>
          <button id="accountCreate" class="primary" type="button">Create Email Shield account</button>
        </div>
        <div class="account-card">
          <h3>Sign in on this trusted device</h3>
          <label class="field" for="accountSignInUsername"><span>Username</span><input id="accountSignInUsername" autocomplete="username" maxlength="32" /></label>
          <button id="accountSignIn" type="button">Sign in</button>
          <button id="accountRecoverOpen" type="button">Recover account</button>
        </div>
      </div>
    </div>
    <div id="accountSignedIn" hidden>
      <div class="account-summary-grid">
        <div class="account-card"><span class="account-card-label">Username</span><strong id="accountUsername"></strong></div>
        <div class="account-card"><span class="account-card-label">Plan</span><strong id="accountPlan"></strong><span id="accountPlanState" class="hint"></span></div>
        <div class="account-card"><span class="account-card-label">This device</span><strong id="accountDeviceId" class="mono"></strong><span class="hint">Derived from Email Shield's cryptographic public key.</span></div>
        <div class="account-card"><span class="account-card-label">Account state</span><strong id="accountPersistence"></strong><span class="hint">Mail content is not stored in this account profile.</span></div>
      </div>
      <div id="accountRecoveryCode" class="account-recovery" hidden></div>
      <div class="account-actions-row">
        <button id="accountLinkMailbox" type="button">Link selected mailbox to this profile</button>
        <button id="accountSignOut" type="button">Sign out</button>
      </div>
      <div id="accountDevPlans" class="account-card account-dev-plans" hidden>
        <h3>Desktop acceptance plan preview</h3>
        <p>This control is enabled only by the local test environment. It does not represent a paid App Store, Google Play or web subscription.</p>
        <div class="row">
          <button type="button" data-dev-plan="free">Free</button>
          <button type="button" data-dev-plan="individual">Individual</button>
          <button type="button" data-dev-plan="family">Family (6 seats)</button>
        </div>
      </div>
      <div class="account-card">
        <h3>Registered devices</h3>
        <div id="accountDevices" class="account-device-list"></div>
      </div>
    </div>
  `;

  const style = document.createElement('style');
  style.textContent = `
    .account-plan-heading-row{display:flex;justify-content:space-between;gap:16px;align-items:flex-start}
    .account-plan-intro{max-width:720px;color:var(--text-muted);font-size:12px;line-height:1.55;margin:0 0 14px}
    .account-plan-status{min-height:20px;margin:8px 0 12px;color:var(--text-muted);font-size:12px}
    .account-plan-status.error{color:var(--confirmed)} .account-plan-status.ok{color:var(--safe)}
    .account-grid,.account-summary-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin-bottom:14px}
    .account-summary-grid{grid-template-columns:repeat(4,minmax(0,1fr))}
    .account-card{border:1px solid var(--border);background:var(--panel-raised);border-radius:9px;padding:14px;display:flex;flex-direction:column;gap:9px}
    .account-card h3{margin:0;font-size:13px}.account-card-label{font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--text-faint)}
    .account-actions-row{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0 14px}.account-recovery{border:1px solid var(--review);background:rgba(232,178,61,.08);padding:14px;border-radius:8px;margin:10px 0;line-height:1.5}
    .account-recovery code{display:block;overflow-wrap:anywhere;margin:8px 0;font-size:13px}.account-device-list{display:flex;flex-direction:column;gap:8px}
    .account-device-row{display:flex;justify-content:space-between;gap:10px;align-items:center;border-top:1px solid var(--border);padding-top:8px}.account-device-row:first-child{border-top:0;padding-top:0}
    .account-dev-plans{margin:0 0 14px;border-style:dashed}.account-dev-plans p{margin:0;color:var(--review);font-size:11px;line-height:1.5}
    @media(max-width:900px){.account-summary-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
    @media(max-width:680px){.account-grid,.account-summary-grid{grid-template-columns:1fr}.account-plan-heading-row{flex-direction:column}.account-device-row{align-items:flex-start;flex-direction:column}}
  `;
  document.head.appendChild(style);

  const scanPanel = document.getElementById('scanPanel');
  if (scanPanel) scanPanel.insertAdjacentElement('afterend', panel);
  else document.querySelector('main')?.appendChild(panel);

  const status = panel.querySelector('#accountPlanStatus');
  const signedOut = panel.querySelector('#accountSignedOut');
  const signedIn = panel.querySelector('#accountSignedIn');
  const refresh = panel.querySelector('#accountPlanRefresh');
  const create = panel.querySelector('#accountCreate');
  const createUsername = panel.querySelector('#accountCreateUsername');
  const deviceLabel = panel.querySelector('#accountDeviceLabel');
  const signIn = panel.querySelector('#accountSignIn');
  const signInUsername = panel.querySelector('#accountSignInUsername');
  const recoverOpen = panel.querySelector('#accountRecoverOpen');
  const username = panel.querySelector('#accountUsername');
  const plan = panel.querySelector('#accountPlan');
  const planState = panel.querySelector('#accountPlanState');
  const deviceId = panel.querySelector('#accountDeviceId');
  const persistence = panel.querySelector('#accountPersistence');
  const devices = panel.querySelector('#accountDevices');
  const signOut = panel.querySelector('#accountSignOut');
  const linkMailbox = panel.querySelector('#accountLinkMailbox');
  const devPlans = panel.querySelector('#accountDevPlans');
  const recovery = panel.querySelector('#accountRecoveryCode');
  let snapshot = null;

  function setStatus(message, kind = '') {
    status.textContent = message;
    status.className = `account-plan-status${kind ? ` ${kind}` : ''}`;
  }

  async function json(response) {
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || `Account request failed (${response.status}).`);
    return body;
  }

  async function post(path, body = {}) {
    return json(await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }));
  }

  function shortDevice(value) {
    const text = String(value || '');
    return text.length > 22 ? `${text.slice(0, 10)}…${text.slice(-8)}` : text;
  }

  function showRecovery(code, notice) {
    if (!code) { recovery.hidden = true; recovery.replaceChildren(); return; }
    recovery.hidden = false;
    recovery.replaceChildren();
    const strong = document.createElement('strong');
    strong.textContent = 'Save this recovery code now';
    const text = document.createElement('div');
    text.textContent = notice || 'Email Shield will not show this same code again.';
    const value = document.createElement('code');
    value.textContent = code;
    const copied = document.createElement('button');
    copied.type = 'button';
    copied.textContent = 'Copy recovery code';
    copied.addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(code); copied.textContent = 'Copied ✓'; }
      catch { copied.textContent = 'Copy manually from the code above'; }
    });
    const acknowledge = document.createElement('button');
    acknowledge.type = 'button';
    acknowledge.textContent = 'I saved it';
    acknowledge.addEventListener('click', () => { recovery.hidden = true; recovery.replaceChildren(); });
    recovery.append(strong, text, value, copied, acknowledge);
  }

  function render() {
    const signed = snapshot?.signedIn === true && snapshot.account;
    signedOut.hidden = Boolean(signed);
    signedIn.hidden = !signed;
    devPlans.hidden = !signed || snapshot?.developmentEntitlementsEnabled !== true;
    if (!signed) return;
    username.textContent = snapshot.account.username;
    plan.textContent = snapshot.account.entitlement.plan.replace(/^./, (letter) => letter.toUpperCase());
    planState.textContent = `${snapshot.account.entitlement.status} · ${snapshot.account.entitlement.source}`;
    deviceId.textContent = shortDevice(snapshot.deviceId);
    deviceId.title = snapshot.deviceId;
    persistence.textContent = snapshot.persistent ? 'Encrypted & persistent' : 'Memory-only';
    devices.replaceChildren();
    for (const item of snapshot.account.devices) {
      const row = document.createElement('div');
      row.className = 'account-device-row';
      const info = document.createElement('div');
      const title = document.createElement('strong');
      title.textContent = item.label;
      const detail = document.createElement('div');
      detail.className = 'hint mono';
      detail.textContent = `${item.platform} · ${item.algorithm} · ${shortDevice(item.deviceId)}${item.deviceId === snapshot.deviceId ? ' · this device' : ''}${item.revoked ? ' · revoked' : ''}`;
      info.append(title, detail);
      row.append(info);
      if (!item.revoked && item.deviceId !== snapshot.deviceId) {
        const revoke = document.createElement('button');
        revoke.type = 'button';
        revoke.textContent = 'Revoke device';
        revoke.addEventListener('click', async () => {
          if (!confirm(`Revoke ${item.label}?`)) return;
          try {
            snapshot = await json(await fetch(`/api/profile/v1/devices/${encodeURIComponent(item.deviceId)}`, { method: 'DELETE' }));
            setStatus('Device revoked.', 'ok');
            render();
          } catch (error) { setStatus(error.message || String(error), 'error'); }
        });
        row.append(revoke);
      }
      devices.append(row);
    }
  }

  async function load() {
    try {
      const body = await json(await fetch('/api/profile/v1/snapshot'));
      snapshot = body;
      setStatus(body.signedIn
        ? `Signed in as ${body.account.username}. Mailbox content remains outside the account profile.`
        : 'Create or sign in to an Email Shield profile. Mail provider accounts remain separate.', body.signedIn ? 'ok' : '');
      render();
      window.dispatchEvent(new CustomEvent('email-shield-profile-changed', { detail: structuredClone(body) }));
    } catch (error) { setStatus(error.message || String(error), 'error'); }
  }

  create.addEventListener('click', async () => {
    create.disabled = true;
    setStatus('Creating cryptographic Email Shield account…');
    try {
      const result = await post('/api/profile/v1/accounts', {
        username: createUsername.value,
        deviceLabel: deviceLabel.value,
      });
      snapshot = { ...result.snapshot, persistent: true, developmentEntitlementsEnabled: snapshot?.developmentEntitlementsEnabled === true };
      showRecovery(result.recoveryCode, result.recoveryCodeNotice);
      setStatus('Account created. Save the recovery code before continuing.', 'ok');
      await load();
    } catch (error) { setStatus(error.message || String(error), 'error'); }
    finally { create.disabled = false; }
  });

  signIn.addEventListener('click', async () => {
    signIn.disabled = true;
    try {
      snapshot = await post('/api/profile/v1/sign-in', { username: signInUsername.value });
      setStatus('Signed in on this registered device.', 'ok');
      await load();
    } catch (error) { setStatus(error.message || String(error), 'error'); }
    finally { signIn.disabled = false; }
  });

  recoverOpen.addEventListener('click', async () => {
    const enteredUsername = prompt('Email Shield username');
    if (enteredUsername === null) return;
    const code = prompt('Recovery code');
    if (code === null) return;
    const label = prompt('Name this recovered device', 'Recovered desktop');
    if (label === null) return;
    try {
      const result = await post('/api/profile/v1/recover', { username: enteredUsername, recoveryCode: code, deviceLabel: label });
      showRecovery(result.recoveryCode, result.recoveryCodeNotice);
      setStatus('Account recovered and recovery code rotated.', 'ok');
      await load();
    } catch (error) { setStatus(error.message || String(error), 'error'); }
  });

  signOut.addEventListener('click', async () => {
    try {
      const response = await fetch('/api/profile/v1/sign-out', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
      if (!response.ok) throw new Error('Sign out failed.');
      showRecovery(null);
      await load();
    } catch (error) { setStatus(error.message || String(error), 'error'); }
  });

  linkMailbox.addEventListener('click', async () => {
    const selected = document.querySelector('#accountsList .account-chip.active')?.dataset.id;
    if (!selected) return setStatus('Select a connected mailbox first.', 'error');
    try {
      await post(`/api/profile/v1/mailboxes/${encodeURIComponent(selected)}/link`);
      setStatus('Selected mailbox linked to this Email Shield profile. Family threat rules can now protect it.', 'ok');
      window.dispatchEvent(new CustomEvent('email-shield-mailbox-profile-linked', { detail: { sessionId: selected } }));
    } catch (error) { setStatus(error.message || String(error), 'error'); }
  });

  devPlans.addEventListener('click', async (event) => {
    const button = event.target.closest('[data-dev-plan]');
    if (!(button instanceof HTMLButtonElement)) return;
    const targetPlan = button.dataset.devPlan;
    if (!confirm(`Switch this local acceptance profile to ${targetPlan}?\n\nThis is a development entitlement only and does not simulate payment.`)) return;
    try {
      await post('/api/profile/v1/entitlement/development', { plan: targetPlan });
      setStatus(`Development preview entitlement switched to ${targetPlan}.`, 'ok');
      await load();
    } catch (error) { setStatus(error.message || String(error), 'error'); }
  });

  refresh.addEventListener('click', load);
  window.addEventListener('email-shield-family-changed', load);
  void load();
})();
