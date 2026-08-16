(() => {
  const installedModules = window.emailShieldInstalledModules ||= new Set();
  if (installedModules.has('family-shield')) return;
  installedModules.add('family-shield');

  const panel = document.createElement('section');
  panel.className = 'panel family-shield-panel';
  panel.id = 'familyShieldPanel';
  panel.dataset.appRoute = 'family';
  panel.setAttribute('aria-labelledby', 'familyShieldHeading');
  panel.innerHTML = `
    <div class="family-heading-row">
      <div>
        <h2 id="familyShieldHeading">Family Shield</h2>
        <p class="family-intro">Create a private Shield Circle for family members. Email bodies, subjects, mailbox addresses, contacts, provider IDs and raw URLs are never shared with family members. Family protection uses privacy-reduced campaign fingerprints only.</p>
      </div>
      <button id="familyRefresh" type="button">Refresh</button>
    </div>
    <div id="familyStatus" class="family-status" role="status" aria-live="polite"></div>
    <div id="familySignedOut" class="family-empty">Sign in to an Email Shield account to use Family Shield.</div>
    <div id="familyNoCircle" hidden>
      <div class="family-grid">
        <div class="family-card">
          <h3>Create a Shield Circle</h3>
          <p>Requires an active Family plan. The owner controls seats and Strict Family Protection.</p>
          <button id="familyCreate" class="primary" type="button">Create Family Shield</button>
        </div>
        <div class="family-card">
          <h3>Join a family</h3>
          <label class="field" for="familyInviteCode"><span>One-time invitation code</span><input id="familyInviteCode" autocomplete="off" /></label>
          <button id="familyJoin" type="button">Join Family Shield</button>
        </div>
      </div>
    </div>
    <div id="familyCircle" hidden>
      <div class="family-summary-grid">
        <div class="family-card"><span class="family-card-label">Seats</span><strong id="familySeats"></strong></div>
        <div class="family-card"><span class="family-card-label">Family threat campaigns</span><strong id="familyThreats"></strong></div>
        <div class="family-card"><span class="family-card-label">Warnings</span><strong id="familyWarnings"></strong></div>
        <div class="family-card"><span class="family-card-label">Confirmed</span><strong id="familyConfirmed"></strong></div>
      </div>
      <div class="family-toolbar">
        <button id="familyInvite" type="button">Invite family member</button>
        <button id="familyStrict" type="button" aria-pressed="false">Strict Family Protection: Off</button>
        <button id="familyLeave" type="button">Leave Family Shield</button>
      </div>
      <div id="familyInviteResult" class="family-invite-result" hidden></div>
      <div class="family-card">
        <h3>Protected members</h3>
        <div id="familyMembers" class="family-member-list"></div>
      </div>
      <div class="family-card family-how-it-works">
        <h3>Protection ladder</h3>
        <div><strong>Personal report:</strong> your matching future messages go to Trash immediately.</div>
        <div><strong>Family warning:</strong> one family report/block warns the Shield Circle and matching mail is reversibly moved to Spam/Junk.</div>
        <div><strong>Family confirmed:</strong> two independent family confirmations, or the owner/Strict Family rule, moves matching mail to Trash for the whole circle.</div>
        <div><strong>Global community:</strong> Family Shield never promotes itself into global consensus. Public community thresholds remain separate.</div>
      </div>
    </div>
  `;

  const style = document.createElement('style');
  style.textContent = `
    .family-heading-row{display:flex;justify-content:space-between;gap:16px;align-items:flex-start}.family-intro{max-width:760px;color:var(--text-muted);font-size:12px;line-height:1.55;margin:0 0 14px}
    .family-status{min-height:20px;margin:8px 0 12px;color:var(--text-muted);font-size:12px}.family-status.error{color:var(--confirmed)}.family-status.ok{color:var(--safe)}
    .family-grid,.family-summary-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin-bottom:14px}.family-summary-grid{grid-template-columns:repeat(4,minmax(0,1fr))}
    .family-card{border:1px solid var(--border);background:var(--panel-raised);border-radius:9px;padding:14px;display:flex;flex-direction:column;gap:8px}.family-card h3{margin:0;font-size:13px}.family-card p,.family-card div{font-size:12px;color:var(--text-muted);line-height:1.5}.family-card-label{font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--text-faint)}
    .family-toolbar{display:flex;gap:8px;flex-wrap:wrap;margin:8px 0 14px}.family-invite-result{border:1px solid var(--review);background:rgba(232,178,61,.08);border-radius:8px;padding:14px;margin-bottom:14px}.family-invite-result code{display:block;overflow-wrap:anywhere;margin:7px 0}
    .family-member-list{display:flex;flex-direction:column;gap:8px}.family-member-row{display:flex;align-items:center;justify-content:space-between;gap:10px;border-top:1px solid var(--border);padding-top:9px}.family-member-row:first-child{border-top:0;padding-top:0}.family-empty{padding:24px;text-align:center;color:var(--text-faint)}
    .family-how-it-works{margin-top:14px}.family-how-it-works strong{color:var(--text)}
    @media(max-width:900px){.family-summary-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:680px){.family-grid,.family-summary-grid{grid-template-columns:1fr}.family-heading-row,.family-member-row{flex-direction:column;align-items:flex-start}}
  `;
  document.head.appendChild(style);

  const scanPanel = document.getElementById('scanPanel');
  const accountPanel = document.getElementById('accountPlanPanel');
  if (accountPanel) accountPanel.insertAdjacentElement('beforebegin', panel);
  else if (scanPanel) scanPanel.insertAdjacentElement('afterend', panel);
  else document.querySelector('main')?.appendChild(panel);

  const status = panel.querySelector('#familyStatus');
  const signedOut = panel.querySelector('#familySignedOut');
  const noCircle = panel.querySelector('#familyNoCircle');
  const circle = panel.querySelector('#familyCircle');
  const create = panel.querySelector('#familyCreate');
  const join = panel.querySelector('#familyJoin');
  const inviteInput = panel.querySelector('#familyInviteCode');
  const invite = panel.querySelector('#familyInvite');
  const strict = panel.querySelector('#familyStrict');
  const leave = panel.querySelector('#familyLeave');
  const members = panel.querySelector('#familyMembers');
  const inviteResult = panel.querySelector('#familyInviteResult');
  const refresh = panel.querySelector('#familyRefresh');
  const seats = panel.querySelector('#familySeats');
  const threats = panel.querySelector('#familyThreats');
  const warnings = panel.querySelector('#familyWarnings');
  const confirmed = panel.querySelector('#familyConfirmed');
  let snapshot = null;

  function setStatus(message, kind = '') {
    status.textContent = message;
    status.className = `family-status${kind ? ` ${kind}` : ''}`;
  }

  function checkpoint(workflowId, checkpointId, outcome = 'success', errorCode) {
    const trace = window.emailShieldRuntimeTrace;
    if (trace?.currentWorkflowId?.() !== workflowId) return;
    trace.checkpoint(checkpointId, outcome, errorCode ? { errorCode } : undefined);
  }

  async function json(response) {
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || `Family Shield request failed (${response.status}).`);
    return body;
  }

  async function post(path, body = {}) {
    return json(await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }));
  }

  function render() {
    const signed = snapshot?.signedIn === true && snapshot.account;
    signedOut.hidden = Boolean(signed);
    noCircle.hidden = !signed || Boolean(snapshot?.family);
    circle.hidden = !signed || !snapshot?.family;
    if (!signed || !snapshot.family) return;

    const family = snapshot.family;
    const selfId = snapshot.account.accountId;
    const self = family.members.find((member) => member.accountId === selfId);
    const owner = self?.role === 'owner';
    seats.textContent = `${family.seatsUsed} / ${family.seatLimit || 'paused'}`;
    threats.textContent = String(family.threatCampaigns);
    warnings.textContent = String(family.warningCampaigns);
    confirmed.textContent = String(family.confirmedCampaigns);
    invite.hidden = !owner;
    strict.hidden = !owner;
    leave.hidden = owner;
    strict.setAttribute('aria-pressed', String(family.strictProtection));
    strict.textContent = `Strict Family Protection: ${family.strictProtection ? 'On' : 'Off'}`;

    members.replaceChildren();
    for (const member of family.members) {
      const row = document.createElement('div');
      row.className = 'family-member-row';
      const info = document.createElement('div');
      const title = document.createElement('strong');
      title.textContent = member.username;
      const detail = document.createElement('div');
      detail.className = 'hint';
      detail.textContent = `${member.role === 'owner' ? 'Owner' : 'Member'} · ${member.activeDevices} active device${member.activeDevices === 1 ? '' : 's'}${member.accountId === selfId ? ' · you' : ''}`;
      info.append(title, detail);
      row.append(info);
      if (owner && member.role !== 'owner') {
        const remove = document.createElement('button');
        remove.type = 'button';
        remove.textContent = 'Remove member';
        window.emailShieldRuntimeTrace?.registerControl(remove, 'family.remove_member', 'family.remove_member', 'family_remove_member');
        remove.addEventListener('click', async () => {
          if (!confirm(`Remove ${member.username} from Family Shield? Their future family protection will stop immediately.`)) return;
          try {
            snapshot = await json(await fetch(`/api/profile/v1/family/members/${encodeURIComponent(member.accountId)}`, { method: 'DELETE' }));
            setStatus(`${member.username} removed from Family Shield.`, 'ok');
            render();
            window.dispatchEvent(new CustomEvent('email-shield-family-changed'));
            checkpoint('family.remove_member', 'family.remove_member.ui_confirmed');
          } catch (error) {
            setStatus(error.message || String(error), 'error');
            checkpoint('family.remove_member', 'family.remove_member.ui_confirmed', 'failed', 'family_remove_member_failed');
          }
        });
        row.append(remove);
      }
      members.append(row);
    }
  }

  async function load() {
    try {
      snapshot = await json(await fetch('/api/profile/v1/snapshot'));
      if (!snapshot.signedIn) setStatus('Sign in to an Email Shield profile first.');
      else if (!snapshot.family) setStatus(snapshot.account.entitlement.plan === 'family'
        ? 'Family plan active. Create a new Shield Circle or join an existing one.'
        : 'Family Shield requires a Family plan to create a circle. You can still join an active family owner’s invitation.', '');
      else setStatus('Family Shield active. Only privacy-reduced campaign protection is shared.', 'ok');
      render();
      checkpoint('family.load', 'family.load.ui_confirmed');
    } catch (error) {
      setStatus(error.message || String(error), 'error');
      checkpoint('family.load', 'family.load.ui_confirmed', 'failed', 'family_load_failed');
    }
  }

  create.addEventListener('click', async () => {
    create.disabled = true;
    try {
      snapshot = await post('/api/profile/v1/family');
      setStatus('Family Shield circle created.', 'ok');
      render();
      window.dispatchEvent(new CustomEvent('email-shield-family-changed'));
      checkpoint('family.create', 'family.create.ui_confirmed');
    } catch (error) {
      setStatus(error.message || String(error), 'error');
      checkpoint('family.create', 'family.create.ui_confirmed', 'failed', 'family_create_failed');
    } finally { create.disabled = false; }
  });

  join.addEventListener('click', async () => {
    join.disabled = true;
    try {
      snapshot = await post('/api/profile/v1/family/join', { inviteCode: inviteInput.value });
      inviteInput.value = '';
      setStatus('Joined Family Shield. Link a mailbox from Account & Plan to receive family protection.', 'ok');
      render();
      window.dispatchEvent(new CustomEvent('email-shield-family-changed'));
      checkpoint('family.join', 'family.join.ui_confirmed');
    } catch (error) {
      setStatus(error.message || String(error), 'error');
      checkpoint('family.join', 'family.join.ui_confirmed', 'failed', 'family_join_failed');
    } finally { join.disabled = false; }
  });

  invite.addEventListener('click', async () => {
    invite.disabled = true;
    try {
      const result = await post('/api/profile/v1/family/invites');
      inviteResult.hidden = false;
      inviteResult.replaceChildren();
      const title = document.createElement('strong');
      title.textContent = 'One-time Family Shield invitation';
      const code = document.createElement('code');
      code.textContent = result.inviteCode;
      const expiry = document.createElement('div');
      expiry.textContent = `Expires ${new Date(result.expiresAt).toLocaleString()}. It contains no mailbox identity or email content.`;
      const copy = document.createElement('button');
      copy.type = 'button';
      copy.textContent = 'Copy invitation code';
      window.emailShieldRuntimeTrace?.registerControl(copy, 'family.invite.copy', 'family.invite.copy', 'family_invite_copy');
      copy.addEventListener('click', async () => {
        try {
          await navigator.clipboard.writeText(result.inviteCode);
          copy.textContent = 'Copied ✓';
          checkpoint('family.invite.copy', 'family.invite.copy.ui_confirmed');
        } catch {
          copy.textContent = 'Copy manually from the code above';
          checkpoint('family.invite.copy', 'family.invite.copy.ui_confirmed', 'failed', 'clipboard_failed');
        }
      });
      inviteResult.append(title, code, expiry, copy);
      setStatus('Invitation created. Share it directly with the intended family member.', 'ok');
      await load();
      checkpoint('family.invite', 'family.invite.ui_confirmed');
    } catch (error) {
      setStatus(error.message || String(error), 'error');
      checkpoint('family.invite', 'family.invite.ui_confirmed', 'failed', 'family_invite_failed');
    } finally { invite.disabled = false; }
  });

  strict.addEventListener('click', async () => {
    const enabled = strict.getAttribute('aria-pressed') !== 'true';
    const warning = enabled
      ? 'Enable Strict Family Protection?\n\nA single family Report Scam will become family-confirmed and matching mail can move to Trash for the entire Shield Circle. This does not affect global community users.'
      : 'Disable Strict Family Protection?\n\nIndependent family confirmations will again be required before family-wide automatic Trash.';
    if (!confirm(warning)) return;
    try {
      snapshot = await post('/api/profile/v1/family/strict', { enabled });
      setStatus(`Strict Family Protection ${enabled ? 'enabled' : 'disabled'}.`, 'ok');
      render();
      window.dispatchEvent(new CustomEvent('email-shield-family-changed'));
      checkpoint('family.strict', 'family.strict.ui_confirmed');
    } catch (error) {
      setStatus(error.message || String(error), 'error');
      checkpoint('family.strict', 'family.strict.ui_confirmed', 'failed', 'family_strict_failed');
    }
  });

  leave.addEventListener('click', async () => {
    if (!confirm('Leave this Family Shield circle? Family threat protection will stop for this account.')) return;
    try {
      snapshot = await post('/api/profile/v1/family/leave');
      setStatus('Left Family Shield.', 'ok');
      render();
      window.dispatchEvent(new CustomEvent('email-shield-family-changed'));
      checkpoint('family.leave', 'family.leave.ui_confirmed');
    } catch (error) {
      setStatus(error.message || String(error), 'error');
      checkpoint('family.leave', 'family.leave.ui_confirmed', 'failed', 'family_leave_failed');
    }
  });

  refresh.addEventListener('click', load);
  window.addEventListener('email-shield-profile-changed', load);
  void load();
})();
