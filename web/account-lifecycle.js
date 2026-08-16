(() => {
  const installedModules = window.emailShieldInstalledModules ||= new Set();
  if (installedModules.has('account-lifecycle')) return;
  installedModules.add('account-lifecycle');

  const signedIn = document.getElementById('accountSignedIn');
  if (!signedIn) return;

  const style = document.createElement('style');
  style.textContent = `
    .account-lifecycle-card{margin:0 0 14px}.account-lifecycle-actions{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.account-lifecycle-actions button.danger{border-color:var(--confirmed);background:var(--confirmed);color:#fff}
    .account-lifecycle-actions select{max-width:260px;padding:7px;border:1px solid var(--border);border-radius:6px;background:var(--surface);color:var(--text)}
    .account-lifecycle-help{margin:0;color:var(--text-muted);font-size:11px;line-height:1.55}.account-lifecycle-status{min-height:18px;font-size:11px;color:var(--text-muted)}.account-lifecycle-status.error{color:var(--confirmed)}.account-lifecycle-status.ok{color:var(--safe)}
    .account-lifecycle-recovery{border:1px solid var(--review);background:rgba(232,178,61,.08);padding:10px;border-radius:7px;font-size:11px;line-height:1.5}.account-lifecycle-recovery code{display:block;margin:7px 0;overflow-wrap:anywhere;font-size:12px}
  `;
  document.head.append(style);

  const card = document.createElement('div');
  card.className = 'account-card account-lifecycle-card';
  card.innerHTML = `
    <h3>Account security & privacy</h3>
    <p class="account-lifecycle-help">These actions manage your Email Shield identity and trusted devices. They never delete your provider mailbox or upload mailbox content.</p>
    <div class="account-lifecycle-actions">
      <button id="accountRotateRecovery" type="button">Rotate recovery code</button>
      <button id="accountRevokeOthers" type="button">Revoke other devices</button>
      <button id="accountExportMetadata" type="button">Export account metadata</button>
      <button id="accountSignOutEverywhere" type="button">Sign out everywhere</button>
      <select id="accountTransferTarget" aria-label="New Family Shield owner" hidden></select>
      <button id="accountTransferFamily" type="button" hidden>Transfer Family Shield</button>
      <button id="accountDeleteFamily" class="danger" type="button" hidden>Delete Family Shield</button>
      <button id="accountDeleteProfile" class="danger" type="button">Delete Email Shield account</button>
    </div>
    <p id="accountTransferHelp" class="account-lifecycle-help" hidden>The new owner must already be a member and have an active Family plan with enough seats. Store subscriptions are never reassigned automatically.</p>
    <div id="accountLifecycleStatus" class="account-lifecycle-status" role="status" aria-live="polite"></div>
    <div id="accountLifecycleRecovery" class="account-lifecycle-recovery" hidden></div>
  `;
  signedIn.append(card);

  const rotateRecovery = card.querySelector('#accountRotateRecovery');
  const revokeOthers = card.querySelector('#accountRevokeOthers');
  const exportMetadata = card.querySelector('#accountExportMetadata');
  const signOutEverywhere = card.querySelector('#accountSignOutEverywhere');
  const transferTarget = card.querySelector('#accountTransferTarget');
  const transferFamily = card.querySelector('#accountTransferFamily');
  const transferHelp = card.querySelector('#accountTransferHelp');
  const deleteFamily = card.querySelector('#accountDeleteFamily');
  const deleteProfile = card.querySelector('#accountDeleteProfile');
  const status = card.querySelector('#accountLifecycleStatus');
  const recovery = card.querySelector('#accountLifecycleRecovery');
  let snapshot = null;

  function setStatus(message, kind = '') {
    status.textContent = message;
    status.className = `account-lifecycle-status${kind ? ` ${kind}` : ''}`;
  }

  function checkpoint(workflowId, checkpointId, outcome = 'success', errorCode) {
    const trace = window.emailShieldRuntimeTrace;
    if (trace?.currentWorkflowId?.() !== workflowId) return;
    trace.checkpoint(checkpointId, outcome, errorCode ? { errorCode } : undefined);
  }

  async function json(response) {
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || `Account lifecycle request failed (${response.status}).`);
    return body;
  }

  function refreshAccountPanel() {
    document.getElementById('accountPlanRefresh')?.click();
  }

  function currentIsOwner(value) {
    const accountId = value?.account?.accountId;
    return Boolean(accountId && value?.family?.members?.some((member) => member.accountId === accountId && member.role === 'owner'));
  }

  function renderTransferTargets(value) {
    transferTarget.replaceChildren();
    const accountId = value?.account?.accountId;
    const members = Array.isArray(value?.family?.members)
      ? value.family.members.filter((member) => member.accountId && member.accountId !== accountId && member.role === 'member')
      : [];
    for (const member of members) {
      const option = document.createElement('option');
      option.value = member.accountId;
      option.textContent = member.username || 'Family member';
      transferTarget.append(option);
    }
    return members.length;
  }

  function render() {
    const active = snapshot?.signedIn === true && snapshot.account;
    const owner = active && currentIsOwner(snapshot);
    const transferTargets = owner ? renderTransferTargets(snapshot) : 0;
    card.hidden = !active;
    deleteFamily.hidden = !owner;
    transferTarget.hidden = !owner || transferTargets === 0;
    transferFamily.hidden = !owner || transferTargets === 0;
    transferHelp.hidden = !owner || transferTargets === 0;
  }

  function showRecovery(code, notice) {
    recovery.replaceChildren();
    if (!code) { recovery.hidden = true; return; }
    recovery.hidden = false;
    const strong = document.createElement('strong');
    strong.textContent = 'New recovery code — save it now';
    const text = document.createElement('div');
    text.textContent = notice || 'The previous recovery code no longer works.';
    const value = document.createElement('code');
    value.textContent = code;
    const copy = document.createElement('button');
    copy.type = 'button';
    copy.textContent = 'Copy recovery code';
    window.emailShieldRuntimeTrace?.registerControl(copy, 'account.recovery.copy', 'account.recovery.copy', 'account_recovery_copy');
    copy.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(code);
        copy.textContent = 'Copied ✓';
        checkpoint('account.recovery.copy', 'account.recovery.copy.ui_confirmed');
      } catch {
        copy.textContent = 'Copy manually from the code above';
        checkpoint('account.recovery.copy', 'account.recovery.copy.ui_confirmed', 'failed', 'clipboard_failed');
      }
    });
    const saved = document.createElement('button');
    saved.type = 'button';
    saved.textContent = 'I saved it';
    window.emailShieldRuntimeTrace?.registerControl(saved, 'account.recovery.acknowledge', 'account.recovery.acknowledge', 'account_recovery_acknowledge');
    saved.addEventListener('click', () => {
      recovery.hidden = true;
      recovery.replaceChildren();
      checkpoint('account.recovery.acknowledge', 'account.recovery.acknowledge.ui_confirmed');
    });
    recovery.append(strong, text, value, copy, saved);
  }

  async function post(path, body = {}) {
    return json(await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }));
  }

  async function destroy(path, confirmation) {
    return json(await fetch(path, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ confirmation }),
    }));
  }

  rotateRecovery.addEventListener('click', async () => {
    if (!confirm('Rotate your Email Shield recovery code?\n\nThe previous recovery code will stop working immediately.')) return;
    rotateRecovery.disabled = true;
    try {
      const result = await post('/api/profile/v1/recovery/rotate');
      showRecovery(result.recoveryCode, result.recoveryCodeNotice);
      setStatus('Recovery code rotated. Save the replacement before closing it.', 'ok');
      checkpoint('account.recovery.rotate', 'account.recovery.rotate.ui_confirmed');
    } catch (error) {
      setStatus(error.message || String(error), 'error');
      checkpoint('account.recovery.rotate', 'account.recovery.rotate.ui_confirmed', 'failed', 'recovery_rotate_failed');
    } finally { rotateRecovery.disabled = false; }
  });

  revokeOthers.addEventListener('click', async () => {
    if (!confirm('Revoke every other trusted Email Shield device?\n\nThis device will remain signed in.')) return;
    revokeOthers.disabled = true;
    try {
      const result = await post('/api/profile/v1/devices/revoke-others');
      setStatus(`${result.revoked || 0} other device${result.revoked === 1 ? '' : 's'} revoked.`, 'ok');
      refreshAccountPanel();
      checkpoint('account.devices.revoke_others', 'account.devices.revoke_others.ui_confirmed');
    } catch (error) {
      setStatus(error.message || String(error), 'error');
      checkpoint('account.devices.revoke_others', 'account.devices.revoke_others.ui_confirmed', 'failed', 'device_revoke_others_failed');
    } finally { revokeOthers.disabled = false; }
  });

  exportMetadata.addEventListener('click', async () => {
    exportMetadata.disabled = true;
    try {
      const data = await json(await fetch('/api/profile/v1/export'));
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const href = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = href;
      anchor.download = `email-shield-account-${Date.now()}.json`;
      anchor.rel = 'noopener';
      document.body.append(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(href);
      setStatus('Privacy-safe account metadata exported locally.', 'ok');
      checkpoint('account.metadata.export', 'account.metadata.export.ui_confirmed');
    } catch (error) {
      setStatus(error.message || String(error), 'error');
      checkpoint('account.metadata.export', 'account.metadata.export.ui_confirmed', 'failed', 'account_export_failed');
    } finally { exportMetadata.disabled = false; }
  });

  signOutEverywhere.addEventListener('click', async () => {
    if (!confirm('Sign out every Email Shield device, including this one?\n\nYou will need your recovery code to regain access.')) return;
    signOutEverywhere.disabled = true;
    try {
      const result = await post('/api/profile/v1/sign-out-everywhere');
      setStatus(`${result.revoked || 0} device${result.revoked === 1 ? '' : 's'} signed out. Reloading…`, 'ok');
      checkpoint('account.sign_out_everywhere', 'account.sign_out_everywhere.ui_confirmed');
      window.setTimeout(() => window.location.reload(), 250);
    } catch (error) {
      setStatus(error.message || String(error), 'error');
      checkpoint('account.sign_out_everywhere', 'account.sign_out_everywhere.ui_confirmed', 'failed', 'sign_out_everywhere_failed');
      signOutEverywhere.disabled = false;
    }
  });

  transferFamily.addEventListener('click', async () => {
    const targetAccountId = transferTarget.value;
    const targetName = transferTarget.options[transferTarget.selectedIndex]?.textContent || 'the selected member';
    if (!targetAccountId) {
      setStatus('Choose a Family Shield member first.', 'error');
      checkpoint('family.transfer', 'family.transfer.ui_confirmed', 'rejected', 'transfer_target_missing');
      return;
    }
    const typed = prompt(`Transfer Family Shield ownership to ${targetName}?\n\nThe member must already have an active Family plan with enough seats. Your store subscription is not transferred.\n\nType TRANSFER FAMILY to continue.`);
    if (typed === null) return;
    if (typed !== 'TRANSFER FAMILY') {
      setStatus('Family Shield ownership was not transferred because the confirmation text did not match.', 'error');
      checkpoint('family.transfer', 'family.transfer.ui_confirmed', 'rejected', 'confirmation_mismatch');
      return;
    }
    transferFamily.disabled = true;
    try {
      const result = await post('/api/profile/v1/family/transfer', { targetAccountId, confirmation: typed });
      setStatus(`Family Shield ownership transferred to ${targetName}. Seat limit: ${result.seatLimit}.`, 'ok');
      refreshAccountPanel();
      window.dispatchEvent(new CustomEvent('email-shield-family-changed'));
      checkpoint('family.transfer', 'family.transfer.ui_confirmed');
    } catch (error) {
      setStatus(error.message || String(error), 'error');
      checkpoint('family.transfer', 'family.transfer.ui_confirmed', 'failed', 'family_transfer_failed');
    } finally { transferFamily.disabled = false; }
  });

  deleteFamily.addEventListener('click', async () => {
    const typed = prompt('Deleting Family Shield releases every member and removes the private family threat history.\n\nType DELETE FAMILY to continue.');
    if (typed === null) return;
    if (typed !== 'DELETE FAMILY') {
      setStatus('Family Shield was not deleted because the confirmation text did not match.', 'error');
      checkpoint('account.family.delete', 'account.family.delete.ui_confirmed', 'rejected', 'confirmation_mismatch');
      return;
    }
    deleteFamily.disabled = true;
    try {
      const result = await destroy('/api/profile/v1/family', typed);
      setStatus(`Family Shield deleted. ${result.releasedMembers || 0} member record${result.releasedMembers === 1 ? '' : 's'} released.`, 'ok');
      refreshAccountPanel();
      window.dispatchEvent(new CustomEvent('email-shield-family-changed'));
      checkpoint('account.family.delete', 'account.family.delete.ui_confirmed');
    } catch (error) {
      setStatus(error.message || String(error), 'error');
      checkpoint('account.family.delete', 'account.family.delete.ui_confirmed', 'failed', 'family_delete_failed');
    } finally { deleteFamily.disabled = false; }
  });

  deleteProfile.addEventListener('click', async () => {
    const typed = prompt('Delete your Email Shield account profile?\n\nThis does NOT delete your Gmail/Outlook/iCloud/Yahoo/IMAP mailbox. If you own Family Shield, delete or transfer it first.\n\nType DELETE ACCOUNT to continue.');
    if (typed === null) return;
    if (typed !== 'DELETE ACCOUNT') {
      setStatus('Email Shield account was not deleted because the confirmation text did not match.', 'error');
      checkpoint('account.delete', 'account.delete.ui_confirmed', 'rejected', 'confirmation_mismatch');
      return;
    }
    deleteProfile.disabled = true;
    try {
      const result = await destroy('/api/profile/v1/account', typed);
      setStatus(result.notice || 'Email Shield account deleted. Your provider mailbox remains connected separately.', 'ok');
      checkpoint('account.delete', 'account.delete.ui_confirmed');
      window.setTimeout(() => window.location.reload(), 350);
    } catch (error) {
      setStatus(error.message || String(error), 'error');
      checkpoint('account.delete', 'account.delete.ui_confirmed', 'failed', 'account_delete_failed');
      deleteProfile.disabled = false;
    }
  });

  window.addEventListener('email-shield-profile-changed', (event) => {
    snapshot = event.detail || null;
    render();
  });

  card.hidden = true;
})();
