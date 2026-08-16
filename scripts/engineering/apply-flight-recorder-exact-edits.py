from pathlib import Path

ROOT = Path.cwd()


def replace_once(path: str, label: str, before: str, after: str) -> None:
    target = ROOT / path
    source = target.read_text(encoding="utf-8")
    count = source.count(before)
    if count != 1:
        raise RuntimeError(f"{path}: expected exactly one source match for {label}, got {count}")
    target.write_text(source.replace(before, after, 1), encoding="utf-8")


# Central browser trace: correct account recovery semantics and add trusted
# change-event correlation without reading the changed value.
replace_once(
    "web/runtime-workflow-trace.js",
    "account recovery workflow",
    "    accountRecoverOpen: ['account.recovery.open', 'account.recovery.open', 'account_recovery_open'],",
    "    accountRecoverOpen: ['account.recovery.use', 'account.recovery.use', 'account_recovery'],",
)

replace_once(
    "web/runtime-workflow-trace.js",
    "trusted change listener",
    """  document.addEventListener('click', (event) => {
    if (event.isTrusted === false) return;
    const button = event.target instanceof Element ? event.target.closest('button') : null;
    if (!(button instanceof HTMLButtonElement) || button.disabled) return;
    const semantic = semanticControl(button);
    if (!semantic) return;
    begin(semantic.actionId, semantic.workflowId, semantic.expectedWorkflow, semantic.provider || providerFor(button));
  }, true);

  Object.defineProperty(window, 'emailShieldRuntimeTrace', {""",
    """  document.addEventListener('click', (event) => {
    if (event.isTrusted === false) return;
    const button = event.target instanceof Element ? event.target.closest('button') : null;
    if (!(button instanceof HTMLButtonElement) || button.disabled) return;
    const semantic = semanticControl(button);
    if (!semantic) return;
    begin(semantic.actionId, semantic.workflowId, semantic.expectedWorkflow, semantic.provider || providerFor(button));
  }, true);

  document.addEventListener('change', (event) => {
    if (event.isTrusted === false) return;
    const control = event.target instanceof Element ? event.target : null;
    if (!(control instanceof HTMLInputElement || control instanceof HTMLSelectElement) || control.disabled) return;
    const bound = registeredElements.get(control) || (control.id ? registeredById.get(control.id) : null);
    if (!bound) return;
    begin(bound.actionId, bound.workflowId, bound.expectedWorkflow, bound.provider || providerFor(control));
  }, true);

  Object.defineProperty(window, 'emailShieldRuntimeTrace', {""",
)

# Consumer product helper.
replace_once(
    "web/consumer-product.js",
    "consumer checkpoint helper",
    """  const state = {
    accountId: null,
    consumer: null,
    health: null,
    healthAccountId: null,
    family: null,
    radar: null,
  };
""",
    """  const state = {
    accountId: null,
    consumer: null,
    health: null,
    healthAccountId: null,
    family: null,
    radar: null,
  };

  function checkpoint(workflowId, checkpointId, outcome = 'success', errorCode) {
    const trace = window.emailShieldRuntimeTrace;
    if (trace?.currentWorkflowId?.() !== workflowId) return;
    trace.checkpoint(checkpointId, outcome, errorCode ? { errorCode } : undefined);
  }
""",
)

replace_once(
    "web/consumer-product.js",
    "fixture button trace registration",
    """      fixture.type = 'button';
      fixture.textContent = 'Use fixture mode';""",
    """      fixture.type = 'button';
      fixture.textContent = 'Use fixture mode';
      window.emailShieldRuntimeTrace?.registerControl(fixture, 'developer.mode.select', 'developer.mode.select', 'developer_mode_select');""",
)

replace_once(
    "web/consumer-product.js",
    "cleanup button trace registration",
    """        const cleanup = document.createElement('button'); cleanup.type = 'button'; cleanup.textContent = 'Clean old mail';
        cleanup.addEventListener('click', async () => {""",
    """        const cleanup = document.createElement('button'); cleanup.type = 'button'; cleanup.textContent = 'Clean old mail';
        window.emailShieldRuntimeTrace?.registerControl(cleanup, 'mailbox.cleanup', 'mailbox.cleanup', 'mailbox_cleanup');
        cleanup.addEventListener('click', async () => {""",
)

replace_once(
    "web/consumer-product.js",
    "cleanup stale selection",
    """          if (!stillSelected(accountId)) {
            setHealthStatus('Mailbox selection changed. Run Health again before cleaning mail.', true);
            return;
          }""",
    """          if (!stillSelected(accountId)) {
            setHealthStatus('Mailbox selection changed. Run Health again before cleaning mail.', true);
            checkpoint('mailbox.cleanup', 'mailbox.cleanup.ui_confirmed', 'rejected', 'stale_selection');
            return;
          }""",
)

replace_once(
    "web/consumer-product.js",
    "cleanup result",
    """            setHealthStatus(`${cleanupResult.movedToTrash} message(s) moved to Trash.${cleanupResult.undoAvailable ? ' Undo is available in Activity for 30 minutes.' : ''}`);
            await loadActivity();
          } catch (error) {
            if (stillSelected(accountId)) setHealthStatus(error.message || String(error), true);
          }""",
    """            setHealthStatus(`${cleanupResult.movedToTrash} message(s) moved to Trash.${cleanupResult.undoAvailable ? ' Undo is available in Activity for 30 minutes.' : ''}`);
            await loadActivity();
            checkpoint('mailbox.cleanup', 'mailbox.cleanup.ui_confirmed');
          } catch (error) {
            if (stillSelected(accountId)) setHealthStatus(error.message || String(error), true);
            checkpoint('mailbox.cleanup', 'mailbox.cleanup.ui_confirmed', 'failed', 'mailbox_cleanup_failed');
          }""",
)

replace_once(
    "web/consumer-product.js",
    "health result",
    """      renderHealth(result, id);
      setHealthStatus('Health check complete. Unsupported provider checks remain explicitly marked unavailable.');
    } catch (error) {
      if (!id || stillSelected(id)) setHealthStatus(error.message || String(error), true);
    }""",
    """      renderHealth(result, id);
      setHealthStatus('Health check complete. Unsupported provider checks remain explicitly marked unavailable.');
      checkpoint('mailbox.health.run', 'mailbox.health.run.ui_confirmed');
    } catch (error) {
      if (!id || stillSelected(id)) setHealthStatus(error.message || String(error), true);
      checkpoint('mailbox.health.run', 'mailbox.health.run.ui_confirmed', 'failed', id ? 'mailbox_health_failed' : 'account_not_selected');
    }""",
)

replace_once(
    "web/consumer-product.js",
    "undo dynamic control",
    """        if(item.undoAvailable){const undo=document.createElement('button');undo.type='button';undo.textContent='Undo';undo.addEventListener('click',async()=>{if(!stillSelected(id)){document.getElementById('consumerActivityStatus').textContent='Mailbox selection changed. Refresh Activity before using Undo.';return;}try{await post(`/api/consumer/v1/accounts/${encodeURIComponent(id)}/activity/${encodeURIComponent(item.activityId)}/undo`);if(stillSelected(id))await loadActivity();}catch(error){if(stillSelected(id))document.getElementById('consumerActivityStatus').textContent=error.message||String(error);}});controls.append(undo);}""",
    """        if(item.undoAvailable){const undo=document.createElement('button');undo.type='button';undo.textContent='Undo';window.emailShieldRuntimeTrace?.registerControl(undo,'message.undo','message.undo','provider_undo');undo.addEventListener('click',async()=>{if(!stillSelected(id)){document.getElementById('consumerActivityStatus').textContent='Mailbox selection changed. Refresh Activity before using Undo.';checkpoint('message.undo','message.undo.ui_confirmed','rejected','stale_selection');return;}try{await post(`/api/consumer/v1/accounts/${encodeURIComponent(id)}/activity/${encodeURIComponent(item.activityId)}/undo`);if(stillSelected(id))await loadActivity();checkpoint('message.undo','message.undo.ui_confirmed');}catch(error){if(stillSelected(id))document.getElementById('consumerActivityStatus').textContent=error.message||String(error);checkpoint('message.undo','message.undo.ui_confirmed','failed','undo_failed');}});controls.append(undo);}""",
)

replace_once(
    "web/consumer-product.js",
    "activity load result",
    """      if (!(body.activity || []).length) list.innerHTML='<div class="hint">No local protection activity yet.</div>';
    } catch (error) { if(stillSelected(id)) document.getElementById('consumerActivityStatus').textContent=error.message||String(error); }""",
    """      if (!(body.activity || []).length) list.innerHTML='<div class="hint">No local protection activity yet.</div>';
      checkpoint('activity.load', 'activity.load.ui_confirmed');
    } catch (error) { if(stillSelected(id)) document.getElementById('consumerActivityStatus').textContent=error.message||String(error); checkpoint('activity.load', 'activity.load.ui_confirmed', 'failed', 'activity_load_failed'); }""",
)

replace_once(
    "web/consumer-product.js",
    "family load result",
    """      const radarList=document.getElementById('consumerRadar'); if(radarList){radarList.replaceChildren(); if(!radar.available)radarList.innerHTML=`<div class="hint">${escapeHtml(radar.reason||'Verified campaign intelligence is unavailable.')}</div>`; else for(const item of radar.advisories||[]){const row=document.createElement('div');row.className='consumer-list-item';row.innerHTML=`<div><strong>${escapeHtml(item.severity)} campaign advisory</strong><div class="hint">${escapeHtml(item.guidance)}</div></div><span class="consumer-chip ${item.severity==='confirmed'?'critical':'warning'}">${Number(item.independentReports||0)} reports</span>`;radarList.append(row);} if(radar.available&&!(radar.advisories||[]).length)radarList.innerHTML='<div class="hint">No verified multi-report campaign advisory is active.</div>';}
    } catch (error) { const radarList=document.getElementById('consumerRadar'); if(radarList) radarList.innerHTML=`<div class="hint">${escapeHtml(error.message||String(error))}</div>`; }""",
    """      const radarList=document.getElementById('consumerRadar'); if(radarList){radarList.replaceChildren(); if(!radar.available)radarList.innerHTML=`<div class="hint">${escapeHtml(radar.reason||'Verified campaign intelligence is unavailable.')}</div>`; else for(const item of radar.advisories||[]){const row=document.createElement('div');row.className='consumer-list-item';row.innerHTML=`<div><strong>${escapeHtml(item.severity)} campaign advisory</strong><div class="hint">${escapeHtml(item.guidance)}</div></div><span class="consumer-chip ${item.severity==='confirmed'?'critical':'warning'}">${Number(item.independentReports||0)} reports</span>`;radarList.append(row);} if(radar.available&&!(radar.advisories||[]).length)radarList.innerHTML='<div class="hint">No verified multi-report campaign advisory is active.</div>';}
      checkpoint('family.load', 'family.load.ui_confirmed');
    } catch (error) { const radarList=document.getElementById('consumerRadar'); if(radarList) radarList.innerHTML=`<div class="hint">${escapeHtml(error.message||String(error))}</div>`; checkpoint('family.load', 'family.load.ui_confirmed', 'failed', 'family_guardian_load_failed'); }""",
)

replace_once(
    "web/consumer-product.js",
    "consumer action handlers",
    """  document.getElementById('consumerRunHealth')?.addEventListener('click',runHealth);
  document.getElementById('consumerRefreshHealth')?.addEventListener('click',()=>{const id=activeMailboxId();if(id&&state.health&&state.healthAccountId===id)renderHealth(state.health,id);});
  document.getElementById('consumerRefreshActivity')?.addEventListener('click',loadActivity);
  document.getElementById('consumerRefreshFamily')?.addEventListener('click',loadFamily);
  document.getElementById('consumerClearActivity')?.addEventListener('click',async()=>{const id=activeMailboxId();if(!id)return;const confirmation=prompt('Type CLEAR ACTIVITY to delete local activity history');if(confirmation!=='CLEAR ACTIVITY'||activeMailboxId()!==id)return;try{await json(await fetch(`/api/consumer/v1/accounts/${encodeURIComponent(id)}/activity`,{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({confirmation})}));if(activeMailboxId()===id)await loadActivity();}catch(error){if(activeMailboxId()===id)document.getElementById('consumerActivityStatus').textContent=error.message||String(error);}});
  document.querySelectorAll('[data-consumer-sensitivity]').forEach(button=>button.addEventListener('click',async()=>{const id=selectedSessionOrThrow();try{const consumer=await post(`/api/consumer/v1/accounts/${encodeURIComponent(id)}/sensitivity`,{profile:button.dataset.consumerSensitivity});if(stillSelected(id)){state.consumer=consumer;await loadConsumerState();}}catch(error){if(stillSelected(id))document.getElementById('consumerSensitivityStatus').textContent=error.message||String(error);}}));
  document.getElementById('consumerRicherNotifications')?.addEventListener('change',async(event)=>{const id=selectedSessionOrThrow();try{await post(`/api/consumer/v1/accounts/${encodeURIComponent(id)}/notifications`,{richerLocalNotifications:event.target.checked});}catch(error){if(stillSelected(id))event.target.checked=!event.target.checked;else void loadConsumerState();}});
  document.getElementById('consumerCheckBrowser')?.addEventListener('click',async()=>{const out=document.getElementById('consumerBrowserResult');try{const url=document.getElementById('consumerBrowserUrl').value;const result=await post('/api/consumer/v1/browser/check',{schemaVersion:1,url,context:'explicit_check'});out.textContent=`${result.disposition.toUpperCase()}: ${result.explanation}`;}catch(error){out.textContent=error.message||String(error);}});
  document.getElementById('consumerCheckIntervention')?.addEventListener('click',async()=>{const out=document.getElementById('consumerInterventionResult');try{const text=document.getElementById('consumerInterventionText').value;const result=await post('/api/consumer/v1/intervention/check',{text});out.textContent=result.recommendedAction;}catch(error){out.textContent=error.message||String(error);}});
  document.getElementById('consumerCheckExposure')?.addEventListener('click',async()=>{const out=document.getElementById('consumerExposureResult');try{const email=document.getElementById('consumerExposureEmail').value;if(!confirm('Check this email using the configured privacy-preserving exposure service? Only a short local hash prefix is sent.'))return;const result=await post('/api/consumer/v1/exposure/email',{email,consent:true});out.textContent=result.state==='unavailable'?result.limitations?.[0]||'Exposure service unavailable.':result.state==='exposed'?'Exposure evidence was found. Change reused credentials and review account security.':'No matching exposure was returned by the configured source. This is not proof the address was never exposed.';}catch(error){out.textContent=error.message||String(error);}});
  document.getElementById('consumerSupportBundle')?.addEventListener('click',async()=>{try{const bundle=await json(await fetch('/api/consumer/v1/support-bundle'));downloadJson(`email-shield-support-${new Date().toISOString().slice(0,10)}.json`,bundle);}catch(error){alert(error.message||String(error));}});""",
    """  document.getElementById('consumerRunHealth')?.addEventListener('click',runHealth);
  document.getElementById('consumerRefreshHealth')?.addEventListener('click',()=>{const id=activeMailboxId();if(id&&state.health&&state.healthAccountId===id){renderHealth(state.health,id);checkpoint('mailbox.health.load','mailbox.health.load.ui_confirmed');}else checkpoint('mailbox.health.load','mailbox.health.load.ui_confirmed','rejected',id?'health_result_unavailable':'account_not_selected');});
  document.getElementById('consumerRefreshActivity')?.addEventListener('click',loadActivity);
  document.getElementById('consumerRefreshFamily')?.addEventListener('click',loadFamily);
  document.getElementById('consumerClearActivity')?.addEventListener('click',async()=>{const id=activeMailboxId();if(!id){checkpoint('activity.clear','activity.clear.ui_confirmed','rejected','account_not_selected');return;}const confirmation=prompt('Type CLEAR ACTIVITY to delete local activity history');if(confirmation!=='CLEAR ACTIVITY'||activeMailboxId()!==id){if(confirmation!==null)checkpoint('activity.clear','activity.clear.ui_confirmed','rejected','confirmation_or_selection_mismatch');return;}try{await json(await fetch(`/api/consumer/v1/accounts/${encodeURIComponent(id)}/activity`,{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({confirmation})}));if(activeMailboxId()===id)await loadActivity();checkpoint('activity.clear','activity.clear.ui_confirmed');}catch(error){if(activeMailboxId()===id)document.getElementById('consumerActivityStatus').textContent=error.message||String(error);checkpoint('activity.clear','activity.clear.ui_confirmed','failed','activity_clear_failed');}});
  document.querySelectorAll('[data-consumer-sensitivity]').forEach(button=>button.addEventListener('click',async()=>{let id=null;try{id=selectedSessionOrThrow();const consumer=await post(`/api/consumer/v1/accounts/${encodeURIComponent(id)}/sensitivity`,{profile:button.dataset.consumerSensitivity});if(stillSelected(id)){state.consumer=consumer;await loadConsumerState();checkpoint('protection.sensitivity.save','protection.sensitivity.save.ui_confirmed');}}catch(error){if(id&&stillSelected(id))document.getElementById('consumerSensitivityStatus').textContent=error.message||String(error);checkpoint('protection.sensitivity.save','protection.sensitivity.save.ui_confirmed','failed',id?'sensitivity_save_failed':'account_not_selected');}}));
  const richerNotifications=document.getElementById('consumerRicherNotifications');if(richerNotifications){window.emailShieldRuntimeTrace?.registerControl(richerNotifications,'notifications.rich_text.toggle','notifications.rich_text.toggle','notification_privacy');richerNotifications.addEventListener('change',async(event)=>{let id=null;try{id=selectedSessionOrThrow();await post(`/api/consumer/v1/accounts/${encodeURIComponent(id)}/notifications`,{richerLocalNotifications:event.target.checked});checkpoint('notifications.rich_text.toggle','notifications.rich_text.toggle.ui_confirmed');}catch(error){if(id&&stillSelected(id))event.target.checked=!event.target.checked;else void loadConsumerState();checkpoint('notifications.rich_text.toggle','notifications.rich_text.toggle.ui_confirmed','failed',id?'notification_privacy_failed':'account_not_selected');}});}
  document.getElementById('consumerCheckBrowser')?.addEventListener('click',async()=>{const out=document.getElementById('consumerBrowserResult');try{const url=document.getElementById('consumerBrowserUrl').value;const result=await post('/api/consumer/v1/browser/check',{schemaVersion:1,url,context:'explicit_check'});out.textContent=`${result.disposition.toUpperCase()}: ${result.explanation}`;checkpoint('browser_destination.check','browser_destination.check.ui_confirmed');}catch(error){out.textContent=error.message||String(error);checkpoint('browser_destination.check','browser_destination.check.ui_confirmed','failed','browser_check_failed');}});
  document.getElementById('consumerCheckIntervention')?.addEventListener('click',async()=>{const out=document.getElementById('consumerInterventionResult');try{const text=document.getElementById('consumerInterventionText').value;const result=await post('/api/consumer/v1/intervention/check',{text});out.textContent=result.recommendedAction;checkpoint('intervention.check','intervention.check.ui_confirmed');}catch(error){out.textContent=error.message||String(error);checkpoint('intervention.check','intervention.check.ui_confirmed','failed','intervention_check_failed');}});
  document.getElementById('consumerCheckExposure')?.addEventListener('click',async()=>{const out=document.getElementById('consumerExposureResult');try{const email=document.getElementById('consumerExposureEmail').value;if(!confirm('Check this email using the configured privacy-preserving exposure service? Only a short local hash prefix is sent.'))return;const result=await post('/api/consumer/v1/exposure/email',{email,consent:true});out.textContent=result.state==='unavailable'?result.limitations?.[0]||'Exposure service unavailable.':result.state==='exposed'?'Exposure evidence was found. Change reused credentials and review account security.':'No matching exposure was returned by the configured source. This is not proof the address was never exposed.';checkpoint('exposure.email.check','exposure.email.check.ui_confirmed',result.state==='unavailable'?'partial':'success');}catch(error){out.textContent=error.message||String(error);checkpoint('exposure.email.check','exposure.email.check.ui_confirmed','failed','exposure_check_failed');}});
  document.getElementById('consumerSupportBundle')?.addEventListener('click',async()=>{try{const bundle=await json(await fetch('/api/consumer/v1/support-bundle'));downloadJson(`email-shield-support-${new Date().toISOString().slice(0,10)}.json`,bundle);checkpoint('support.bundle.export','support.bundle.export.ui_confirmed');}catch(error){alert(error.message||String(error));checkpoint('support.bundle.export','support.bundle.export.ui_confirmed','failed','support_bundle_failed');}});""",
)

replace_once(
    "web/consumer-product.js",
    "onboarding done registration",
    """    document.body.append(overlay);
    overlay.querySelector('#consumerOnboardingDone')?.addEventListener('click',async()=>{
      if(!stillSelected(id)){overlay.remove();return;}
      try{await post(`/api/consumer/v1/accounts/${encodeURIComponent(id)}/onboarding`,{completedSteps:['consumer_intro'],dismissed:true});overlay.remove();if(stillSelected(id))await loadConsumerState();}catch(error){if(stillSelected(id))alert(error.message||String(error));}
    });""",
    """    document.body.append(overlay);
    const onboardingDone=overlay.querySelector('#consumerOnboardingDone');
    if(onboardingDone){
      window.emailShieldRuntimeTrace?.registerControl(onboardingDone,'onboarding.complete','onboarding.complete','onboarding_complete');
      onboardingDone.addEventListener('click',async()=>{
        if(!stillSelected(id)){overlay.remove();checkpoint('onboarding.complete','onboarding.complete.ui_confirmed','rejected','stale_selection');return;}
        try{await post(`/api/consumer/v1/accounts/${encodeURIComponent(id)}/onboarding`,{completedSteps:['consumer_intro'],dismissed:true});overlay.remove();if(stillSelected(id))await loadConsumerState();checkpoint('onboarding.complete','onboarding.complete.ui_confirmed');}catch(error){if(stillSelected(id))alert(error.message||String(error));checkpoint('onboarding.complete','onboarding.complete.ui_confirmed','failed','onboarding_complete_failed');}
      });
    }""",
)

print("Exact flight recorder edits applied.")
