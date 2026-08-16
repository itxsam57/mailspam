import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = process.cwd();

function rewrite(path, edits) {
  const full = resolve(root, path);
  let source = readFileSync(full, 'utf8');
  for (const [label, before, after] of edits) {
    if (!source.includes(before)) {
      throw new Error(`${path}: expected source pattern missing for ${label}`);
    }
    source = source.replace(before, after);
  }
  writeFileSync(full, source, 'utf8');
}

rewrite('web/runtime-workflow-trace.js', [
  [
    'recover-account semantic owner',
    "    accountRecoverOpen: ['account.recovery.open', 'account.recovery.open', 'account_recovery_open'],",
    "    accountRecoverOpen: ['account.recovery.use', 'account.recovery.use', 'account_recovery'],",
  ],
  [
    'change-control registry',
    "  const registeredById = new Map();\n  const registeredElements = new WeakMap();",
    `  const CHANGE_CONTROLS = Object.freeze({\n    backgroundInterval: ['protection.background.interval', 'protection.background.interval', 'background_protection_interval'],\n    providerSelect: ['developer.provider.select', 'developer.provider.select', 'developer_provider_select'],\n    modeSelect: ['developer.mode.select', 'developer.mode.select', 'developer_mode_select'],\n    consumerRicherNotifications: ['notifications.rich_text.toggle', 'notifications.rich_text.toggle', 'notification_privacy'],\n    accountTransferTarget: ['family.transfer.selection', 'family.transfer.selection', 'family_transfer_selection'],\n    policyCategory: ['policy.filter.change', 'policy.filter.change', 'policy_filter'],\n    policyImportMode: ['policy.import_mode.change', 'policy.import_mode.change', 'policy_import_mode'],\n  });\n\n  const registeredById = new Map();\n  const registeredElements = new WeakMap();`,
  ],
  [
    'semantic change resolver',
    "  function providerFor(button) {",
    `  function semanticChangeControl(control) {\n    const bound = registeredElements.get(control) || (control.id ? registeredById.get(control.id) : null);\n    if (bound) return bound;\n    if (control.id && CHANGE_CONTROLS[control.id]) {\n      const [actionId, workflowId, expectedWorkflow] = CHANGE_CONTROLS[control.id];\n      return definition(actionId, workflowId, expectedWorkflow, providerFor(control));\n    }\n    return null;\n  }\n\n  function providerFor(button) {`,
  ],
  [
    'trusted change tracing',
    `  document.addEventListener('click', (event) => {\n    if (event.isTrusted === false) return;\n    const button = event.target instanceof Element ? event.target.closest('button') : null;\n    if (!(button instanceof HTMLButtonElement) || button.disabled) return;\n    const semantic = semanticControl(button);\n    if (!semantic) return;\n    begin(semantic.actionId, semantic.workflowId, semantic.expectedWorkflow, semantic.provider || providerFor(button));\n  }, true);\n\n  Object.defineProperty(window, 'emailShieldRuntimeTrace', {`,
    `  document.addEventListener('click', (event) => {\n    if (event.isTrusted === false) return;\n    const button = event.target instanceof Element ? event.target.closest('button') : null;\n    if (!(button instanceof HTMLButtonElement) || button.disabled) return;\n    const semantic = semanticControl(button);\n    if (!semantic) return;\n    begin(semantic.actionId, semantic.workflowId, semantic.expectedWorkflow, semantic.provider || providerFor(button));\n  }, true);\n\n  document.addEventListener('change', (event) => {\n    if (event.isTrusted === false) return;\n    const control = event.target instanceof Element ? event.target : null;\n    if (!(control instanceof HTMLInputElement || control instanceof HTMLSelectElement)) return;\n    if (control.disabled) return;\n    const semantic = semanticChangeControl(control);\n    if (!semantic) return;\n    const context = begin(semantic.actionId, semantic.workflowId, semantic.expectedWorkflow, semantic.provider || providerFor(control));\n    if (!context) return;\n    if (semantic.workflowId.startsWith('developer.') || semantic.workflowId === 'family.transfer.selection' || semantic.workflowId === 'policy.filter.change' || semantic.workflowId === 'policy.import_mode.change') {\n      queueMicrotask(() => checkpointFor(context, `${semantic.workflowId}.ui_confirmed`));\n    }\n  }, true);\n\n  Object.defineProperty(window, 'emailShieldRuntimeTrace', {`,
  ],
]);

rewrite('web/consumer-product.js', [
  [
    'consumer checkpoint helper',
    `  const state = {\n    accountId: null,\n    consumer: null,\n    health: null,\n    healthAccountId: null,\n    family: null,\n    radar: null,\n  };`,
    `  const state = {\n    accountId: null,\n    consumer: null,\n    health: null,\n    healthAccountId: null,\n    family: null,\n    radar: null,\n  };\n\n  function checkpoint(workflowId, checkpointId, outcome = 'success', errorCode) {\n    const trace = window.emailShieldRuntimeTrace;\n    if (trace?.currentWorkflowId?.() !== workflowId) return;\n    trace.checkpoint(checkpointId, outcome, errorCode ? { errorCode } : undefined);\n  }`,
  ],
  [
    'fixture mode dynamic registration',
    `      fixture.type = 'button';\n      fixture.textContent = 'Use fixture mode';`,
    `      fixture.type = 'button';\n      fixture.textContent = 'Use fixture mode';\n      window.emailShieldRuntimeTrace?.registerControl(fixture, 'developer.mode.select', 'developer.mode.select', 'developer_mode_select');`,
  ],
  [
    'cleanup registration',
    `        const cleanup = document.createElement('button'); cleanup.type = 'button'; cleanup.textContent = 'Clean old mail';\n        cleanup.addEventListener('click', async () => {`,
    `        const cleanup = document.createElement('button'); cleanup.type = 'button'; cleanup.textContent = 'Clean old mail';\n        window.emailShieldRuntimeTrace?.registerControl(cleanup, 'mailbox.cleanup', 'mailbox.cleanup', 'mailbox_cleanup');\n        cleanup.addEventListener('click', async () => {`,
  ],
  [
    'cleanup stale selection',
    `          if (!stillSelected(accountId)) {\n            setHealthStatus('Mailbox selection changed. Run Health again before cleaning mail.', true);\n            return;\n          }`,
    `          if (!stillSelected(accountId)) {\n            setHealthStatus('Mailbox selection changed. Run Health again before cleaning mail.', true);\n            checkpoint('mailbox.cleanup', 'mailbox.cleanup.ui_confirmed', 'rejected', 'stale_selection');\n            return;\n          }`,
  ],
  [
    'cleanup completion',
    `            setHealthStatus(\`${'${cleanupResult.movedToTrash}'} message(s) moved to Trash.${'${cleanupResult.undoAvailable'} ? ' Undo is available in Activity for 30 minutes.' : ''}\`);\n            await loadActivity();\n          } catch (error) {\n            if (stillSelected(accountId)) setHealthStatus(error.message || String(error), true);\n          }`,
    `            setHealthStatus(\`${'${cleanupResult.movedToTrash}'} message(s) moved to Trash.${'${cleanupResult.undoAvailable'} ? ' Undo is available in Activity for 30 minutes.' : ''}\`);\n            await loadActivity();\n            checkpoint('mailbox.cleanup', 'mailbox.cleanup.ui_confirmed');\n          } catch (error) {\n            if (stillSelected(accountId)) setHealthStatus(error.message || String(error), true);\n            checkpoint('mailbox.cleanup', 'mailbox.cleanup.ui_confirmed', 'failed', 'mailbox_cleanup_failed');\n          }`,
  ],
  [
    'health completion',
    `      renderHealth(result, id);\n      setHealthStatus('Health check complete. Unsupported provider checks remain explicitly marked unavailable.');\n    } catch (error) {\n      if (!id || stillSelected(id)) setHealthStatus(error.message || String(error), true);\n    }`,
    `      renderHealth(result, id);\n      setHealthStatus('Health check complete. Unsupported provider checks remain explicitly marked unavailable.');\n      checkpoint('mailbox.health.run', 'mailbox.health.run.ui_confirmed');\n    } catch (error) {\n      if (!id || stillSelected(id)) setHealthStatus(error.message || String(error), true);\n      checkpoint('mailbox.health.run', 'mailbox.health.run.ui_confirmed', 'failed', id ? 'mailbox_health_failed' : 'account_not_selected');\n    }`,
  ],
  [
    'undo action expansion',
    `        if(item.undoAvailable){const undo=document.createElement('button');undo.type='button';undo.textContent='Undo';undo.addEventListener('click',async()=>{if(!stillSelected(id)){document.getElementById('consumerActivityStatus').textContent='Mailbox selection changed. Refresh Activity before using Undo.';return;}try{await post(\`/api/consumer/v1/accounts/${'${encodeURIComponent(id)}'}/activity/${'${encodeURIComponent(item.activityId)}'}/undo\`);if(stillSelected(id))await loadActivity();}catch(error){if(stillSelected(id))document.getElementById('consumerActivityStatus').textContent=error.message||String(error);}});controls.append(undo);}`,
    `        if(item.undoAvailable){\n          const undo=document.createElement('button');\n          undo.type='button';\n          undo.textContent='Undo';\n          window.emailShieldRuntimeTrace?.registerControl(undo, 'message.undo', 'message.undo', 'provider_undo');\n          undo.addEventListener('click',async()=>{\n            if(!stillSelected(id)){\n              document.getElementById('consumerActivityStatus').textContent='Mailbox selection changed. Refresh Activity before using Undo.';\n              checkpoint('message.undo', 'message.undo.ui_confirmed', 'rejected', 'stale_selection');\n              return;\n            }\n            try{\n              await post(\`/api/consumer/v1/accounts/${'${encodeURIComponent(id)}'}/activity/${'${encodeURIComponent(item.activityId)}'}/undo\`);\n              if(stillSelected(id))await loadActivity();\n              checkpoint('message.undo', 'message.undo.ui_confirmed');\n            }catch(error){\n              if(stillSelected(id))document.getElementById('consumerActivityStatus').textContent=error.message||String(error);\n              checkpoint('message.undo', 'message.undo.ui_confirmed', 'failed', 'undo_failed');\n            }\n          });\n          controls.append(undo);\n        }`,
  ],
  [
    'activity load completion',
    `      if (!(body.activity || []).length) list.innerHTML='<div class="hint">No local protection activity yet.</div>';\n    } catch (error) { if(stillSelected(id)) document.getElementById('consumerActivityStatus').textContent=error.message||String(error); }`,
    `      if (!(body.activity || []).length) list.innerHTML='<div class="hint">No local protection activity yet.</div>';\n      checkpoint('activity.load', 'activity.load.ui_confirmed');\n    } catch (error) {\n      if(stillSelected(id)) document.getElementById('consumerActivityStatus').textContent=error.message||String(error);\n      checkpoint('activity.load', 'activity.load.ui_confirmed', 'failed', 'activity_load_failed');\n    }`,
  ],
  [
    'family load completion',
    `      const radarList=document.getElementById('consumerRadar'); if(radarList){radarList.replaceChildren(); if(!radar.available)radarList.innerHTML=\`<div class="hint">${'${escapeHtml(radar.reason||\'Verified campaign intelligence is unavailable.\')}'}</div>\`; else for(const item of radar.advisories||[]){const row=document.createElement('div');row.className='consumer-list-item';row.innerHTML=\`<div><strong>${'${escapeHtml(item.severity)}'} campaign advisory</strong><div class="hint">${'${escapeHtml(item.guidance)}'}</div></div><span class="consumer-chip ${'${item.severity===\'confirmed\'?\'critical\':\'warning\'}'}">${'${Number(item.independentReports||0)}'} reports</span>\`;radarList.append(row);} if(radar.available&&!(radar.advisories||[]).length)radarList.innerHTML='<div class="hint">No verified multi-report campaign advisory is active.</div>';}\n    } catch (error) { const radarList=document.getElementById('consumerRadar'); if(radarList) radarList.innerHTML=\`<div class="hint">${'${escapeHtml(error.message||String(error))}'}</div>\`; }`,
    `      const radarList=document.getElementById('consumerRadar'); if(radarList){radarList.replaceChildren(); if(!radar.available)radarList.innerHTML=\`<div class="hint">${'${escapeHtml(radar.reason||\'Verified campaign intelligence is unavailable.\')}'}</div>\`; else for(const item of radar.advisories||[]){const row=document.createElement('div');row.className='consumer-list-item';row.innerHTML=\`<div><strong>${'${escapeHtml(item.severity)}'} campaign advisory</strong><div class="hint">${'${escapeHtml(item.guidance)}'}</div></div><span class="consumer-chip ${'${item.severity===\'confirmed\'?\'critical\':\'warning\'}'}">${'${Number(item.independentReports||0)}'} reports</span>\`;radarList.append(row);} if(radar.available&&!(radar.advisories||[]).length)radarList.innerHTML='<div class="hint">No verified multi-report campaign advisory is active.</div>';}\n      checkpoint('family.load', 'family.load.ui_confirmed');\n    } catch (error) {\n      const radarList=document.getElementById('consumerRadar'); if(radarList) radarList.innerHTML=\`<div class="hint">${'${escapeHtml(error.message||String(error))}'}</div>\`;\n      checkpoint('family.load', 'family.load.ui_confirmed', 'failed', 'family_guardian_load_failed');\n    }`,
  ],
  [
    'refresh health action',
    `  document.getElementById('consumerRefreshHealth')?.addEventListener('click',()=>{const id=activeMailboxId();if(id&&state.health&&state.healthAccountId===id)renderHealth(state.health,id);});`,
    `  document.getElementById('consumerRefreshHealth')?.addEventListener('click',()=>{\n    const id=activeMailboxId();\n    if(id&&state.health&&state.healthAccountId===id){\n      renderHealth(state.health,id);\n      checkpoint('mailbox.health.load', 'mailbox.health.load.ui_confirmed');\n    } else checkpoint('mailbox.health.load', 'mailbox.health.load.ui_confirmed', 'rejected', id ? 'health_result_unavailable' : 'account_not_selected');\n  });`,
  ],
  [
    'clear activity action',
    `  document.getElementById('consumerClearActivity')?.addEventListener('click',async()=>{const id=activeMailboxId();if(!id)return;const confirmation=prompt('Type CLEAR ACTIVITY to delete local activity history');if(confirmation!=='CLEAR ACTIVITY'||activeMailboxId()!==id)return;try{await json(await fetch(\`/api/consumer/v1/accounts/${'${encodeURIComponent(id)}'}/activity\`,{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({confirmation})}));if(activeMailboxId()===id)await loadActivity();}catch(error){if(activeMailboxId()===id)document.getElementById('consumerActivityStatus').textContent=error.message||String(error);}});`,
    `  document.getElementById('consumerClearActivity')?.addEventListener('click',async()=>{\n    const id=activeMailboxId();\n    if(!id){checkpoint('activity.clear','activity.clear.ui_confirmed','rejected','account_not_selected');return;}\n    const confirmation=prompt('Type CLEAR ACTIVITY to delete local activity history');\n    if(confirmation!=='CLEAR ACTIVITY'||activeMailboxId()!==id){if(confirmation!==null)checkpoint('activity.clear','activity.clear.ui_confirmed','rejected','confirmation_or_selection_mismatch');return;}\n    try{\n      await json(await fetch(\`/api/consumer/v1/accounts/${'${encodeURIComponent(id)}'}/activity\`,{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({confirmation})}));\n      if(activeMailboxId()===id)await loadActivity();\n      checkpoint('activity.clear','activity.clear.ui_confirmed');\n    }catch(error){\n      if(activeMailboxId()===id)document.getElementById('consumerActivityStatus').textContent=error.message||String(error);\n      checkpoint('activity.clear','activity.clear.ui_confirmed','failed','activity_clear_failed');\n    }\n  });`,
  ],
  [
    'sensitivity action',
    `  document.querySelectorAll('[data-consumer-sensitivity]').forEach(button=>button.addEventListener('click',async()=>{const id=selectedSessionOrThrow();try{const consumer=await post(\`/api/consumer/v1/accounts/${'${encodeURIComponent(id)}'}/sensitivity\`,{profile:button.dataset.consumerSensitivity});if(stillSelected(id)){state.consumer=consumer;await loadConsumerState();}}catch(error){if(stillSelected(id))document.getElementById('consumerSensitivityStatus').textContent=error.message||String(error);}}));`,
    `  document.querySelectorAll('[data-consumer-sensitivity]').forEach(button=>button.addEventListener('click',async()=>{\n    let id=null;\n    try{\n      id=selectedSessionOrThrow();\n      const consumer=await post(\`/api/consumer/v1/accounts/${'${encodeURIComponent(id)}'}/sensitivity\`,{profile:button.dataset.consumerSensitivity});\n      if(stillSelected(id)){state.consumer=consumer;await loadConsumerState();checkpoint('protection.sensitivity.save','protection.sensitivity.save.ui_confirmed');}\n    }catch(error){\n      if(id&&stillSelected(id))document.getElementById('consumerSensitivityStatus').textContent=error.message||String(error);\n      checkpoint('protection.sensitivity.save','protection.sensitivity.save.ui_confirmed','failed',id?'sensitivity_save_failed':'account_not_selected');\n    }\n  }));`,
  ],
  [
    'notification change action',
    `  document.getElementById('consumerRicherNotifications')?.addEventListener('change',async(event)=>{const id=selectedSessionOrThrow();try{await post(\`/api/consumer/v1/accounts/${'${encodeURIComponent(id)}'}/notifications\`,{richerLocalNotifications:event.target.checked});}catch(error){if(stillSelected(id))event.target.checked=!event.target.checked;else void loadConsumerState();}});`,
    `  const richerNotifications=document.getElementById('consumerRicherNotifications');\n  if(richerNotifications){\n    window.emailShieldRuntimeTrace?.registerControl(richerNotifications,'notifications.rich_text.toggle','notifications.rich_text.toggle','notification_privacy');\n    richerNotifications.addEventListener('change',async(event)=>{\n      let id=null;\n      try{\n        id=selectedSessionOrThrow();\n        await post(\`/api/consumer/v1/accounts/${'${encodeURIComponent(id)}'}/notifications\`,{richerLocalNotifications:event.target.checked});\n        checkpoint('notifications.rich_text.toggle','notifications.rich_text.toggle.ui_confirmed');\n      }catch(error){\n        if(id&&stillSelected(id))event.target.checked=!event.target.checked;else void loadConsumerState();\n        checkpoint('notifications.rich_text.toggle','notifications.rich_text.toggle.ui_confirmed','failed',id?'notification_privacy_failed':'account_not_selected');\n      }\n    });\n  }`,
  ],
  [
    'browser check action',
    `  document.getElementById('consumerCheckBrowser')?.addEventListener('click',async()=>{const out=document.getElementById('consumerBrowserResult');try{const url=document.getElementById('consumerBrowserUrl').value;const result=await post('/api/consumer/v1/browser/check',{schemaVersion:1,url,context:'explicit_check'});out.textContent=\`${'${result.disposition.toUpperCase()}'}: ${'${result.explanation}'}\`;}catch(error){out.textContent=error.message||String(error);}});`,
    `  document.getElementById('consumerCheckBrowser')?.addEventListener('click',async()=>{\n    const out=document.getElementById('consumerBrowserResult');\n    try{\n      const url=document.getElementById('consumerBrowserUrl').value;\n      const result=await post('/api/consumer/v1/browser/check',{schemaVersion:1,url,context:'explicit_check'});\n      out.textContent=\`${'${result.disposition.toUpperCase()}'}: ${'${result.explanation}'}\`;\n      checkpoint('browser_destination.check','browser_destination.check.ui_confirmed');\n    }catch(error){out.textContent=error.message||String(error);checkpoint('browser_destination.check','browser_destination.check.ui_confirmed','failed','browser_check_failed');}\n  });`,
  ],
  [
    'intervention check action',
    `  document.getElementById('consumerCheckIntervention')?.addEventListener('click',async()=>{const out=document.getElementById('consumerInterventionResult');try{const text=document.getElementById('consumerInterventionText').value;const result=await post('/api/consumer/v1/intervention/check',{text});out.textContent=result.recommendedAction;}catch(error){out.textContent=error.message||String(error);}});`,
    `  document.getElementById('consumerCheckIntervention')?.addEventListener('click',async()=>{\n    const out=document.getElementById('consumerInterventionResult');\n    try{const text=document.getElementById('consumerInterventionText').value;const result=await post('/api/consumer/v1/intervention/check',{text});out.textContent=result.recommendedAction;checkpoint('intervention.check','intervention.check.ui_confirmed');}\n    catch(error){out.textContent=error.message||String(error);checkpoint('intervention.check','intervention.check.ui_confirmed','failed','intervention_check_failed');}\n  });`,
  ],
  [
    'exposure check action',
    `  document.getElementById('consumerCheckExposure')?.addEventListener('click',async()=>{const out=document.getElementById('consumerExposureResult');try{const email=document.getElementById('consumerExposureEmail').value;if(!confirm('Check this email using the configured privacy-preserving exposure service? Only a short local hash prefix is sent.'))return;const result=await post('/api/consumer/v1/exposure/email',{email,consent:true});out.textContent=result.state==='unavailable'?result.limitations?.[0]||'Exposure service unavailable.':result.state==='exposed'?'Exposure evidence was found. Change reused credentials and review account security.':'No matching exposure was returned by the configured source. This is not proof the address was never exposed.';}catch(error){out.textContent=error.message||String(error);}});`,
    `  document.getElementById('consumerCheckExposure')?.addEventListener('click',async()=>{\n    const out=document.getElementById('consumerExposureResult');\n    try{\n      const email=document.getElementById('consumerExposureEmail').value;\n      if(!confirm('Check this email using the configured privacy-preserving exposure service? Only a short local hash prefix is sent.'))return;\n      const result=await post('/api/consumer/v1/exposure/email',{email,consent:true});\n      out.textContent=result.state==='unavailable'?result.limitations?.[0]||'Exposure service unavailable.':result.state==='exposed'?'Exposure evidence was found. Change reused credentials and review account security.':'No matching exposure was returned by the configured source. This is not proof the address was never exposed.';\n      checkpoint('exposure.email.check','exposure.email.check.ui_confirmed',result.state==='unavailable'?'partial':'success');\n    }catch(error){out.textContent=error.message||String(error);checkpoint('exposure.email.check','exposure.email.check.ui_confirmed','failed','exposure_check_failed');}\n  });`,
  ],
  [
    'support bundle action',
    `  document.getElementById('consumerSupportBundle')?.addEventListener('click',async()=>{try{const bundle=await json(await fetch('/api/consumer/v1/support-bundle'));downloadJson(\`email-shield-support-${'${new Date().toISOString().slice(0,10)}'}.json\`,bundle);}catch(error){alert(error.message||String(error));}});`,
    `  document.getElementById('consumerSupportBundle')?.addEventListener('click',async()=>{\n    try{const bundle=await json(await fetch('/api/consumer/v1/support-bundle'));downloadJson(\`email-shield-support-${'${new Date().toISOString().slice(0,10)}'}.json\`,bundle);checkpoint('support.bundle.export','support.bundle.export.ui_confirmed');}\n    catch(error){alert(error.message||String(error));checkpoint('support.bundle.export','support.bundle.export.ui_confirmed','failed','support_bundle_failed');}\n  });`,
  ],
  [
    'onboarding control registration and completion',
    `    document.body.append(overlay);\n    overlay.querySelector('#consumerOnboardingDone')?.addEventListener('click',async()=>{\n      if(!stillSelected(id)){overlay.remove();return;}\n      try{await post(\`/api/consumer/v1/accounts/${'${encodeURIComponent(id)}'}/onboarding\`,{completedSteps:['consumer_intro'],dismissed:true});overlay.remove();if(stillSelected(id))await loadConsumerState();}catch(error){if(stillSelected(id))alert(error.message||String(error));}\n    });`,
    `    document.body.append(overlay);\n    const onboardingDone=overlay.querySelector('#consumerOnboardingDone');\n    if(onboardingDone){\n      window.emailShieldRuntimeTrace?.registerControl(onboardingDone,'onboarding.complete','onboarding.complete','onboarding_complete');\n      onboardingDone.addEventListener('click',async()=>{\n        if(!stillSelected(id)){overlay.remove();checkpoint('onboarding.complete','onboarding.complete.ui_confirmed','rejected','stale_selection');return;}\n        try{\n          await post(\`/api/consumer/v1/accounts/${'${encodeURIComponent(id)}'}/onboarding\`,{completedSteps:['consumer_intro'],dismissed:true});\n          overlay.remove();\n          if(stillSelected(id))await loadConsumerState();\n          checkpoint('onboarding.complete','onboarding.complete.ui_confirmed');\n        }catch(error){if(stillSelected(id))alert(error.message||String(error));checkpoint('onboarding.complete','onboarding.complete.ui_confirmed','failed','onboarding_complete_failed');}\n      });\n    }`,
  ],
]);

rewrite('server/src/diagnostics/workflowRegistry.ts', [
  [
    'additional UI workflows',
    `  linearWorkflow("family.guardian_preferences"),\n  linearWorkflow("family.transfer"),`,
    `  linearWorkflow("family.guardian_preferences"),\n  uiWorkflow("family.guardian_preferences.edit"),\n  linearWorkflow("family.invite.copy"),\n  linearWorkflow("family.transfer"),\n  uiWorkflow("family.transfer.selection"),`,
  ],
  [
    'notification and policy edit workflows',
    `  linearWorkflow("support.bundle.export"),\n\n  linearWorkflow("scam_check.run"),`,
    `  linearWorkflow("support.bundle.export"),\n  linearWorkflow("notifications.rich_text.toggle"),\n  uiWorkflow("policy.filter.change"),\n  uiWorkflow("policy.import_mode.change"),\n\n  linearWorkflow("scam_check.run"),`,
  ],
  [
    'account recovery presentation workflows',
    `  uiWorkflow("account.recovery.acknowledge"),\n  linearWorkflow("account.devices.revoke"),`,
    `  uiWorkflow("account.recovery.acknowledge"),\n  linearWorkflow("account.devices.revoke"),`,
  ],
]);

rewrite('tests/unit/runtimeWorkflowFeatureCheckpoints.test.ts', [
  [
    'account recovery test already canonical',
    `    "account.recovery.use.ui_confirmed",`,
    `    "account.recovery.use.ui_confirmed",`,
  ],
]);

console.log('Flight recorder codemods applied successfully.');
