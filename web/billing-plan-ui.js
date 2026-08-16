(() => {
  const installed = window.emailShieldInstalledModules ||= new Set();
  if (installed.has('billing-plan-ui')) return;
  installed.add('billing-plan-ui');

  const developerMode = new URLSearchParams(location.search).get('developer') === '1';

  function checkpoint(workflowId, checkpointId, outcome = 'success', errorCode) {
    const trace = window.emailShieldRuntimeTrace;
    if (trace?.currentWorkflowId?.() !== workflowId) return;
    trace.checkpoint(checkpointId, outcome, errorCode ? { errorCode } : undefined);
  }

  function enforceDeveloperVisibility() {
    const devPlans = document.getElementById('accountDevPlans');
    if (devPlans && !developerMode && !devPlans.hidden) devPlans.hidden = true;
  }

  function billingBridge() {
    const bridge = window.emailShieldBillingBridge;
    if (!bridge || typeof bridge !== 'object') return null;
    return bridge;
  }

  async function refreshCurrentPlan() {
    const plan = document.getElementById('consumerBillingCurrentPlan');
    const status = document.getElementById('consumerBillingStatus');
    try {
      const response = await fetch('/api/profile/v1/snapshot');
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.error || `Account snapshot failed (${response.status}).`);
      if (!body.signedIn || !body.account) {
        if (plan) plan.textContent = 'Sign in to manage a plan';
        checkpoint('billing.plan.load', 'billing.plan.load.ui_confirmed', 'rejected', 'profile_not_signed_in');
        return;
      }
      if (plan) {
        const entitlement = body.account.entitlement;
        plan.textContent = `${String(entitlement.plan).replace(/^./, (letter) => letter.toUpperCase())} · ${entitlement.status}`;
      }
      if (status && body.account.entitlement.source !== 'development') {
        status.textContent = `Verified by ${body.account.entitlement.source}. Email Shield does not trust a local premium toggle.`;
      }
      checkpoint('billing.plan.load', 'billing.plan.load.ui_confirmed');
    } catch (error) {
      if (status) status.textContent = error.message || String(error);
      checkpoint('billing.plan.load', 'billing.plan.load.ui_confirmed', 'failed', 'billing_plan_load_failed');
    }
  }

  async function purchase(plan) {
    const status = document.getElementById('consumerBillingStatus');
    const bridge = billingBridge();
    const workflowId = plan === 'family' ? 'billing.purchase.family' : 'billing.purchase.individual';
    const checkpointId = `${workflowId}.ui_confirmed`;
    if (!bridge || typeof bridge.purchase !== 'function') {
      if (status) status.textContent = 'Paid purchase is not available in this desktop runtime. Production iOS/Android builds use their signed StoreKit/Play Billing bridge; a web checkout must be configured separately.';
      checkpoint(workflowId, checkpointId, 'rejected', 'store_bridge_unavailable');
      return;
    }
    try {
      if (status) status.textContent = `Opening ${plan} purchase…`;
      const result = await bridge.purchase(plan);
      if (!result || result.verified !== true) throw new Error('The store purchase did not return a server-verified Email Shield entitlement.');
      if (status) status.textContent = `${plan.replace(/^./, (letter) => letter.toUpperCase())} plan verified successfully.`;
      await refreshCurrentPlan();
      window.dispatchEvent(new CustomEvent('email-shield-profile-changed'));
      checkpoint(workflowId, checkpointId);
    } catch (error) {
      if (status) status.textContent = error.message || String(error);
      checkpoint(workflowId, checkpointId, 'failed', 'purchase_verification_failed');
    }
  }

  async function restore() {
    const status = document.getElementById('consumerBillingStatus');
    const bridge = billingBridge();
    if (!bridge || typeof bridge.restore !== 'function') {
      if (status) status.textContent = 'Purchase restore requires the signed production store bridge on this platform.';
      checkpoint('billing.purchase.restore', 'billing.purchase.restore.ui_confirmed', 'rejected', 'store_bridge_unavailable');
      return;
    }
    try {
      if (status) status.textContent = 'Checking previous purchases…';
      const result = await bridge.restore();
      if (!result || result.verified !== true) throw new Error('No server-verified restorable Email Shield purchase was returned.');
      if (status) status.textContent = 'Purchase restored and verified.';
      await refreshCurrentPlan();
      window.dispatchEvent(new CustomEvent('email-shield-profile-changed'));
      checkpoint('billing.purchase.restore', 'billing.purchase.restore.ui_confirmed');
    } catch (error) {
      if (status) status.textContent = error.message || String(error);
      checkpoint('billing.purchase.restore', 'billing.purchase.restore.ui_confirmed', 'failed', 'purchase_restore_failed');
    }
  }

  function mount() {
    enforceDeveloperVisibility();
    const signedIn = document.getElementById('accountSignedIn');
    if (!signedIn || document.getElementById('consumerBillingCard')) return;
    const card = document.createElement('div');
    card.id = 'consumerBillingCard';
    card.className = 'account-card';
    card.innerHTML = `
      <h3>Subscription</h3>
      <strong id="consumerBillingCurrentPlan">Checking current plan…</strong>
      <p class="hint">Individual and Family access is granted only after server verification of signed store/web purchase evidence. Billing verifier secrets never ship in the app.</p>
      <div class="row">
        <button id="consumerBuyIndividual" type="button">Choose Individual</button>
        <button id="consumerBuyFamily" type="button">Choose Family · 6 seats</button>
        <button id="consumerRestorePurchase" type="button">Restore purchase</button>
      </div>
      <div id="consumerBillingStatus" class="hint" role="status" aria-live="polite"></div>`;
    const devPlans = document.getElementById('accountDevPlans');
    if (devPlans?.parentElement === signedIn) signedIn.insertBefore(card, devPlans);
    else signedIn.append(card);
    card.querySelector('#consumerBuyIndividual')?.addEventListener('click', () => { void purchase('individual'); });
    card.querySelector('#consumerBuyFamily')?.addEventListener('click', () => { void purchase('family'); });
    card.querySelector('#consumerRestorePurchase')?.addEventListener('click', () => { void restore(); });
    void refreshCurrentPlan();
  }

  function accountVisible() {
    const signedIn = document.getElementById('accountSignedIn');
    const route = signedIn?.closest('.app-route');
    return route ? !route.hidden && route.dataset.route === 'account' : location.hash === '#account';
  }

  function mountWhenVisible() {
    enforceDeveloperVisibility();
    if (accountVisible()) mount();
  }

  window.addEventListener('email-shield-profile-changed', () => {
    enforceDeveloperVisibility();
    if (accountVisible()) {
      mount();
      if (document.getElementById('consumerBillingCard')) void refreshCurrentPlan();
    }
  });
  window.addEventListener('email-shield-route-changed', (event) => {
    if (event.detail?.route === 'account') mountWhenVisible();
  });
  if (location.hash === '#account') queueMicrotask(mountWhenVisible);
  else enforceDeveloperVisibility();
})();
