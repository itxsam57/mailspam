(() => {
  const installed = window.emailShieldInstalledModules ||= new Set();
  if (installed.has('billing-plan-ui')) return;
  installed.add('billing-plan-ui');

  const developerMode = new URLSearchParams(location.search).get('developer') === '1';
  const runtimeTrace = window.emailShieldRuntimeTrace;
  let restoreGeneration = 0;

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
        return;
      }
      if (plan) {
        const entitlement = body.account.entitlement;
        plan.textContent = `${String(entitlement.plan).replace(/^./, (letter) => letter.toUpperCase())} · ${entitlement.status}`;
      }
      if (status && body.account.entitlement.source !== 'development') {
        status.textContent = `Verified by ${body.account.entitlement.source}. Email Shield does not trust a local premium toggle.`;
      }
    } catch (error) {
      if (status) status.textContent = error.message || String(error);
    }
  }

  async function purchase(plan) {
    const status = document.getElementById('consumerBillingStatus');
    const bridge = billingBridge();
    if (!bridge || typeof bridge.purchase !== 'function') {
      if (status) status.textContent = 'Paid purchase is not available in this desktop runtime. Production iOS/Android builds use their signed StoreKit/Play Billing bridge; a web checkout must be configured separately.';
      return;
    }
    try {
      if (status) status.textContent = `Opening ${plan} purchase…`;
      const result = await bridge.purchase(plan);
      if (!result || result.verified !== true) throw new Error('The store purchase did not return a server-verified Email Shield entitlement.');
      if (status) status.textContent = `${plan.replace(/^./, (letter) => letter.toUpperCase())} plan verified successfully.`;
      await refreshCurrentPlan();
      window.dispatchEvent(new CustomEvent('email-shield-profile-changed'));
    } catch (error) {
      if (status) status.textContent = error.message || String(error);
    }
  }

  function restoreTerminal(generation, code, message, outcome = 'success') {
    if (generation !== restoreGeneration) return false;
    const status = document.getElementById('consumerBillingStatus');
    if (status) {
      status.dataset.restoreState = code;
      status.textContent = message;
    }
    runtimeTrace?.checkpoint('billing.purchase.restore.ui_confirmed', outcome, {
      component: 'billing_plan_ui',
      step: code,
    });
    return true;
  }

  function restoreResultCode(result) {
    if (!result || typeof result !== 'object') return 'nothing_to_restore';
    const raw = String(result.code || result.status || result.reason || '').trim().toLowerCase();
    if (['nothing_to_restore', 'none', 'not_found', 'no_purchase', 'no_purchases'].includes(raw)) return 'nothing_to_restore';
    return result.verified === true ? 'restored_verified' : 'verification_rejected';
  }

  async function restore() {
    const generation = ++restoreGeneration;
    const status = document.getElementById('consumerBillingStatus');
    const bridge = billingBridge();
    if (!bridge || typeof bridge.restore !== 'function') {
      restoreTerminal(generation, 'bridge_unavailable', 'Purchase restore requires the signed production store bridge on this platform.', 'unavailable');
      return;
    }
    if (status && generation === restoreGeneration) {
      status.dataset.restoreState = 'checking';
      status.textContent = 'Checking previous purchases…';
    }
    try {
      const result = await bridge.restore();
      if (generation !== restoreGeneration) return;
      const code = restoreResultCode(result);
      if (code === 'nothing_to_restore') {
        restoreTerminal(generation, 'nothing_to_restore', 'No restorable Email Shield purchase was found for the signed-in store account.', 'success');
        return;
      }
      if (code === 'verification_rejected') {
        restoreTerminal(generation, 'verification_rejected', 'A store record was returned, but Email Shield could not verify a valid entitlement. No paid access was granted.', 'failure');
        return;
      }
      await refreshCurrentPlan();
      if (!restoreTerminal(generation, 'restored_verified', 'Purchase restored and server-verified.', 'success')) return;
      window.dispatchEvent(new CustomEvent('email-shield-profile-changed'));
    } catch (error) {
      restoreTerminal(generation, 'restore_failed', error?.message || String(error), 'failure');
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
    const restoreButton = card.querySelector('#consumerRestorePurchase');
    card.querySelector('#consumerBuyIndividual')?.addEventListener('click', () => { void purchase('individual'); });
    card.querySelector('#consumerBuyFamily')?.addEventListener('click', () => { void purchase('family'); });
    restoreButton?.addEventListener('click', () => { void restore(); });
    if (restoreButton) runtimeTrace?.registerControl(restoreButton, 'billing.purchase.restore', 'billing.purchase.restore', 'billing_restore');
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