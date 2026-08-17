(() => {
  const installedModules = window.emailShieldInstalledModules ||= new Set();
  if (installedModules.has('consumer-provider-onboarding')) return;
  installedModules.add('consumer-provider-onboarding');

  // Developer acceptance mode deliberately retains the raw provider/mode
  // controls, including Microsoft/Outlook. Normal consumer acceptance currently
  // exposes only providers whose live onboarding is ready for owner testing.
  if (new URLSearchParams(location.search).get('developer') === '1') return;

  const providerSelect = document.getElementById('providerSelect');
  const modeSelect = document.getElementById('modeSelect');
  const connectBtn = document.getElementById('connectBtn');
  const credentialFields = document.getElementById('credentialFields');
  const connectStatus = document.getElementById('connectStatus');
  const grid = document.querySelector('.consumer-provider-grid');
  const legacyRow = providerSelect?.closest('.row');

  if (!(providerSelect instanceof HTMLSelectElement)
      || !(modeSelect instanceof HTMLSelectElement)
      || !(connectBtn instanceof HTMLButtonElement)
      || !(credentialFields instanceof HTMLElement)
      || !(connectStatus instanceof HTMLElement)
      || !(grid instanceof HTMLElement)
      || !(legacyRow instanceof HTMLElement)) return;

  let actions = document.getElementById('consumerCredentialActions');
  if (!(actions instanceof HTMLElement)) {
    actions = document.createElement('div');
    actions.id = 'consumerCredentialActions';
    actions.className = 'consumer-actions';
    credentialFields.insertAdjacentElement('afterend', actions);
  }

  // Bind consumer cards by their declared identity, never by DOM position. This
  // prevents removing/defering one provider from silently remapping another
  // card to the wrong authorization handler.
  const providerByTitle = new Map([
    ['Continue with Google', 'gmail'],
    ['Continue with Microsoft', 'outlook'],
    ['Add iCloud Mail', 'icloud'],
    ['Add Yahoo Mail', 'yahoo'],
    ['Other email provider', 'imap'],
  ]);
  const discoveredButtons = Array.from(grid.querySelectorAll('button.consumer-provider'));
  const providerButtons = new Map();
  for (const button of discoveredButtons) {
    if (!(button instanceof HTMLButtonElement)) continue;
    const title = button.querySelector('strong')?.textContent?.trim() || '';
    const provider = providerByTitle.get(title);
    if (!provider) continue;
    button.dataset.consumerProvider = provider;
    providerButtons.set(provider, button);
  }

  // Microsoft remains implemented internally for later acceptance, but it is
  // intentionally absent from the normal consumer journey until that live path
  // is provisioned and owner-accepted. Developer mode above keeps it reachable.
  providerButtons.get('outlook')?.remove();
  providerButtons.delete('outlook');

  const setupGuidance = document.createElement('div');
  setupGuidance.id = 'consumerProviderSetupGuidance';
  setupGuidance.className = 'consumer-card';
  setupGuidance.hidden = true;
  setupGuidance.setAttribute('role', 'status');
  setupGuidance.setAttribute('aria-live', 'polite');
  grid.insertAdjacentElement('beforebegin', setupGuidance);

  const setupGuidanceByReason = new Map([
    ['connect', 'Choose a provider below and finish its sign-in or app-password steps. This setup item completes only after Email Shield sees that mailbox connected and selected.'],
    ['permissions', 'Connect and select a mailbox first. Then Email Shield can show the permission promise for the provider you are actually using.'],
    ['scan', 'Connect and select a mailbox first. Then return to Check & Scan to establish the first protection baseline.'],
    ['sensitivity', 'Connect and select a mailbox first. Protection sensitivity is saved to the selected mailbox and cannot be applied before one is connected.'],
    ['background', 'Connect and select a mailbox first. Background Protection is configured per mailbox and completes only after the enabled state is observed.'],
    ['family', 'Connect and select a mailbox first so this setup choice is saved to the correct mailbox before you review or skip Family Shield.'],
    ['home', 'Connect and select a mailbox first. The protection home cannot be confirmed until all required mailbox setup steps are complete.'],
  ]);

  function showSetupGuidance(reason) {
    const message = setupGuidanceByReason.get(reason)
      || 'Connect and select a mailbox first. Choose one of the available providers below to continue setup.';
    const heading = document.createElement('strong');
    heading.textContent = 'Connect a mailbox to continue';
    const copy = document.createElement('p');
    copy.textContent = message;
    setupGuidance.replaceChildren(heading, copy);
    setupGuidance.hidden = false;
    grid.scrollIntoView({ behavior: 'smooth', block: 'center' });
    const firstAvailableProvider = [...providerButtons.values()].find((button) => button instanceof HTMLButtonElement && !button.hidden);
    if (firstAvailableProvider instanceof HTMLButtonElement) firstAvailableProvider.focus({ preventScroll: true });
  }

  window.addEventListener('email-shield-provider-setup-requested', (event) => {
    const reason = event instanceof CustomEvent && typeof event.detail?.reason === 'string'
      ? event.detail.reason
      : 'generic';
    showSetupGuidance(reason);
  });

  const oauthConfiguration = {
    gmail: { path: '/api/accounts/oauth/google/config', label: 'Google' },
  };

  // This guard is deliberately idempotent. A MutationObserver watches the
  // legacy row for compatibility code that tries to reveal it, so writing the
  // same watched attributes unconditionally would create a self-triggering
  // mutation loop and hang the browser renderer.
  function restoreConsumerVisibility() {
    if (!legacyRow.hidden) legacyRow.hidden = true;
    if (legacyRow.style.display !== 'none') legacyRow.style.display = 'none';
    if (legacyRow.getAttribute('aria-hidden') !== 'true') legacyRow.setAttribute('aria-hidden', 'true');
    if (!connectBtn.hidden) connectBtn.hidden = true;
  }

  function selectProvider(provider) {
    providerSelect.value = provider;
    modeSelect.value = 'live';
    providerSelect.dispatchEvent(new Event('change', { bubbles: true }));
    modeSelect.dispatchEvent(new Event('change', { bubbles: true }));
    restoreConsumerVisibility();
  }

  function waitForLegacyConnectToSettle(button) {
    let frames = 0;
    const poll = () => {
      frames += 1;
      restoreConsumerVisibility();
      if (!connectBtn.disabled || frames > 1200) {
        button.disabled = false;
        return;
      }
      requestAnimationFrame(poll);
    };
    requestAnimationFrame(poll);
  }

  function renderCredentialAction(provider) {
    actions.replaceChildren();
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'primary';
    button.textContent = provider === 'icloud'
      ? 'Connect iCloud Mail'
      : provider === 'yahoo'
        ? 'Connect Yahoo Mail'
        : 'Connect email provider';
    button.addEventListener('click', () => {
      button.disabled = true;
      connectBtn.click();
      restoreConsumerVisibility();
      waitForLegacyConnectToSettle(button);
    });
    actions.append(button);
  }

  function startGoogleOAuth() {
    actions.replaceChildren();
    const owner = window.emailShieldGoogleOAuth;
    if (!owner || typeof owner.start !== 'function') {
      connectStatus.textContent = 'Google sign-in is unavailable in this running Email Shield session.';
      return;
    }
    void owner.start();
    restoreConsumerVisibility();
  }

  function setOAuthButtonState(provider, configured) {
    const button = providerButtons.get(provider);
    if (!(button instanceof HTMLButtonElement)) return;
    const description = button.querySelector('div span');
    if (description instanceof HTMLElement && !description.dataset.originalText) {
      description.dataset.originalText = description.textContent || '';
    }

    // Readiness is information, not permission to interact with the control.
    // A native disabled button suppresses click/focus events entirely, which
    // previously trapped the owner with no way to retry or see why Google was
    // unavailable after one failed readiness probe. The hardened OAuth owner
    // and server remain the authorization boundary; this card stays actionable.
    button.disabled = false;
    button.setAttribute('aria-disabled', 'false');
    button.dataset.oauthConfigured = String(configured);
    if (configured) {
      button.removeAttribute('title');
      if (description instanceof HTMLElement) description.textContent = description.dataset.originalText || '';
    } else {
      const label = oauthConfiguration[provider].label;
      button.title = `Click to re-check ${label} sign-in availability.`;
      if (description instanceof HTMLElement) description.textContent = `${label} sign-in · click to re-check setup`;
    }
  }

  async function loadOAuthAvailability(provider) {
    const configuration = oauthConfiguration[provider];
    if (!configuration) return;
    try {
      const response = await fetch(configuration.path, { cache: 'no-store' });
      const body = await response.json().catch(() => ({}));
      setOAuthButtonState(provider, response.ok && body.configured === true);
    } catch {
      setOAuthButtonState(provider, false);
    }
  }

  for (const [provider, button] of providerButtons) {
    if (oauthConfiguration[provider]) {
      const description = button.querySelector('div span');
      if (description instanceof HTMLElement) {
        description.dataset.originalText = description.textContent || '';
        description.textContent = `Checking ${oauthConfiguration[provider].label} sign-in…`;
      }
      button.disabled = false;
      button.setAttribute('aria-disabled', 'false');
      button.dataset.oauthConfigured = 'checking';
    }

    // Capture phase makes this module authoritative over the older
    // consumer-product compatibility handler. Normal consumer actions terminate
    // here and never synthesize a click into a provider with a different ID.
    button.addEventListener('click', (event) => {
      event.preventDefault();
      event.stopImmediatePropagation();
      connectStatus.textContent = '';
      setupGuidance.hidden = true;
      actions.replaceChildren();
      selectProvider(provider);

      if (provider === 'gmail') {
        // Never gate the user's click on a cached browser-side readiness probe.
        // The OAuth owner performs a fresh protected check and the server is the
        // final fail-closed authority for whether authorization can start.
        startGoogleOAuth();
        return;
      }

      renderCredentialAction(provider);
      credentialFields.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }, true);
  }

  const observer = new MutationObserver(restoreConsumerVisibility);
  observer.observe(legacyRow, { attributes: true, attributeFilter: ['hidden', 'style', 'aria-hidden'] });

  restoreConsumerVisibility();
  void loadOAuthAvailability('gmail');
})();