(() => {
  const installedModules = window.emailShieldInstalledModules ||= new Set();
  if (installedModules.has('consumer-provider-onboarding')) return;
  installedModules.add('consumer-provider-onboarding');

  // Developer acceptance mode deliberately retains the raw provider/mode
  // controls. Normal consumers must never have to operate the engineering
  // connector that sits underneath the product UI.
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

  // The old selector/mode/button row remains an internal implementation detail.
  // Hiding the entire row, rather than individual fields, prevents a later
  // provider renderer from accidentally exposing Fixture/demo controls.
  legacyRow.hidden = true;
  legacyRow.style.display = 'none';
  legacyRow.setAttribute('aria-hidden', 'true');
  connectBtn.hidden = true;

  let actions = document.getElementById('consumerCredentialActions');
  if (!(actions instanceof HTMLElement)) {
    actions = document.createElement('div');
    actions.id = 'consumerCredentialActions';
    actions.className = 'consumer-actions';
    credentialFields.insertAdjacentElement('afterend', actions);
  }

  const providerOrder = ['gmail', 'outlook', 'icloud', 'yahoo', 'imap'];
  const providerButtons = Array.from(grid.querySelectorAll('button.consumer-provider'));
  const oauthConfiguration = {
    gmail: { path: '/api/accounts/oauth/google/config', label: 'Google' },
    outlook: { path: '/api/accounts/oauth/microsoft/config', label: 'Microsoft' },
  };

  function selectProvider(provider) {
    providerSelect.value = provider;
    modeSelect.value = 'live';
    providerSelect.dispatchEvent(new Event('change', { bubbles: true }));
    modeSelect.dispatchEvent(new Event('change', { bubbles: true }));
    // Consumer onboarding owns visibility. Provider-specific renderers may
    // change labels/disabled state, but they must not expose this legacy row.
    legacyRow.hidden = true;
    legacyRow.style.display = 'none';
    connectBtn.hidden = true;
  }

  function restoreConsumerVisibility() {
    legacyRow.hidden = true;
    legacyRow.style.display = 'none';
    connectBtn.hidden = true;
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
      connectBtn.hidden = true;
      connectBtn.click();
      restoreConsumerVisibility();
      waitForLegacyConnectToSettle(button);
    });
    actions.append(button);
  }

  function startOAuth(provider) {
    actions.replaceChildren();
    const owner = provider === 'gmail'
      ? window.emailShieldGoogleOAuth
      : window.emailShieldMicrosoftOAuth;
    if (!owner || typeof owner.start !== 'function') {
      connectStatus.textContent = `${provider === 'gmail' ? 'Google' : 'Microsoft'} sign-in is unavailable in this build.`;
      return;
    }
    // OAuth ownership stays in the hardened provider module. Calling it
    // directly preserves the user's click gesture for popup handling and avoids
    // the old synthetic-click dependency on an invisible engineering button.
    void owner.start();
    restoreConsumerVisibility();
  }

  function setOAuthButtonState(provider, configured) {
    const index = providerOrder.indexOf(provider);
    const button = providerButtons[index];
    if (!(button instanceof HTMLButtonElement)) return;
    const description = button.querySelector('div span');
    if (description instanceof HTMLElement && !description.dataset.originalText) {
      description.dataset.originalText = description.textContent || '';
    }
    button.disabled = !configured;
    button.setAttribute('aria-disabled', String(!configured));
    button.dataset.oauthConfigured = String(configured);
    if (configured) {
      button.removeAttribute('title');
      if (description instanceof HTMLElement) description.textContent = description.dataset.originalText || '';
    } else {
      const label = oauthConfiguration[provider].label;
      button.title = `${label} sign-in is not available in this build.`;
      if (description instanceof HTMLElement) description.textContent = `${label} sign-in · unavailable in this build`;
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

  providerButtons.forEach((button, index) => {
    const provider = providerOrder[index];
    if (!provider) return;
    button.dataset.consumerProvider = provider;
    if (oauthConfiguration[provider]) {
      const description = button.querySelector('div span');
      if (description instanceof HTMLElement) {
        description.dataset.originalText = description.textContent || '';
        description.textContent = `Checking ${oauthConfiguration[provider].label} sign-in…`;
      }
      button.disabled = true;
      button.setAttribute('aria-disabled', 'true');
    }

    // Capture phase makes this module authoritative over the older
    // consumer-product compatibility handler. That handler used to reveal the
    // hidden engineering Connect control and defer OAuth through a synthetic
    // click. Normal consumer actions now terminate here.
    button.addEventListener('click', (event) => {
      event.preventDefault();
      event.stopImmediatePropagation();
      connectStatus.textContent = '';
      actions.replaceChildren();
      selectProvider(provider);

      if (provider === 'gmail' || provider === 'outlook') {
        if (button.dataset.oauthConfigured !== 'true') {
          connectStatus.textContent = `${oauthConfiguration[provider].label} sign-in is unavailable in this build.`;
          return;
        }
        startOAuth(provider);
        return;
      }

      renderCredentialAction(provider);
      credentialFields.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }, true);
  });

  // A defensive observer keeps the legacy row private if another compatibility
  // module mutates hidden/display state after provider changes.
  const observer = new MutationObserver(restoreConsumerVisibility);
  observer.observe(legacyRow, { attributes: true, attributeFilter: ['hidden', 'style'] });

  restoreConsumerVisibility();
  void loadOAuthAvailability('gmail');
  void loadOAuthAvailability('outlook');
})();
