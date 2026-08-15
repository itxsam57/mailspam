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
    // gmail-oauth.js / outlook-oauth.js own the secure popup, PKCE, one-time
    // callback and provider validation. Triggering the internal button here is
    // only a module boundary; the consumer never sees or operates that control.
    // It remains a synchronous click so popup blockers still recognize the
    // user gesture.
    connectBtn.hidden = true;
    connectBtn.click();
    restoreConsumerVisibility();
  }

  providerButtons.forEach((button, index) => {
    const provider = providerOrder[index];
    if (!provider) return;
    button.dataset.consumerProvider = provider;

    // Capture phase makes this module authoritative over the older
    // consumer-product compatibility handler. That handler used to reveal the
    // hidden engineering Connect control for credential providers and used a
    // deferred synthetic click for OAuth providers.
    button.addEventListener('click', (event) => {
      event.preventDefault();
      event.stopImmediatePropagation();
      connectStatus.textContent = '';
      actions.replaceChildren();
      selectProvider(provider);

      if (provider === 'gmail' || provider === 'outlook') {
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
})();
