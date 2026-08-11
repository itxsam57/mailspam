(() => {
  const providerSelect = document.getElementById('providerSelect');
  const modeSelect = document.getElementById('modeSelect');
  const connectBtn = document.getElementById('connectBtn');
  const credentialFields = document.getElementById('credentialFields');
  if (!(providerSelect instanceof HTMLSelectElement) ||
      !(modeSelect instanceof HTMLSelectElement) ||
      !(connectBtn instanceof HTMLButtonElement) ||
      !(credentialFields instanceof HTMLElement)) return;

  let googleConfigured = null;
  let activeFlowId = null;
  let pollGeneration = 0;

  const isGuidedGmail = () => providerSelect.value === 'gmail' && modeSelect.value === 'live';

  function statusElement() {
    let element = document.getElementById('gmailOAuthStatus');
    if (!element) {
      element = document.createElement('div');
      element.id = 'gmailOAuthStatus';
      element.className = 'hint';
      element.setAttribute('role', 'status');
      element.setAttribute('aria-live', 'polite');
      element.setAttribute('aria-atomic', 'true');
      credentialFields.replaceChildren(element);
    }
    return element;
  }

  function setStatus(message) {
    statusElement().textContent = message;
  }

  async function loadConfiguration() {
    try {
      const response = await fetch('/api/accounts/oauth/google/config');
      const body = await response.json().catch(() => ({}));
      googleConfigured = response.ok && body.configured === true;
    } catch {
      googleConfigured = false;
    }
    if (isGuidedGmail()) renderGuidedState();
  }

  function renderGuidedState() {
    if (!isGuidedGmail()) return;
    connectBtn.textContent = 'Continue with Google';
    connectBtn.disabled = false;
    if (activeFlowId) {
      setStatus('Complete the Google consent window. Email Shield is waiting for the protected loopback callback…');
    } else if (googleConfigured === false) {
      setStatus('Google OAuth is not configured in this development build. Set the Email Shield desktop OAuth client ID and restart the app.');
    } else if (googleConfigured === true) {
      setStatus('Google opens in a separate browser window. Email Shield uses PKCE and a one-time local callback; your Google password is never given to Email Shield.');
    } else {
      setStatus('Checking Google OAuth configuration…');
    }
  }

  function restoreNormalConnectLabel() {
    if (!isGuidedGmail() && !connectBtn.disabled) connectBtn.textContent = 'Connect';
  }

  async function pollFlow(flowId, generation) {
    while (activeFlowId === flowId && generation === pollGeneration) {
      await new Promise((resolve) => setTimeout(resolve, 750));
      let response;
      let body;
      try {
        response = await fetch(`/api/accounts/oauth/google/status/${encodeURIComponent(flowId)}`);
        body = await response.json().catch(() => ({}));
      } catch {
        if (activeFlowId !== flowId) return;
        setStatus('Could not read Google authorization status. The local session may need to be reloaded.');
        continue;
      }

      if (!response.ok || body.status === 'error') {
        activeFlowId = null;
        connectBtn.disabled = false;
        setStatus(body.error || 'Google authorization failed. Start again.');
        return;
      }
      if (body.status === 'complete') {
        activeFlowId = null;
        connectBtn.disabled = false;
        connectBtn.textContent = 'Continue with Google';
        setStatus(`Connected ${body.label || 'Gmail'} securely.`);
        if (typeof window.refreshAccounts === 'function') await window.refreshAccounts();
        if (typeof window.selectAccount === 'function' && typeof body.accountId === 'string') {
          window.selectAccount(body.accountId);
        }
        return;
      }
    }
  }

  async function startGuidedGoogleOAuth() {
    if (activeFlowId) return;
    if (googleConfigured === false) {
      setStatus('Google OAuth is not configured for this build. Configure the desktop client ID and restart Email Shield.');
      return;
    }

    // Open synchronously from the click so popup blocking cannot force Email
    // Shield to navigate the protected dashboard away from localhost.
    const popup = window.open('about:blank', 'emailShieldGoogleOAuth', 'popup=yes,width=720,height=760');
    if (!popup) {
      setStatus('Your browser blocked the Google window. Allow popups for this local Email Shield page and try again.');
      return;
    }
    try {
      popup.document.title = 'Email Shield — Google';
      popup.document.body.textContent = 'Preparing secure Google authorization…';
    } catch {}

    connectBtn.disabled = true;
    connectBtn.textContent = 'Waiting for Google…';
    setStatus('Creating a one-time PKCE authorization request…');

    try {
      const response = await fetch('/api/accounts/oauth/google/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.error || 'Could not start Google authorization.');
      if (typeof body.flowId !== 'string' || typeof body.authorizationUrl !== 'string') {
        throw new Error('Email Shield returned an invalid Google authorization request.');
      }
      const authorizationUrl = new URL(body.authorizationUrl);
      if (authorizationUrl.protocol !== 'https:' || authorizationUrl.origin !== 'https://accounts.google.com') {
        throw new Error('Email Shield refused an unexpected Google authorization destination.');
      }

      activeFlowId = body.flowId;
      pollGeneration += 1;
      renderGuidedState();
      popup.location.replace(authorizationUrl.href);
      void pollFlow(body.flowId, pollGeneration);
    } catch (error) {
      activeFlowId = null;
      connectBtn.disabled = false;
      connectBtn.textContent = 'Continue with Google';
      setStatus(error instanceof Error ? error.message : String(error));
      try { popup.close(); } catch {}
    }
  }

  // Capture phase prevents the legacy live-Gmail click handler from sending an
  // empty credential payload to /api/accounts/connect.
  connectBtn.addEventListener('click', (event) => {
    if (!isGuidedGmail()) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    void startGuidedGoogleOAuth();
  }, true);

  for (const select of [providerSelect, modeSelect]) {
    select.addEventListener('change', () => {
      // Run after the legacy field renderer so guided Gmail can replace only
      // that provider's old developer-flow hint without redesigning the panel.
      setTimeout(() => {
        if (isGuidedGmail()) renderGuidedState();
        else restoreNormalConnectLabel();
      }, 0);
    });
  }

  if (isGuidedGmail()) renderGuidedState();
  void loadConfiguration();
})();
