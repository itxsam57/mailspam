(() => {
  const providerSelect = document.getElementById('providerSelect');
  const modeSelect = document.getElementById('modeSelect');
  const connectBtn = document.getElementById('connectBtn');
  const credentialFields = document.getElementById('credentialFields');
  if (!(providerSelect instanceof HTMLSelectElement) ||
      !(modeSelect instanceof HTMLSelectElement) ||
      !(connectBtn instanceof HTMLButtonElement) ||
      !(credentialFields instanceof HTMLElement)) return;

  let microsoftConfigured = null;
  let activeFlowId = null;
  let pollGeneration = 0;

  const isGuidedOutlook = () => providerSelect.value === 'outlook' && modeSelect.value === 'live';

  function statusElement() {
    let element = document.getElementById('outlookOAuthStatus');
    if (!element) {
      element = document.createElement('div');
      element.id = 'outlookOAuthStatus';
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
      const response = await fetch('/api/accounts/oauth/microsoft/config');
      const body = await response.json().catch(() => ({}));
      microsoftConfigured = response.ok && body.configured === true;
    } catch {
      microsoftConfigured = false;
    }
    if (isGuidedOutlook()) renderGuidedState();
  }

  function renderGuidedState() {
    if (!isGuidedOutlook()) return;
    connectBtn.textContent = 'Continue with Microsoft';
    connectBtn.disabled = false;
    if (activeFlowId) {
      setStatus('Complete the Microsoft consent window. Email Shield is waiting for the one-time local PKCE callback…');
    } else if (microsoftConfigured === false) {
      setStatus('Microsoft OAuth is not configured in this development build. Set the Email Shield Microsoft public-client ID and restart the app.');
    } else if (microsoftConfigured === true) {
      setStatus('Microsoft opens in a separate browser window. Email Shield uses a public desktop client, PKCE and a one-time local callback; your Microsoft password is never given to Email Shield.');
    } else {
      setStatus('Checking Microsoft OAuth configuration…');
    }
  }

  function restoreNormalConnectLabel() {
    if (!isGuidedOutlook() && !connectBtn.disabled && providerSelect.value !== 'gmail') connectBtn.textContent = 'Connect';
  }

  async function pollFlow(flowId, generation) {
    while (activeFlowId === flowId && generation === pollGeneration) {
      await new Promise((resolve) => setTimeout(resolve, 750));
      let response;
      let body;
      try {
        response = await fetch(`/api/accounts/oauth/microsoft/status/${encodeURIComponent(flowId)}`);
        body = await response.json().catch(() => ({}));
      } catch {
        if (activeFlowId !== flowId) return;
        setStatus('Could not read Microsoft authorization status. The local session may need to be reloaded.');
        continue;
      }

      if (!response.ok || body.status === 'error') {
        activeFlowId = null;
        connectBtn.disabled = false;
        setStatus(body.error || 'Microsoft authorization failed. Start again.');
        return;
      }
      if (body.status === 'complete') {
        activeFlowId = null;
        connectBtn.disabled = false;
        connectBtn.textContent = 'Continue with Microsoft';
        setStatus(`Connected ${body.label || 'Outlook'} securely.`);
        if (typeof window.refreshAccounts === 'function') await window.refreshAccounts();
        if (typeof window.selectAccount === 'function' && typeof body.accountId === 'string') {
          window.selectAccount(body.accountId);
        }
        return;
      }
    }
  }

  async function startGuidedMicrosoftOAuth() {
    if (activeFlowId) return;
    if (microsoftConfigured === false) {
      setStatus('Microsoft OAuth is not configured for this build. Configure the public desktop client ID and restart Email Shield.');
      return;
    }

    const popup = window.open('about:blank', 'emailShieldMicrosoftOAuth', 'popup=yes,width=720,height=760');
    if (!popup) {
      setStatus('Your browser blocked the Microsoft window. Allow popups for this local Email Shield page and try again.');
      return;
    }
    try {
      popup.document.title = 'Email Shield — Microsoft';
      popup.document.body.textContent = 'Preparing secure Microsoft authorization…';
    } catch {}

    connectBtn.disabled = true;
    connectBtn.textContent = 'Waiting for Microsoft…';
    setStatus('Creating a one-time public-client PKCE authorization request…');

    try {
      const response = await fetch('/api/accounts/oauth/microsoft/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.error || 'Could not start Microsoft authorization.');
      if (typeof body.flowId !== 'string' || typeof body.authorizationUrl !== 'string') {
        throw new Error('Email Shield returned an invalid Microsoft authorization request.');
      }
      const authorizationUrl = new URL(body.authorizationUrl);
      if (authorizationUrl.protocol !== 'https:' || authorizationUrl.hostname !== 'login.microsoftonline.com') {
        throw new Error('Email Shield refused an unexpected Microsoft authorization destination.');
      }

      activeFlowId = body.flowId;
      pollGeneration += 1;
      renderGuidedState();
      popup.location.replace(authorizationUrl.href);
      void pollFlow(body.flowId, pollGeneration);
    } catch (error) {
      activeFlowId = null;
      connectBtn.disabled = false;
      connectBtn.textContent = 'Continue with Microsoft';
      setStatus(error instanceof Error ? error.message : String(error));
      try { popup.close(); } catch {}
    }
  }

  connectBtn.addEventListener('click', (event) => {
    if (!isGuidedOutlook()) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    void startGuidedMicrosoftOAuth();
  }, true);

  for (const select of [providerSelect, modeSelect]) {
    select.addEventListener('change', () => {
      setTimeout(() => {
        if (isGuidedOutlook()) renderGuidedState();
        else restoreNormalConnectLabel();
      }, 0);
    });
  }

  if (isGuidedOutlook()) renderGuidedState();
  void loadConfiguration();
})();
