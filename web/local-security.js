(() => {
  const meta = document.querySelector('meta[name="email-shield-csrf"]');
  const csrfToken = meta?.getAttribute('content') || '';
  meta?.remove();
  if (!csrfToken) throw new Error('Email Shield local security did not initialize. Reload the dashboard.');

  const originalFetch = window.fetch.bind(window);
  const protectedPath = (path) =>
    path.startsWith('/api/accounts') ||
    path.startsWith('/api/profile') ||
    path.startsWith('/api/dev') ||
    path.startsWith('/api/operations') ||
    path.startsWith('/api/scam-check') ||
    path.startsWith('/api/security');
  const analysisOnlyPath = (path) => path.startsWith('/api/scam-check/');
  const unsafeMethod = (method) => !['GET', 'HEAD', 'OPTIONS'].includes(method.toUpperCase());

  function requestMethod(input, init) {
    if (init?.method) return String(init.method).toUpperCase();
    if (input instanceof Request) return input.method.toUpperCase();
    return 'GET';
  }

  function mergedHeaders(input, init) {
    const headers = new Headers(input instanceof Request ? input.headers : undefined);
    new Headers(init?.headers || undefined).forEach((value, name) => headers.set(name, value));
    headers.set('X-Email-Shield-CSRF', csrfToken);
    return headers;
  }

  function requestActionToken(init) {
    if (typeof init?.body !== 'string') return null;
    try {
      const parsed = JSON.parse(init.body);
      return typeof parsed?.token === 'string' ? parsed.token : null;
    } catch {
      return null;
    }
  }

  function disableUsedAction(token) {
    if (!token) return;
    let selector;
    try { selector = CSS.escape(token); }
    catch { return; }
    document.querySelectorAll(
      `[data-review-token="${selector}"],[data-unsubscribe-token="${selector}"]`,
    ).forEach((element) => {
      if (element instanceof HTMLButtonElement) {
        element.disabled = true;
        if (!/✓|complete|reported|blocked|trusted|safe/i.test(element.textContent || '')) {
          element.textContent = 'Action used — rescan';
        }
      }
    });
  }

  async function mutationNonce() {
    const response = await originalFetch('/api/security/mutation-token', {
      method: 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
      headers: { 'X-Email-Shield-CSRF': csrfToken },
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok || typeof body.nonce !== 'string') {
      throw new Error(body.error || 'Could not authorize the local Email Shield action. Reload the dashboard.');
    }
    return body.nonce;
  }

  window.fetch = async function emailShieldProtectedFetch(input, init = {}) {
    const rawUrl = typeof input === 'string' || input instanceof URL ? String(input) : input.url;
    const url = new URL(rawUrl, window.location.href);
    if (url.origin !== window.location.origin || !protectedPath(url.pathname)) {
      return originalFetch(input, init);
    }

    const method = requestMethod(input, init);
    const headers = mergedHeaders(input, init);
    const options = { ...init, method, headers, credentials: 'same-origin', cache: init.cache || 'no-store' };
    const isNonceRequest = url.pathname === '/api/security/mutation-token';
    const token = requestActionToken(init);

    if (unsafeMethod(method) && !isNonceRequest && !analysisOnlyPath(url.pathname)) {
      headers.set('X-Email-Shield-Nonce', await mutationNonce());
    }

    const response = await originalFetch(input, options);
    if (response.status === 401) {
      window.dispatchEvent(new CustomEvent('email-shield-session-expired'));
    }
    if (token) {
      response.clone().json().then((body) => {
        if (response.ok || body?.localProtected === true) disableUsedAction(token);
      }).catch(() => {});
    }
    return response;
  };

  window.addEventListener('email-shield-session-expired', () => {
    const status = document.getElementById('scanMonitorStatus');
    if (status) {
      status.textContent = 'The protected local session expired. Reload Email Shield before continuing.';
      status.className = 'scan-monitor-status error';
    }
  });

  Object.defineProperty(window, 'emailShieldSecureFetchInstalled', {
    value: true,
    writable: false,
    configurable: false,
    enumerable: false,
  });
})();
