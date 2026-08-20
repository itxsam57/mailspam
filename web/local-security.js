(() => {
  const meta = document.querySelector('meta[name="email-shield-csrf"]');
  const csrfToken = meta?.getAttribute('content') || '';
  meta?.remove();
  if (!csrfToken) throw new Error('Email Shield local security did not initialize. Reload the dashboard.');

  const originalFetch = window.fetch.bind(window);
  const protectedPath = (path) =>
    path.startsWith('/api/accounts') ||
    path.startsWith('/api/profile') ||
    path.startsWith('/api/consumer') ||
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
    const traceId = window.emailShieldRuntimeTrace?.currentTraceId?.();
    if (traceId) headers.set('X-Email-Shield-Trace-Id', traceId);
    return headers;
  }

  function dashboardProvenance() {
    // The document intentionally uses Referrer-Policy: no-referrer so ordinary
    // navigation cannot leak local dashboard paths. Protected same-origin API
    // requests are the one exception: the server requires browser provenance
    // in addition to the HttpOnly session and CSRF token. RequestInit.referrer
    // is browser-controlled and cannot be forged by a cross-origin page.
    return {
      credentials: 'same-origin',
      cache: 'no-store',
      referrer: `${window.location.origin}/`,
      referrerPolicy: 'same-origin',
    };
  }

  async function mutationNonce() {
    const response = await originalFetch('/api/security/mutation-token', {
      ...dashboardProvenance(),
      method: 'POST',
      headers: { 'X-Email-Shield-CSRF': csrfToken },
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok || typeof body.nonce !== 'string') {
      throw new Error(body.error || 'Could not authorize the local Email Shield action. Reload the dashboard.');
    }
    return body.nonce;
  }

  // Runtime tracing is optional diagnostics. Probe its protected local config
  // before sending events so a normal trace-disabled consumer session never
  // generates repeated 404s. Rate limiting backs diagnostics off without
  // affecting product requests or weakening their security boundary.
  let traceAvailability = 'unknown';
  let traceAvailabilityPromise = null;
  let traceRetryAt = 0;

  function traceBackoffMs(response, fallbackMs) {
    const retryAfter = Number(response?.headers?.get?.('Retry-After'));
    if (Number.isFinite(retryAfter) && retryAfter > 0 && retryAfter <= 3600) return retryAfter * 1000;
    return fallbackMs;
  }

  async function runtimeTraceAvailable() {
    if (Date.now() < traceRetryAt) return false;
    if (traceAvailability === 'disabled') return false;
    if (traceAvailability === 'enabled') return true;
    if (traceAvailabilityPromise) return traceAvailabilityPromise;

    traceAvailabilityPromise = (async () => {
      try {
        const response = await originalFetch('/api/dev/runtime-trace/config', {
          ...dashboardProvenance(),
          method: 'GET',
          headers: { 'X-Email-Shield-CSRF': csrfToken },
        });
        if (response.status === 429) {
          traceRetryAt = Date.now() + traceBackoffMs(response, 60_000);
          return false;
        }
        if (!response.ok) {
          traceAvailability = 'disabled';
          return false;
        }
        const body = await response.json().catch(() => ({}));
        traceAvailability = body.enabled === true ? 'enabled' : 'disabled';
        return traceAvailability === 'enabled';
      } catch {
        traceRetryAt = Date.now() + 30_000;
        return false;
      } finally {
        traceAvailabilityPromise = null;
      }
    })();
    return traceAvailabilityPromise;
  }

  Object.defineProperty(window, 'emailShieldRuntimeTraceTransport', {
    value: async (event) => {
      if (!await runtimeTraceAvailable()) return;
      try {
        const response = await originalFetch('/api/dev/runtime-trace/events', {
          ...dashboardProvenance(),
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Email-Shield-CSRF': csrfToken,
          },
          body: JSON.stringify(event),
        });
        if (response.status === 429) {
          traceRetryAt = Date.now() + traceBackoffMs(response, 60_000);
        } else if (response.status === 404) {
          traceAvailability = 'disabled';
        }
      } catch {
        traceRetryAt = Date.now() + 30_000;
      }
    },
    writable: false,
    configurable: false,
    enumerable: false,
  });

  window.fetch = async function emailShieldProtectedFetch(input, init = {}) {
    const rawUrl = typeof input === 'string' || input instanceof URL ? String(input) : input.url;
    const url = new URL(rawUrl, window.location.href);
    if (url.origin !== window.location.origin || !protectedPath(url.pathname)) {
      return originalFetch(input, init);
    }

    const method = requestMethod(input, init);
    const headers = mergedHeaders(input, init);
    const options = {
      ...init,
      ...dashboardProvenance(),
      method,
      headers,
    };
    const isNonceRequest = url.pathname === '/api/security/mutation-token';
    const traceRequest = window.emailShieldRuntimeTrace?.apiRequest?.(method, url.pathname) || null;

    if (unsafeMethod(method) && !isNonceRequest && !analysisOnlyPath(url.pathname)) {
      headers.set('X-Email-Shield-Nonce', await mutationNonce());
    }

    let response;
    try {
      response = await originalFetch(input, options);
      window.emailShieldRuntimeTrace?.apiResponse?.(traceRequest, response.status);
    } catch (error) {
      window.emailShieldRuntimeTrace?.apiResponse?.(traceRequest, 599);
      throw error;
    }
    if (response.status === 401) {
      window.dispatchEvent(new CustomEvent('email-shield-session-expired'));
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
