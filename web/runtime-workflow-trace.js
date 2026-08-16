(() => {
  const installedModules = window.emailShieldInstalledModules ||= new Set();
  if (installedModules.has('runtime-workflow-trace')) return;
  installedModules.add('runtime-workflow-trace');

  const TRACE_WINDOW_MS = 30_000;
  const PROVIDERS = new Set(['gmail', 'icloud', 'yahoo', 'imap', 'outlook']);
  const SCAN_TYPES = new Set(['quick', 'full', 'spam']);
  const STATIC_CONTROLS = Object.freeze({
    connectBtn: ['account.connect', 'provider_connection'],
    quickScanBtn: ['mailbox.scan.quick', 'quick_mailbox_scan'],
    fullScanBtn: ['mailbox.scan.full', 'full_mailbox_audit'],
    spamScanBtn: ['mailbox.scan.spam', 'spam_junk_scan'],
    stopScanBtn: ['mailbox.scan.stop', 'scan_stop'],
    backgroundToggle: ['protection.background.toggle', 'background_protection'],
    backgroundInterval: ['protection.background.interval', 'background_protection'],
    saveSettingsBtn: ['settings.save', 'settings_persistence'],
    scamCheckButton: ['scam_check.run', 'scam_check'],
    familyShieldButton: ['family.open', 'family_shield'],
    disconnectAccountBtn: ['account.disconnect', 'account_disconnect'],
  });
  const ACTION_CONTROLS = Object.freeze({
    'block-sender': ['message.block_sender', 'message_policy_action'],
    'block-domain': ['message.block_domain', 'message_policy_action'],
    trash: ['message.trash', 'provider_message_mutation'],
    'report-scam': ['message.report_scam', 'scam_report'],
    'move-spam': ['message.move_spam', 'provider_message_mutation'],
    'mark-safe': ['message.mark_safe', 'personal_message_approval'],
    'trust-sender': ['message.trust_sender', 'personal_sender_trust'],
    unsubscribe: ['message.unsubscribe', 'unsubscribe_workflow'],
    'analyze-links': ['message.analyze_links', 'destination_analysis'],
  });
  const ROUTE_CONTROLS = new Set([
    'home', 'scan', 'protection', 'family', 'check', 'settings', 'activity', 'account',
  ]);

  let active = null;

  function validProvider(value) {
    return typeof value === 'string' && PROVIDERS.has(value) ? value : undefined;
  }

  function scanTypeFor(actionId) {
    const candidate = actionId.split('.').at(-1);
    return SCAN_TYPES.has(candidate) ? candidate : undefined;
  }

  function current() {
    if (!active || Date.now() - active.startedAt > TRACE_WINDOW_MS) {
      active = null;
      return null;
    }
    return active;
  }

  function transport(event) {
    const send = window.emailShieldRuntimeTraceTransport;
    if (typeof send !== 'function') return;
    try { void send(event); } catch {}
  }

  function begin(actionId, expectedWorkflow, provider) {
    const traceId = crypto.randomUUID();
    active = Object.freeze({
      traceId,
      actionId,
      expectedWorkflow,
      provider: validProvider(provider),
      scanType: scanTypeFor(actionId),
      startedAt: Date.now(),
    });
    transport({
      traceId,
      stage: 'ui_action',
      actionId,
      expectedWorkflow,
      ...(active.provider ? { provider: active.provider } : {}),
      ...(active.scanType ? { scanType: active.scanType } : {}),
      component: 'browser',
      step: 'button_pressed',
      outcome: 'started',
    });
    return active;
  }

  function semanticControl(button) {
    if (button.id && STATIC_CONTROLS[button.id]) return STATIC_CONTROLS[button.id];

    const provider = validProvider(button.dataset.consumerProvider);
    if (provider) return [`provider.connect.${provider}`, 'provider_connection'];

    const action = button.getAttribute('data-action');
    if (action && ACTION_CONTROLS[action]) return ACTION_CONTROLS[action];

    const route = button.getAttribute('data-route-target');
    if (route && ROUTE_CONTROLS.has(route)) return [`navigation.${route}`, 'ui_navigation'];

    if (button.hasAttribute('data-select')) return ['account.select', 'workspace_account_selection'];
    if (button.classList.contains('consumer-provider')) return ['provider.connect.unknown', 'provider_connection'];
    return ['ui.unregistered_button', 'ui_action_unknown'];
  }

  function providerFor(button) {
    return validProvider(button.dataset.consumerProvider)
      || validProvider(button.closest('[data-provider]')?.getAttribute('data-provider'));
  }

  function safeRouteTemplate(pathname) {
    if (pathname === '/api/accounts' || pathname === '/api/accounts/connect') return pathname;
    if (pathname === '/api/security/mutation-token') return pathname;
    if (/^\/api\/accounts\/oauth\/google\/status\/[^/]+$/.test(pathname)) return '/api/accounts/oauth/google/status/:flowId';
    if (/^\/api\/accounts\/oauth\/microsoft\/status\/[^/]+$/.test(pathname)) return '/api/accounts/oauth/microsoft/status/:flowId';
    if (/^\/api\/accounts\/[^/]+\/scan\/(quick|full|spam)$/.test(pathname)) return '/api/accounts/:accountId/scan/:type';
    if (/^\/api\/accounts\/[^/]+\/scan\/resume\/[^/]+$/.test(pathname)) return '/api/accounts/:accountId/scan/resume/:scanId';
    if (/^\/api\/accounts\/[^/]+\/scan\/stop$/.test(pathname)) return '/api/accounts/:accountId/scan/stop';
    if (/^\/api\/accounts\/[^/]+\/background-protection$/.test(pathname)) return '/api/accounts/:accountId/background-protection';
    if (/^\/api\/accounts\/[^/]+\/scan-history$/.test(pathname)) return '/api/accounts/:accountId/scan-history';
    if (/^\/api\/accounts\/[^/]+\/messages\/[a-z-]+$/.test(pathname)) return '/api/accounts/:accountId/messages/:action';
    if (/^\/api\/accounts\/[^/]+$/.test(pathname)) return '/api/accounts/:accountId';
    if (pathname.startsWith('/api/profile')) return '/api/profile/:operation';
    if (pathname.startsWith('/api/scam-check')) return '/api/scam-check/:operation';
    if (pathname.startsWith('/api/consumer')) return '/api/consumer/:operation';
    if (pathname.startsWith('/api/dev/runtime-trace')) return '/api/dev/runtime-trace/:operation';
    if (pathname.startsWith('/api/operations')) return '/api/operations/:operation';
    return '/api/other';
  }

  function apiRequest(method, pathname) {
    const context = current();
    if (!context || pathname.startsWith('/api/dev/runtime-trace')) return null;
    const request = Object.freeze({
      ...context,
      routeTemplate: safeRouteTemplate(pathname),
      httpMethod: String(method || 'GET').toUpperCase(),
      apiStartedAt: Date.now(),
    });
    transport({
      traceId: request.traceId,
      stage: 'api_request',
      actionId: request.actionId,
      expectedWorkflow: request.expectedWorkflow,
      ...(request.provider ? { provider: request.provider } : {}),
      ...(request.scanType ? { scanType: request.scanType } : {}),
      component: 'browser',
      step: 'request_sent',
      outcome: 'started',
      routeTemplate: request.routeTemplate,
      httpMethod: request.httpMethod,
    });
    return request;
  }

  function apiResponse(request, status) {
    if (!request) return;
    const durationMs = Math.max(0, Math.min(86_400_000, Date.now() - request.apiStartedAt));
    transport({
      traceId: request.traceId,
      stage: 'api_response',
      actionId: request.actionId,
      expectedWorkflow: request.expectedWorkflow,
      ...(request.provider ? { provider: request.provider } : {}),
      ...(request.scanType ? { scanType: request.scanType } : {}),
      component: 'browser',
      step: 'response_received',
      outcome: Number(status) >= 400 ? 'failed' : 'success',
      routeTemplate: request.routeTemplate,
      httpMethod: request.httpMethod,
      httpStatus: Number.isSafeInteger(Number(status)) ? Number(status) : 0,
      durationMs,
    });
  }

  function withTraceQuery(path) {
    const context = current();
    if (!context) return path;
    const url = new URL(path, window.location.origin);
    if (url.origin !== window.location.origin || !url.pathname.startsWith('/api/accounts/')) return path;
    url.searchParams.set('trace_id', context.traceId);
    return `${url.pathname}${url.search}`;
  }

  const NativeEventSource = window.EventSource;
  if (typeof NativeEventSource === 'function') {
    class TracedEventSource extends NativeEventSource {
      constructor(url, options) {
        super(withTraceQuery(String(url)), options);
      }
    }
    window.EventSource = TracedEventSource;
  }

  document.addEventListener('click', (event) => {
    const button = event.target instanceof Element ? event.target.closest('button') : null;
    if (!(button instanceof HTMLButtonElement) || button.disabled) return;
    const [actionId, expectedWorkflow] = semanticControl(button);
    begin(actionId, expectedWorkflow, providerFor(button));
  }, true);

  Object.defineProperty(window, 'emailShieldRuntimeTrace', {
    value: Object.freeze({
      currentTraceId: () => current()?.traceId || null,
      apiRequest,
      apiResponse,
      withTraceQuery,
    }),
    writable: false,
    configurable: false,
  });
})();
