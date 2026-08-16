(() => {
  const installedModules = window.emailShieldInstalledModules ||= new Set();
  if (installedModules.has('runtime-workflow-trace')) return;
  installedModules.add('runtime-workflow-trace');

  const TRACE_WINDOW_MS = 5 * 60_000;
  const PROVIDERS = new Set(['gmail', 'icloud', 'yahoo', 'imap', 'outlook']);
  const SCAN_TYPES = new Set(['quick', 'full', 'spam']);
  const OUTCOMES = new Set(['started', 'success', 'failed', 'partial', 'cancelled', 'rejected', 'incomplete']);
  const SAFE_LABEL = /^[a-z0-9][a-z0-9_.:/-]{0,159}$/i;
  const SAFE_STREAM_PHASE = /^[a-z][a-z0-9_]{0,63}$/;
  const SAFE_CHECKPOINT_EXTRA_KEYS = new Set([
    'provider', 'scanType', 'component', 'step', 'errorCode',
    'httpStatus', 'durationMs', 'pageSize', 'maxMessages', 'itemCount', 'retryCount',
  ]);

  const STATIC_CONTROLS = Object.freeze({
    connectBtn: ['account.connect', 'provider.connect.imap', 'provider_connection'],
    quickScanBtn: ['mailbox.scan.quick', 'mailbox.scan.quick', 'quick_mailbox_scan'],
    fullScanBtn: ['mailbox.scan.full', 'mailbox.scan.full', 'full_mailbox_audit'],
    spamScanBtn: ['mailbox.scan.spam', 'mailbox.scan.spam', 'spam_junk_scan'],
    stopScanBtn: ['mailbox.scan.stop', 'mailbox.scan.stop', 'scan_stop'],
    backgroundToggle: ['protection.background.toggle', 'protection.background.toggle', 'background_protection'],
    backgroundInterval: ['protection.background.interval', 'protection.background.interval', 'background_protection'],
    saveSettingsBtn: ['settings.save', 'settings.save', 'settings_persistence'],
    scamCheckButton: ['scam_check.run', 'scam_check.run', 'scam_check'],
    familyShieldButton: ['family.open', 'navigation.family', 'family_shield'],
    disconnectAccountBtn: ['account.disconnect', 'account.disconnect', 'account_disconnect'],

    devSuiteBtn: ['developer.test_suite', 'developer.test_suite', 'developer_test_suite'],
    operationsRefresh: ['community.operations.load', 'community.operations.load', 'community_operations'],

    accountPlanRefresh: ['account.profile.snapshot', 'account.profile.snapshot', 'account_profile_snapshot'],
    accountCreate: ['account.profile.register', 'account.profile.register', 'account_register'],
    accountSignIn: ['account.profile.sign_in', 'account.profile.sign_in', 'account_sign_in'],
    accountRecoverOpen: ['account.recovery.open', 'account.recovery.open', 'account_recovery_open'],
    accountLinkMailbox: ['account.mailbox.link', 'account.mailbox.link', 'account_mailbox_link'],
    accountSignOut: ['account.sign_out', 'account.sign_out', 'account_sign_out'],
    accountRotateRecovery: ['account.recovery.rotate', 'account.recovery.rotate', 'account_recovery_rotate'],
    accountRevokeOthers: ['account.devices.revoke_others', 'account.devices.revoke_others', 'account_devices_revoke_others'],
    accountExportMetadata: ['account.metadata.export', 'account.metadata.export', 'account_metadata_export'],
    accountSignOutEverywhere: ['account.sign_out_everywhere', 'account.sign_out_everywhere', 'account_sign_out_everywhere'],
    accountTransferFamily: ['family.transfer', 'family.transfer', 'family_transfer'],
    accountDeleteFamily: ['account.family.delete', 'account.family.delete', 'account_family_delete'],
    accountDeleteProfile: ['account.delete', 'account.delete', 'account_delete'],

    familyRefresh: ['family.load', 'family.load', 'family_refresh'],
    familyCreate: ['family.create', 'family.create', 'family_create'],
    familyJoin: ['family.join', 'family.join', 'family_join'],
    familyInvite: ['family.invite', 'family.invite', 'family_invite'],
    familyStrict: ['family.strict', 'family.strict', 'family_strict'],
    familyLeave: ['family.leave', 'family.leave', 'family_leave'],
    familyGuardianSave: ['family.guardian_preferences', 'family.guardian_preferences', 'family_guardian_preferences'],

    homeScanNow: ['mailbox.scan.quick', 'mailbox.scan.quick', 'home_quick_scan'],
    homeFamily: ['navigation.family', 'navigation.family', 'ui_navigation'],

    consumerBuyIndividual: ['billing.purchase.individual', 'billing.purchase.individual', 'billing_purchase'],
    consumerBuyFamily: ['billing.purchase.family', 'billing.purchase.family', 'billing_purchase'],
    consumerRestorePurchase: ['billing.purchase.restore', 'billing.purchase.restore', 'billing_restore'],
    consumerRunHealth: ['mailbox.health.run', 'mailbox.health.run', 'mailbox_health'],
    consumerRefreshHealth: ['mailbox.health.load', 'mailbox.health.load', 'mailbox_health_view'],
    consumerRefreshActivity: ['activity.load', 'activity.load', 'activity_load'],
    consumerClearActivity: ['activity.clear', 'activity.clear', 'activity_clear'],
    consumerRefreshFamily: ['family.load', 'family.load', 'family_refresh'],
    consumerCheckBrowser: ['browser_destination.check', 'browser_destination.check', 'browser_destination_check'],
    consumerCheckIntervention: ['intervention.check', 'intervention.check', 'intervention_check'],
    consumerCheckExposure: ['exposure.email.check', 'exposure.email.check', 'exposure_check'],
    consumerSupportBundle: ['support.bundle.export', 'support.bundle.export', 'support_bundle'],
    consumerOnboardingDone: ['onboarding.complete', 'onboarding.complete', 'onboarding_complete'],

    policyRefresh: ['policy.load', 'policy.load', 'policy_load'],
    policyRevoke: ['policy.revoke', 'policy.revoke', 'policy_revoke'],
    policyBulkRevoke: ['policy.bulk_revoke', 'policy.bulk_revoke', 'policy_bulk_revoke'],
    policyClear: ['policy.clear', 'policy.clear', 'policy_clear'],
    policyReset: ['policy.reset', 'policy.reset', 'policy_reset'],
    policySelectVisible: ['policy.selection.toggle', 'policy.selection.toggle', 'policy_selection'],

    scamCheckRun: ['scam_check.run', 'scam_check.run', 'scam_check'],
    scamCheckClear: ['scam_check.clear', 'scam_check.clear', 'scam_check_clear'],
    scanHistoryRefresh: ['mailbox.scan.history', 'mailbox.scan.history', 'scan_history'],
  });

  const ACTION_CONTROLS = Object.freeze({
    'block-sender': ['message.block_sender', 'message.block_sender', 'message_policy_action'],
    'block-domain': ['message.block_domain', 'message.block_domain', 'message_policy_action'],
    trash: ['message.trash', 'message.trash', 'provider_message_mutation'],
    'report-scam': ['message.report_scam', 'message.report_scam', 'scam_report'],
    'move-spam': ['message.move_spam', 'message.move_spam', 'provider_message_mutation'],
    'mark-safe': ['message.mark_safe', 'message.mark_safe', 'personal_message_approval'],
    'trust-sender': ['message.trust_sender', 'message.trust_sender', 'personal_sender_trust'],
    unsubscribe: ['message.unsubscribe', 'message.unsubscribe', 'unsubscribe_workflow'],
    'analyze-links': ['message.analyze_links', 'message.analyze_links', 'destination_analysis'],
    undo: ['message.undo', 'message.undo', 'provider_undo'],
  });

  const ROUTE_CONTROLS = Object.freeze({
    home: ['navigation.home', 'navigation.home'],
    scan: ['navigation.scan', 'navigation.scan'],
    protection: ['navigation.protection', 'navigation.protection'],
    family: ['navigation.family', 'navigation.family'],
    community: ['navigation.community', 'navigation.community'],
    history: ['navigation.history', 'navigation.history'],
    account: ['navigation.account', 'navigation.account'],
    settings: ['navigation.settings', 'navigation.settings'],
    activity: ['navigation.activity', 'navigation.activity'],
    check: ['navigation.check', 'navigation.check'],
  });

  const registeredById = new Map();
  const registeredElements = new WeakMap();
  let active = null;

  function validProvider(value) {
    return typeof value === 'string' && PROVIDERS.has(value) ? value : undefined;
  }

  function selectedProviderForConnect() {
    const select = document.getElementById('providerSelect');
    return select instanceof HTMLSelectElement ? validProvider(select.value) : undefined;
  }

  function validScanType(value) {
    return typeof value === 'string' && SCAN_TYPES.has(value) ? value : undefined;
  }

  function validLabel(value) {
    return typeof value === 'string' && SAFE_LABEL.test(value);
  }

  function safeInteger(value, maximum) {
    const number = Number(value);
    return Number.isSafeInteger(number) && number >= 0 && number <= maximum ? number : undefined;
  }

  function scanTypeFor(actionId) {
    return validScanType(String(actionId).split('.').at(-1));
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

  function definition(actionId, workflowId, expectedWorkflow, provider) {
    if (!validLabel(actionId) || !validLabel(workflowId) || !validLabel(expectedWorkflow)) return null;
    return Object.freeze({
      actionId,
      workflowId,
      expectedWorkflow,
      provider: validProvider(provider),
    });
  }

  function registerControl(control, actionId, workflowId, expectedWorkflow = workflowId, provider) {
    const registered = definition(actionId, workflowId, expectedWorkflow, provider);
    if (!registered) return false;
    if (typeof control === 'string') {
      if (!/^[A-Za-z][A-Za-z0-9_:.-]{0,119}$/.test(control)) return false;
      registeredById.set(control, registered);
      return true;
    }
    if (control instanceof Element) {
      registeredElements.set(control, registered);
      return true;
    }
    return false;
  }

  function begin(actionId, workflowId, expectedWorkflow, provider, origin = 'user') {
    const registered = definition(actionId, workflowId, expectedWorkflow, provider);
    if (!registered) return null;
    const context = Object.freeze({
      traceId: crypto.randomUUID(),
      actionId: registered.actionId,
      workflowId: registered.workflowId,
      expectedWorkflow: registered.expectedWorkflow,
      provider: registered.provider,
      scanType: scanTypeFor(registered.actionId),
      origin,
      startedAt: Date.now(),
    });
    active = context;
    transport({
      traceId: context.traceId,
      workflowId: context.workflowId,
      stage: origin === 'automatic' ? 'system' : 'ui_action',
      actionId: context.actionId,
      expectedWorkflow: context.expectedWorkflow,
      ...(context.provider ? { provider: context.provider } : {}),
      ...(context.scanType ? { scanType: context.scanType } : {}),
      component: origin === 'automatic' ? 'browser_automatic' : 'browser',
      step: origin === 'automatic' ? 'automatic_root' : 'button_pressed',
      outcome: 'started',
    });
    return context;
  }

  function automaticRoot(actionId, workflowId, expectedWorkflow = workflowId, provider) {
    return begin(actionId, workflowId, expectedWorkflow, provider, 'automatic');
  }

  function sanitizeCheckpointExtra(value) {
    if (value === undefined) return Object.freeze({});
    if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
    if (Object.keys(value).some((key) => !SAFE_CHECKPOINT_EXTRA_KEYS.has(key))) return null;
    const output = {};
    const provider = validProvider(value.provider);
    if (value.provider !== undefined && !provider) return null;
    if (provider) output.provider = provider;
    const scanType = validScanType(value.scanType);
    if (value.scanType !== undefined && !scanType) return null;
    if (scanType) output.scanType = scanType;
    for (const key of ['component', 'step', 'errorCode']) {
      if (value[key] === undefined) continue;
      if (!validLabel(value[key])) return null;
      output[key] = value[key];
    }
    const integerBounds = {
      httpStatus: 599,
      durationMs: 86_400_000,
      pageSize: 10_000,
      maxMessages: 10_000_000,
      itemCount: 10_000_000,
      retryCount: 1_000,
    };
    for (const [key, maximum] of Object.entries(integerBounds)) {
      if (value[key] === undefined) continue;
      const number = safeInteger(value[key], maximum);
      if (number === undefined) return null;
      output[key] = number;
    }
    return Object.freeze(output);
  }

  function checkpointFor(context, checkpointId, outcome = 'success', safeExtra) {
    if (!context || !validLabel(checkpointId) || !checkpointId.startsWith(`${context.workflowId}.`)) return false;
    if (!OUTCOMES.has(outcome)) return false;
    const extra = sanitizeCheckpointExtra(safeExtra);
    if (!extra) return false;
    const stage = checkpointId.endsWith('.ui_confirmed') || checkpointId.includes('.ui_') ? 'ui_render' : 'workflow';
    const event = {
      traceId: context.traceId,
      workflowId: context.workflowId,
      stage,
      actionId: context.actionId,
      expectedWorkflow: context.expectedWorkflow,
      checkpointId,
      outcome,
    };
    const provider = extra.provider || context.provider;
    const scanType = extra.scanType || context.scanType;
    if (provider) event.provider = provider;
    if (scanType) event.scanType = scanType;
    if (extra.component !== undefined) event.component = extra.component;
    if (extra.step !== undefined) event.step = extra.step;
    if (extra.errorCode !== undefined) event.errorCode = extra.errorCode;
    if (extra.httpStatus !== undefined) event.httpStatus = extra.httpStatus;
    if (extra.durationMs !== undefined) event.durationMs = extra.durationMs;
    if (extra.pageSize !== undefined) event.pageSize = extra.pageSize;
    if (extra.maxMessages !== undefined) event.maxMessages = extra.maxMessages;
    if (extra.itemCount !== undefined) event.itemCount = extra.itemCount;
    if (extra.retryCount !== undefined) event.retryCount = extra.retryCount;
    transport(event);
    if (outcome === 'failed' || outcome === 'rejected' || outcome === 'cancelled' || checkpointId.endsWith('.ui_confirmed')) {
      if (active?.traceId === context.traceId) active = null;
    }
    return true;
  }

  function checkpoint(checkpointId, outcome = 'success', safeExtra) {
    return checkpointFor(current(), checkpointId, outcome, safeExtra);
  }

  function semanticControl(button) {
    const bound = registeredElements.get(button) || (button.id ? registeredById.get(button.id) : null);
    if (bound) return bound;

    if (button.id === 'connectBtn') {
      const provider = selectedProviderForConnect() || providerFor(button);
      if (provider) return definition(`provider.connect.${provider}`, `provider.connect.${provider}`, 'provider_connection', provider);
    }

    if (button.id && STATIC_CONTROLS[button.id]) {
      const [actionId, workflowId, expectedWorkflow] = STATIC_CONTROLS[button.id];
      return definition(actionId, workflowId, expectedWorkflow, providerFor(button));
    }

    const provider = validProvider(button.dataset.consumerProvider);
    if (provider) return definition(`provider.connect.${provider}`, `provider.connect.${provider}`, 'provider_connection', provider);

    const action = button.getAttribute('data-action');
    if (action && ACTION_CONTROLS[action]) {
      const [actionId, workflowId, expectedWorkflow] = ACTION_CONTROLS[action];
      return definition(actionId, workflowId, expectedWorkflow, providerFor(button));
    }

    const route = button.getAttribute('data-route-target') || button.getAttribute('data-mobile-route');
    if (route && ROUTE_CONTROLS[route]) {
      const [actionId, workflowId] = ROUTE_CONTROLS[route];
      return definition(actionId, workflowId, 'ui_navigation');
    }

    if (button.hasAttribute('data-select')) return definition('account.select', 'account.select', 'workspace_account_selection');
    if (button.hasAttribute('data-consumer-sensitivity')) return definition('protection.sensitivity.save', 'protection.sensitivity.save', 'protection_sensitivity');
    if (button.hasAttribute('data-scam-check-mode')) return definition('scam_check.mode', 'scam_check.mode', 'scam_check_mode');
    if (button.classList.contains('consumer-provider')) return definition('provider.connect.unknown', 'provider.connect.unknown', 'provider_connection');
    return definition('ui.unregistered_button', 'ui.unregistered_button', 'ui_action_unknown');
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
    if (pathname.startsWith('/api/accounts/oauth/google/')) return '/api/accounts/oauth/google/:operation';
    if (pathname.startsWith('/api/accounts/oauth/microsoft/')) return '/api/accounts/oauth/microsoft/:operation';
    if (/^\/api\/accounts\/[^/]+\/scan\/(quick|full|spam)$/.test(pathname)) return '/api/accounts/:accountId/scan/:type';
    if (/^\/api\/accounts\/[^/]+\/scan\/resume\/[^/]+$/.test(pathname)) return '/api/accounts/:accountId/scan/resume/:scanId';
    if (/^\/api\/accounts\/[^/]+\/scan\/stop$/.test(pathname)) return '/api/accounts/:accountId/scan/stop';
    if (/^\/api\/accounts\/[^/]+\/background-protection$/.test(pathname)) return '/api/accounts/:accountId/background-protection';
    if (/^\/api\/accounts\/[^/]+\/scan-history$/.test(pathname)) return '/api/accounts/:accountId/scan-history';
    if (/^\/api\/accounts\/[^/]+\/messages\/[a-z-]+$/.test(pathname)) return '/api/accounts/:accountId/messages/:action';
    if (/^\/api\/accounts\/[^/]+$/.test(pathname)) return '/api/accounts/:accountId';
    if (pathname.startsWith('/api/profile/v1/')) return '/api/profile/v1/:operation';
    if (pathname === '/api/profile') return '/api/profile';
    if (pathname.startsWith('/api/scam-check')) return '/api/scam-check/:operation';
    if (pathname.startsWith('/api/consumer')) return '/api/consumer/:operation';
    if (pathname.startsWith('/api/dev/runtime-trace')) return '/api/dev/runtime-trace/:operation';
    if (pathname.startsWith('/api/operations')) return '/api/operations/:operation';
    if (pathname.startsWith('/api/security')) return '/api/security/:operation';
    if (pathname.startsWith('/api/dev/test-suite')) return '/api/dev/test-suite';
    return '/api/other';
  }

  function apiRequest(method, pathname) {
    const context = current();
    if (!context || pathname.startsWith('/api/dev/runtime-trace')) return null;
    const request = Object.freeze({
      traceId: context.traceId,
      workflowId: context.workflowId,
      actionId: context.actionId,
      expectedWorkflow: context.expectedWorkflow,
      provider: context.provider,
      scanType: context.scanType,
      routeTemplate: safeRouteTemplate(pathname),
      httpMethod: String(method || 'GET').toUpperCase(),
      apiStartedAt: Date.now(),
    });
    transport({
      traceId: request.traceId,
      workflowId: request.workflowId,
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
      workflowId: request.workflowId,
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

  function streamTrace(context, stage, step, outcome, fields) {
    if (!context) return;
    const event = {
      traceId: context.traceId,
      workflowId: context.workflowId,
      stage,
      actionId: context.actionId,
      expectedWorkflow: context.expectedWorkflow,
      component: 'scan_stream',
      step,
      outcome,
    };
    if (context.provider) event.provider = context.provider;
    if (context.scanType) event.scanType = context.scanType;
    if (fields?.pageSize !== undefined) event.pageSize = fields.pageSize;
    if (fields?.itemCount !== undefined) event.itemCount = fields.itemCount;
    if (fields?.errorCode !== undefined) event.errorCode = fields.errorCode;
    transport(event);
  }

  function parseStreamData(event) {
    if (!(event instanceof MessageEvent) || typeof event.data !== 'string') return {};
    try {
      const value = JSON.parse(event.data);
      return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
    } catch {
      return {};
    }
  }

  const NativeEventSource = window.EventSource;
  if (typeof NativeEventSource === 'function') {
    class TracedEventSource extends NativeEventSource {
      constructor(url, options) {
        const rawPath = String(url);
        const context = current();
        super(withTraceQuery(rawPath), options);
        const parsedUrl = new URL(rawPath, window.location.origin);
        if (!context || parsedUrl.origin !== window.location.origin || !parsedUrl.pathname.includes('/scan/')) return;

        let streamProvider = context.provider;
        let streamScanType = context.scanType;
        const streamContext = () => Object.freeze({
          traceId: context.traceId,
          workflowId: context.workflowId,
          actionId: context.actionId,
          expectedWorkflow: context.expectedWorkflow,
          provider: streamProvider,
          scanType: streamScanType,
        });

        this.addEventListener('scan-started', (event) => {
          const value = parseStreamData(event);
          streamProvider = validProvider(value.provider) || streamProvider;
          streamScanType = validScanType(value.type) || streamScanType;
          streamTrace(streamContext(), 'workflow', 'scan_started', 'started');
        });
        this.addEventListener('scan-status', (event) => {
          const value = parseStreamData(event);
          const phase = typeof value.phase === 'string' && SAFE_STREAM_PHASE.test(value.phase)
            ? value.phase
            : 'status_update';
          const batchMatch = phase === 'bounded_batches' && typeof value.message === 'string'
            ? value.message.match(/bounded batches of (\d{1,5})/i)
            : null;
          const pageSize = batchMatch ? Number(batchMatch[1]) : undefined;
          streamTrace(streamContext(), phase === 'bounded_batches' ? 'worker' : 'workflow', phase, phase === 'complete' ? 'success' : 'started',
            Number.isSafeInteger(pageSize) ? { pageSize } : undefined);
        });
        this.addEventListener('scan-complete', (event) => {
          const value = parseStreamData(event);
          const examined = Number(value?.counters?.examined);
          streamTrace(streamContext(), 'workflow', 'scan_complete', 'success',
            Number.isSafeInteger(examined) && examined >= 0 ? { itemCount: examined } : undefined);
        });
        this.addEventListener('scan-error', () => {
          streamTrace(streamContext(), 'workflow', 'scan_error', 'failed', { errorCode: 'server_scan_error' });
        });
        this.addEventListener('error', () => {
          streamTrace(streamContext(), 'workflow', 'stream_transport_error', 'failed', { errorCode: 'sse_transport_error' });
        });
      }
    }
    window.EventSource = TracedEventSource;
  }

  document.addEventListener('click', (event) => {
    if (event.isTrusted === false) return;
    const button = event.target instanceof Element ? event.target.closest('button') : null;
    if (!(button instanceof HTMLButtonElement) || button.disabled) return;
    const semantic = semanticControl(button);
    if (!semantic) return;
    begin(semantic.actionId, semantic.workflowId, semantic.expectedWorkflow, semantic.provider || providerFor(button));
  }, true);

  Object.defineProperty(window, 'emailShieldRuntimeTrace', {
    value: Object.freeze({
      currentTraceId: () => current()?.traceId || null,
      currentWorkflowId: () => current()?.workflowId || null,
      apiRequest,
      apiResponse,
      withTraceQuery,
      checkpoint: (checkpointId, outcome, safeExtra) => checkpoint(checkpointId, outcome, safeExtra),
      automaticRoot: (actionId, workflowId, expectedWorkflow, provider) => automaticRoot(actionId, workflowId, expectedWorkflow, provider),
      registerControl: (control, actionId, workflowId, expectedWorkflow, provider) => registerControl(control, actionId, workflowId, expectedWorkflow, provider),
      routeTemplateFor: (pathname) => typeof pathname === 'string' ? safeRouteTemplate(pathname) : '/api/other',
    }),
    writable: false,
    configurable: false,
  });
})();
