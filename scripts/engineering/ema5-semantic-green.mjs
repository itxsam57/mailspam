import { readFileSync, writeFileSync } from "node:fs";

const changed = new Set();

function read(path) { return readFileSync(path, "utf8"); }
function write(path, value) { writeFileSync(path, value, "utf8"); changed.add(path); }
function replaceOnce(path, before, after) {
  const source = read(path);
  const first = source.indexOf(before);
  if (first < 0) throw new Error(`${path}: guarded source snippet not found`);
  if (source.indexOf(before, first + before.length) >= 0) throw new Error(`${path}: guarded source snippet is ambiguous`);
  write(path, `${source.slice(0, first)}${after}${source.slice(first + before.length)}`);
}

// Disabled tracing remains a protected local capability probe instead of a 404 storm.
replaceOnce(
  "server/src/api/runtimeWorkflowTraceRoutes.ts",
  '  recorder: RuntimeWorkflowTraceRecorder;\n',
  '  recorder: RuntimeWorkflowTraceRecorder | null;\n',
);
replaceOnce(
  "server/src/api/runtimeWorkflowTraceRoutes.ts",
  `  router.get("/config", (_req, res) => {\n    if (!recorder.enabled) {\n      res.status(404).json({ error: "Runtime workflow tracing is disabled." });\n      return;\n    }\n    res.json({\n      enabled: true,\n      runId: recorder.runId,\n      localAuthoritative: true,\n    });\n  });`,
  `  router.get("/config", (_req, res) => {\n    if (!recorder?.enabled) {\n      res.json({ enabled: false, localAuthoritative: true });\n      return;\n    }\n    res.json({\n      enabled: true,\n      runId: recorder.runId,\n      localAuthoritative: true,\n    });\n  });`,
);
replaceOnce(
  "server/src/api/runtimeWorkflowTraceRoutes.ts",
  '    if (!recorder.enabled) {\n      res.status(404).json({ error: "Runtime workflow tracing is disabled." });\n',
  '    if (!recorder?.enabled) {\n      res.status(404).json({ error: "Runtime workflow tracing is disabled." });\n',
);
replaceOnce(
  "server/src/api/runtimeWorkflowTraceRoutes.ts",
  '    if (!recorder.enabled) {\n      res.status(404).json({ error: "Runtime workflow tracing is disabled." });\n',
  '    if (!recorder?.enabled) {\n      res.status(404).json({ error: "Runtime workflow tracing is disabled." });\n',
);
replaceOnce(
  "server/src/api/runtimeWorkflowTraceRoutes.ts",
  `  const recorder = options.recorder ?? runtimeWorkflowTrace();\n  if (!recorder?.enabled) return;\n  const telemetry = options.telemetry ?? createTechnicalTelemetryFromEnvironment();`,
  `  const recorder = options.recorder === undefined ? runtimeWorkflowTrace() : options.recorder;\n  const telemetry = recorder?.enabled\n    ? (options.telemetry ?? createTechnicalTelemetryFromEnvironment())\n    : undefined;`,
);

// Server-derived route identity owns backend terminal evidence. Response content is never inspected.
replaceOnce(
  "server/src/diagnostics/runtimeTraceHttp.ts",
  `import {\n  runWithRuntimeTraceRequest,\n  type ResolvedRuntimeTraceWorkflow,\n} from "./runtimeTraceRequestContext.js";`,
  `import {\n  recordCurrentRuntimeCheckpoint,\n  runWithRuntimeTraceRequest,\n  type ResolvedRuntimeTraceWorkflow,\n} from "./runtimeTraceRequestContext.js";\nimport { runtimeWorkflowTrace, type RuntimeWorkflowTraceRecorder } from "./runtimeWorkflowTrace.js";`,
);
replaceOnce(
  "server/src/diagnostics/runtimeTraceHttp.ts",
  `interface RuntimeTraceHttpRequest {\n  method: string;\n  path: string;\n  headers: RuntimeTraceHttpHeaders;\n}\n\ntype RuntimeTraceNext = () => void;`,
  `interface RuntimeTraceHttpRequest {\n  method: string;\n  path: string;\n  headers: RuntimeTraceHttpHeaders;\n}\n\ninterface RuntimeTraceHttpResponse {\n  statusCode?: number;\n  once?: (event: "finish", listener: () => void) => unknown;\n}\n\ntype RuntimeTraceNext = () => void;`,
);
replaceOnce(
  "server/src/diagnostics/runtimeTraceHttp.ts",
  `export function createRuntimeTraceHttpMiddleware() {\n  return (req: RuntimeTraceHttpRequest, _res: unknown, next: RuntimeTraceNext): void => {\n    const workflow = resolveRuntimeHttpWorkflow(req.method, req.path);\n    if (!workflow) {\n      next();\n      return;\n    }\n    runWithRuntimeTraceRequest(req.headers, workflow, next);\n  };\n}`,
  `export function createRuntimeTraceHttpMiddleware(\n  options: { recorder?: RuntimeWorkflowTraceRecorder | null } = {},\n) {\n  const recorder = options.recorder === undefined ? runtimeWorkflowTrace() : options.recorder;\n  return (req: RuntimeTraceHttpRequest, res: RuntimeTraceHttpResponse, next: RuntimeTraceNext): void => {\n    const workflow = resolveRuntimeHttpWorkflow(req.method, req.path);\n    if (!workflow) {\n      next();\n      return;\n    }\n    runWithRuntimeTraceRequest(req.headers, workflow, () => {\n      if (typeof res.once === "function") {\n        res.once("finish", () => {\n          const rawStatus = Number.isSafeInteger(res.statusCode) ? Number(res.statusCode) : 200;\n          const httpStatus = Math.max(0, Math.min(599, rawStatus));\n          recordCurrentRuntimeCheckpoint(recorder, "backend_completed", {\n            stage: "api_response",\n            outcome: httpStatus >= 400 ? "failed" : "success",\n            component: "local_api",\n            step: "response_finished",\n            httpStatus,\n            ...(httpStatus >= 400 ? { errorCode: \`http_\${httpStatus}\` } : {}),\n          });\n        });\n      }\n      next();\n    });\n  };\n}`,
);

// Browser diagnostics probe capability once and back off on rate limiting.
replaceOnce(
  "web/local-security.js",
  `  // This fixed transport can only append an already-sanitized diagnostic event\n  // to the loopback developer trace route. It bypasses the product mutation\n  // nonce because the route cannot mutate mailbox/account state, while still\n  // carrying the protected local session, CSRF token and same-origin provenance.\n  Object.defineProperty(window, 'emailShieldRuntimeTraceTransport', {\n    value: async (event) => {\n      try {\n        await originalFetch('/api/dev/runtime-trace/events', {\n          ...dashboardProvenance(),\n          method: 'POST',\n          headers: {\n            'Content-Type': 'application/json',\n            'X-Email-Shield-CSRF': csrfToken,\n          },\n          body: JSON.stringify(event),\n        });\n      } catch {}\n    },\n    writable: false,\n    configurable: false,\n    enumerable: false,\n  });`,
  `  // Runtime tracing is optional diagnostics. Probe its protected local config\n  // before sending events so a normal trace-disabled consumer session never\n  // generates repeated 404s. Rate limiting backs diagnostics off without\n  // affecting product requests or weakening their security boundary.\n  let traceAvailability = 'unknown';\n  let traceAvailabilityPromise = null;\n  let traceRetryAt = 0;\n\n  function traceBackoffMs(response, fallbackMs) {\n    const retryAfter = Number(response?.headers?.get?.('Retry-After'));\n    if (Number.isFinite(retryAfter) && retryAfter > 0 && retryAfter <= 3600) return retryAfter * 1000;\n    return fallbackMs;\n  }\n\n  async function runtimeTraceAvailable() {\n    if (Date.now() < traceRetryAt) return false;\n    if (traceAvailability === 'disabled') return false;\n    if (traceAvailability === 'enabled') return true;\n    if (traceAvailabilityPromise) return traceAvailabilityPromise;\n\n    traceAvailabilityPromise = (async () => {\n      try {\n        const response = await originalFetch('/api/dev/runtime-trace/config', {\n          ...dashboardProvenance(),\n          method: 'GET',\n          headers: { 'X-Email-Shield-CSRF': csrfToken },\n        });\n        if (response.status === 429) {\n          traceRetryAt = Date.now() + traceBackoffMs(response, 60_000);\n          return false;\n        }\n        if (!response.ok) {\n          traceAvailability = 'disabled';\n          return false;\n        }\n        const body = await response.json().catch(() => ({}));\n        traceAvailability = body.enabled === true ? 'enabled' : 'disabled';\n        return traceAvailability === 'enabled';\n      } catch {\n        traceRetryAt = Date.now() + 30_000;\n        return false;\n      } finally {\n        traceAvailabilityPromise = null;\n      }\n    })();\n    return traceAvailabilityPromise;\n  }\n\n  Object.defineProperty(window, 'emailShieldRuntimeTraceTransport', {\n    value: async (event) => {\n      if (!await runtimeTraceAvailable()) return;\n      try {\n        const response = await originalFetch('/api/dev/runtime-trace/events', {\n          ...dashboardProvenance(),\n          method: 'POST',\n          headers: {\n            'Content-Type': 'application/json',\n            'X-Email-Shield-CSRF': csrfToken,\n          },\n          body: JSON.stringify(event),\n        });\n        if (response.status === 429) {\n          traceRetryAt = Date.now() + traceBackoffMs(response, 60_000);\n        } else if (response.status === 404) {\n          traceAvailability = 'disabled';\n        }\n      } catch {\n        traceRetryAt = Date.now() + 30_000;\n      }\n    },\n    writable: false,\n    configurable: false,\n    enumerable: false,\n  });`,
);

// Registry matches real automatic/setup/projection semantics.
replaceOnce(
  "server/src/diagnostics/workflowRegistry.ts",
  `  automaticWorkflow("community.feed.refresh"),\n\n  linearWorkflow("provider.connect.gmail"`,
  `  automaticWorkflow("community.feed.refresh"),\n  automaticWorkflow("workspace.restore"),\n  automaticWorkflow("learning.legitimate_feedback"),\n\n  linearWorkflow("provider.connect.gmail"`,
);
replaceOnce(
  "server/src/diagnostics/workflowRegistry.ts",
  `  linearWorkflow("provider.connect.outlook", ["provider.connect.outlook"], true),\n  linearWorkflow("account.select"),`,
  `  linearWorkflow("provider.connect.outlook", ["provider.connect.outlook"], true),\n  uiWorkflow("provider.credentials.icloud"),\n  uiWorkflow("provider.credentials.yahoo"),\n  uiWorkflow("provider.credentials.imap"),\n  linearWorkflow("account.select"),`,
);
replaceOnce(
  "server/src/diagnostics/workflowRegistry.ts",
  `  linearWorkflow("account.profile.snapshot"),\n  linearWorkflow("workspace.restore"),\n\n  scanWorkflow("quick"),`,
  `  linearWorkflow("account.profile.snapshot"),\n\n  scanWorkflow("quick"),`,
);
replaceOnce(
  "server/src/diagnostics/workflowRegistry.ts",
  `    \`\${workflowId}.stream_completed\`,\n    \`\${workflowId}.ui_confirmed\`,`,
  `    \`\${workflowId}.stream_completed\`,\n    \`\${workflowId}.projection_rendered\`,\n    \`\${workflowId}.ui_confirmed\`,`,
);
replaceOnce(
  "server/src/diagnostics/workflowRegistry.ts",
  `  linearWorkflow("onboarding.start"),\n  linearWorkflow("onboarding.complete"),`,
  `  linearWorkflow("onboarding.start"),\n  linearWorkflow("onboarding.complete"),\n  uiWorkflow("onboarding.permissions.review"),\n  uiWorkflow("onboarding.family.skip"),`,
);

// Automatic roots use .started and successful .completed is terminal too.
replaceOnce(
  "web/runtime-workflow-trace.js",
  `      checkpointId: \`\${context.workflowId}.requested\`,`,
  `      checkpointId: \`\${context.workflowId}.\${origin === 'automatic' ? 'started' : 'requested'}\`,`,
);
replaceOnce(
  "web/runtime-workflow-trace.js",
  `    if (outcome === 'failed' || outcome === 'rejected' || outcome === 'cancelled' || checkpointId.endsWith('.ui_confirmed')) {`,
  `    if (outcome === 'failed' || outcome === 'rejected' || outcome === 'cancelled' || checkpointId.endsWith('.ui_confirmed') || checkpointId.endsWith('.completed')) {`,
);
replaceOnce(
  "web/runtime-workflow-trace.js",
  `    const provider = validProvider(button.dataset.consumerProvider);\n    if (provider) return definition(\`provider.connect.\${provider}\`, \`provider.connect.\${provider}\`, 'provider_connection', provider);\n\n    const action = button.getAttribute('data-action');`,
  `    const action = button.getAttribute('data-action');`,
);

// Home actions are navigation owned by the shell, never scan execution guesses.
replaceOnce(
  "web/app-shell.js",
  `    window.dispatchEvent(new CustomEvent('email-shield-route-changed', { detail: { route: id } }));\n  }`,
  `    window.dispatchEvent(new CustomEvent('email-shield-route-changed', { detail: { route: id } }));\n    window.emailShieldRuntimeTrace?.checkpoint?.(\`navigation.\${id}.ui_confirmed\`, 'success', { component: 'app_shell', step: 'route_visible' });\n  }`,
);
replaceOnce(
  "web/app-shell.js",
  `  document.getElementById('homeScanNow')?.addEventListener('click', () => showRoute('scan'));\n  document.getElementById('homeFamily')?.addEventListener('click', () => showRoute('family'));`,
  `  window.emailShieldRuntimeTrace?.registerControl?.('homeScanNow', 'navigation.scan', 'navigation.scan', 'ui_navigation');\n  window.emailShieldRuntimeTrace?.registerControl?.('homeFamily', 'navigation.family', 'navigation.family', 'ui_navigation');\n  document.getElementById('homeScanNow')?.addEventListener('click', () => showRoute('scan'));\n  document.getElementById('homeFamily')?.addEventListener('click', () => showRoute('family'));`,
);

// Workspace restore is automatic and terminal even when there is nothing to restore.
replaceOnce(
  "web/workspace-restore.js",
  `  async function restore() {\n    try {`,
  `  async function restore() {\n    const trace = window.emailShieldRuntimeTrace;\n    trace?.automaticRoot?.('system.workspace.restore', 'workspace.restore', 'workspace_restore');\n    let traceOutcome = 'success';\n    try {`,
);
replaceOnce(
  "web/workspace-restore.js",
  `    } catch {\n      // Workspace presentation is optional process memory; account use remains available.\n    }\n  }`,
  `    } catch {\n      traceOutcome = 'failed';\n      // Workspace presentation is optional process memory; account use remains available.\n    } finally {\n      trace?.checkpoint?.('workspace.restore.completed', traceOutcome, {\n        component: 'workspace_restore',\n        step: 'restore_finished',\n        ...(traceOutcome === 'failed' ? { errorCode: 'workspace_restore_failed' } : {}),\n      });\n    }\n  }`,
);

// Secondary positive learning is its own automatic workflow, not part of the user's Safe/Trust action.
replaceOnce(
  "web/protection-learning.js",
  `  async function submitLegitimateFeedback(accountId, token) {\n    const key = \`\${accountId}:\${token}\`;`,
  `  async function submitLegitimateFeedback(accountId, token) {\n    const trace = window.emailShieldRuntimeTrace;\n    trace?.automaticRoot?.('system.learning.legitimate_feedback', 'learning.legitimate_feedback', 'legitimate_feedback');\n    const key = \`\${accountId}:\${token}\`;`,
);
replaceOnce(
  "web/protection-learning.js",
  `    publishCampaignDecisionState(token, state);\n  }`,
  `    publishCampaignDecisionState(token, state);\n    trace?.checkpoint?.('learning.legitimate_feedback.completed', state === 'saved' ? 'success' : 'failed', {\n      component: 'protection_learning',\n      step: 'feedback_finished',\n      ...(state === 'saved' ? {} : { errorCode: 'learning_feedback_unconfirmed' }),\n    });\n  }`,
);

// Scan completion requests the separate consumer projection; that projection owns visible terminal evidence.
replaceOnce(
  "web/scan-monitor.js",
  `    es.addEventListener('scan-complete', () => {\n      if (presentationIsCurrent()) {\n        setStatus(counters.textContent.trim() ? 'Scan complete. Results remain available in the optional lists below and the privacy-reduced history record is saved.' : 'Scan complete. No additional readable messages were returned.', 'complete');\n      }\n      finish(es);`,
  `    es.addEventListener('scan-complete', () => {\n      if (presentationIsCurrent()) {\n        setStatus(counters.textContent.trim() ? 'Scan complete. Results remain available in the optional lists below and the privacy-reduced history record is saved.' : 'Scan complete. No additional readable messages were returned.', 'complete');\n        window.dispatchEvent(new CustomEvent('email-shield-scan-projection-requested', { detail: { type } }));\n      }\n      finish(es);`,
);
replaceOnce(
  "web/consumer-scan-results.js",
  `  window.addEventListener('email-shield-workspace-restored', () => queueMicrotask(render));\n  render();`,
  `  window.addEventListener('email-shield-workspace-restored', () => queueMicrotask(render));\n  window.addEventListener('email-shield-scan-projection-requested', (event) => {\n    const type = event instanceof CustomEvent ? event.detail?.type : null;\n    render();\n    const trace = window.emailShieldRuntimeTrace;\n    if (type === 'quick') {\n      trace?.checkpoint?.('mailbox.scan.quick.projection_rendered', 'success', { component: 'consumer_scan_results', step: 'projection_rendered' });\n      trace?.checkpoint?.('mailbox.scan.quick.ui_confirmed', 'success', { component: 'consumer_scan_results', step: 'results_visible' });\n    } else if (type === 'full') {\n      trace?.checkpoint?.('mailbox.scan.full.projection_rendered', 'success', { component: 'consumer_scan_results', step: 'projection_rendered' });\n      trace?.checkpoint?.('mailbox.scan.full.ui_confirmed', 'success', { component: 'consumer_scan_results', step: 'results_visible' });\n    } else if (type === 'spam') {\n      trace?.checkpoint?.('mailbox.scan.spam.projection_rendered', 'success', { component: 'consumer_scan_results', step: 'projection_rendered' });\n      trace?.checkpoint?.('mailbox.scan.spam.ui_confirmed', 'success', { component: 'consumer_scan_results', step: 'results_visible' });\n    }\n  });\n  render();`,
);

// Normal provider cards explicitly distinguish credential setup from connection.
replaceOnce(
  "web/consumer-provider-onboarding.js",
  `  const providerByTitle = new Map([`,
  `  const trace = window.emailShieldRuntimeTrace;\n  const registerControl = (...args) => trace?.registerControl?.(...args);\n  const providerTrace = Object.freeze({\n    gmail: { setup: 'provider.connect.gmail', connect: 'provider.connect.gmail' },\n    icloud: { setup: 'provider.credentials.icloud', connect: 'provider.connect.icloud' },\n    yahoo: { setup: 'provider.credentials.yahoo', connect: 'provider.connect.yahoo' },\n    imap: { setup: 'provider.credentials.imap', connect: 'provider.connect.imap' },\n  });\n\n  const providerByTitle = new Map([`,
);
replaceOnce(
  "web/consumer-provider-onboarding.js",
  `  function renderCredentialAction(provider) {\n    actions.replaceChildren();\n    const button = document.createElement('button');`,
  `  function renderCredentialAction(provider) {\n    actions.replaceChildren();\n    const button = document.createElement('button');`,
);
replaceOnce(
  "web/consumer-provider-onboarding.js",
  `    button.textContent = provider === 'icloud'\n      ? 'Connect iCloud Mail'\n      : provider === 'yahoo'\n        ? 'Connect Yahoo Mail'\n        : 'Connect email provider';\n    button.addEventListener('click', () => {`,
  `    button.textContent = provider === 'icloud'\n      ? 'Connect iCloud Mail'\n      : provider === 'yahoo'\n        ? 'Connect Yahoo Mail'\n        : 'Connect email provider';\n    const connection = providerTrace[provider]?.connect;\n    if (connection) registerControl(button, connection, connection, 'provider_connection', provider);\n    button.addEventListener('click', () => {`,
);
replaceOnce(
  "web/consumer-provider-onboarding.js",
  `  for (const [provider, button] of providerButtons) {\n    if (oauthConfiguration[provider]) {`,
  `  for (const [provider, button] of providerButtons) {\n    const traceDefinition = providerTrace[provider];\n    if (traceDefinition) {\n      registerControl(button, traceDefinition.setup, traceDefinition.setup, provider === 'gmail' ? 'provider_connection' : 'provider_credential_setup', provider);\n    }\n    if (oauthConfiguration[provider]) {`,
);
replaceOnce(
  "web/consumer-provider-onboarding.js",
  `      renderCredentialAction(provider);\n      credentialFields.scrollIntoView({ behavior: 'smooth', block: 'nearest' });`,
  `      renderCredentialAction(provider);\n      if (provider === 'icloud') trace?.checkpoint?.('provider.credentials.icloud.ui_confirmed', 'success', { provider: 'icloud', component: 'provider_onboarding', step: 'credentials_visible' });\n      else if (provider === 'yahoo') trace?.checkpoint?.('provider.credentials.yahoo.ui_confirmed', 'success', { provider: 'yahoo', component: 'provider_onboarding', step: 'credentials_visible' });\n      else if (provider === 'imap') trace?.checkpoint?.('provider.credentials.imap.ui_confirmed', 'success', { provider: 'imap', component: 'provider_onboarding', step: 'credentials_visible' });\n      credentialFields.scrollIntoView({ behavior: 'smooth', block: 'nearest' });`,
);

// Gmail visible success belongs to OAuth completion, not the initial setup click.
replaceOnce(
  "web/gmail-oauth.js",
  `        if (typeof window.selectAccount === 'function' && typeof body.accountId === 'string') {\n          window.selectAccount(body.accountId);\n        }\n        return;`,
  `        if (typeof window.selectAccount === 'function' && typeof body.accountId === 'string') {\n          window.selectAccount(body.accountId);\n        }\n        window.emailShieldRuntimeTrace?.checkpoint?.('provider.connect.gmail.ui_confirmed', 'success', {\n          provider: 'gmail', component: 'gmail_oauth', step: 'oauth_connected',\n        });\n        return;`,
);

// Dynamic onboarding controls register their own meaning; successful local completion emits only UI-safe checkpoints.
replaceOnce(
  "web/consumer-onboarding.js",
  `  const state = {\n    profileSignedIn: false,`,
  `  const trace = window.emailShieldRuntimeTrace;\n  const registerControl = (...args) => trace?.registerControl?.(...args);\n  const state = {\n    profileSignedIn: false,`,
);
replaceOnce(
  "web/consumer-onboarding.js",
  `        choice.textContent = label;\n        choice.addEventListener('click', () => { void chooseSensitivity(profile); });`,
  `        choice.textContent = label;\n        registerControl(choice, 'protection.sensitivity.save', 'protection.sensitivity.save', 'protection_sensitivity');\n        choice.addEventListener('click', () => { void chooseSensitivity(profile); });`,
);
replaceOnce(
  "web/consumer-onboarding.js",
  `      go.textContent = action === 'permissions' ? 'Review' : action === 'home' ? 'Check Home' : 'Open';\n      go.addEventListener('click', () => { void handleAction(action); });`,
  `      go.textContent = action === 'permissions' ? 'Review' : action === 'home' ? 'Check Home' : 'Open';\n      const ownedWorkflow = action === 'permissions' ? 'onboarding.permissions.review'\n        : action === 'home' ? 'onboarding.complete'\n          : action === 'account' ? 'navigation.account'\n            : action === 'connect' ? 'navigation.settings'\n              : action === 'scan' ? 'navigation.scan'\n                : action === 'background' ? 'navigation.protection'\n                  : action === 'family' ? 'navigation.family'\n                    : null;\n      if (ownedWorkflow) registerControl(go, ownedWorkflow, ownedWorkflow, 'onboarding_navigation');\n      go.addEventListener('click', () => { void handleAction(action); });`,
);
replaceOnce(
  "web/consumer-onboarding.js",
  `      local.textContent = 'Use local Scam Check';\n      local.addEventListener('click', () => route('scan'));`,
  `      local.textContent = 'Use local Scam Check';\n      registerControl(local, 'navigation.scan', 'navigation.scan', 'ui_navigation');\n      local.addEventListener('click', () => route('scan'));`,
);
replaceOnce(
  "web/consumer-onboarding.js",
  `      skip.textContent = 'Not now';\n      skip.addEventListener('click', async () => {`,
  `      skip.textContent = 'Not now';\n      registerControl(skip, 'onboarding.family.skip', 'onboarding.family.skip', 'onboarding_family_skip');\n      skip.addEventListener('click', async () => {`,
);
replaceOnce(
  "web/consumer-onboarding.js",
  `        await persistProgress(false, id).catch(showError);\n        render();\n      });`,
  `        await persistProgress(false, id).catch(showError);\n        render();\n        trace?.checkpoint?.('onboarding.family.skip.ui_confirmed', 'success', { component: 'consumer_onboarding', step: 'family_skipped' });\n      });`,
);
replaceOnce(
  "web/consumer-onboarding.js",
  `      await persistProgress(false, id).catch(showError);\n      render();\n      return;\n    }\n    if (action === 'scan') {`,
  `      await persistProgress(false, id).catch(showError);\n      render();\n      trace?.checkpoint?.('onboarding.permissions.review.ui_confirmed', 'success', { component: 'consumer_onboarding', step: 'permissions_visible' });\n      return;\n    }\n    if (action === 'scan') {`,
);
replaceOnce(
  "web/consumer-onboarding.js",
  `      try { await persistProgress(true, id); status.textContent = 'Protection setup complete.'; }\n      catch (error) { state.completed.delete('consumer_home_ready'); showError(error); }\n      render();`,
  `      try {\n        await persistProgress(true, id);\n        status.textContent = 'Protection setup complete.';\n        trace?.checkpoint?.('onboarding.complete.ui_confirmed', 'success', { component: 'consumer_onboarding', step: 'setup_complete' });\n      } catch (error) { state.completed.delete('consumer_home_ready'); showError(error); }\n      render();`,
);

// Exact-build manifest owns automatic .started roots from the central browser owner.
replaceOnce(
  "scripts/engineering/generate-runtime-trace-manifest.mjs",
  `function registryWorkflowIds() {\n  const path = resolve(root, "server/src/diagnostics/workflowRegistry.ts");\n  const source = readFileSync(path, "utf8");\n  const ids = new Set();`,
  `function registryWorkflowIds() {\n  const path = resolve(root, "server/src/diagnostics/workflowRegistry.ts");\n  const source = readFileSync(path, "utf8");\n  const ids = new Set();\n  const automaticIds = new Set();`,
);
replaceOnce(
  "scripts/engineering/generate-runtime-trace-manifest.mjs",
  `  for (const regex of [\n    /linearWorkflow\\(\\s*["']([^"']+)["']/g,\n    /uiWorkflow\\(\\s*["']([^"']+)["']/g,\n    /automaticWorkflow\\(\\s*["']([^"']+)["']/g,\n  ]) {\n    for (const match of source.matchAll(regex)) ids.add(match[1]);\n  }`,
  `  for (const regex of [\n    /linearWorkflow\\(\\s*["']([^"']+)["']/g,\n    /uiWorkflow\\(\\s*["']([^"']+)["']/g,\n  ]) {\n    for (const match of source.matchAll(regex)) ids.add(match[1]);\n  }\n  for (const match of source.matchAll(/automaticWorkflow\\(\\s*["']([^"']+)["']/g)) {\n    ids.add(match[1]);\n    automaticIds.add(match[1]);\n  }`,
);
replaceOnce(
  "scripts/engineering/generate-runtime-trace-manifest.mjs",
  `  return [...ids].sort((a, b) => a.localeCompare(b));\n}`,
  `  return {\n    workflowIds: [...ids].sort((a, b) => a.localeCompare(b)),\n    automaticIds,\n  };\n}`,
);
replaceOnce(
  "scripts/engineering/generate-runtime-trace-manifest.mjs",
  `function dynamicRequestedOwners(entries, workflowIds) {`,
  `function dynamicRequestedOwners(entries, workflowIds, automaticIds) {`,
);
replaceOnce(
  "scripts/engineering/generate-runtime-trace-manifest.mjs",
  `  for (const workflowId of workflowIds) {\n    addEntry(entries, {\n      checkpointId: \`\${workflowId}.requested\`,`,
  `  for (const workflowId of workflowIds) {\n    addEntry(entries, {\n      checkpointId: \`\${workflowId}.\${automaticIds.has(workflowId) ? 'started' : 'requested'}\`,`,
);
replaceOnce(
  "scripts/engineering/generate-runtime-trace-manifest.mjs",
  `  const workflowIds = registryWorkflowIds();\n  const entries = new Map();\n  dynamicRequestedOwners(entries, workflowIds);`,
  `  const { workflowIds, automaticIds } = registryWorkflowIds();\n  const entries = new Map();\n  dynamicRequestedOwners(entries, workflowIds, automaticIds);`,
);

console.log(`EMA-5 guarded transform changed ${changed.size} files:`);
for (const path of [...changed].sort()) console.log(` - ${path}`);
