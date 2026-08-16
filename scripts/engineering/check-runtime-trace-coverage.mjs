import { readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';

const root = process.cwd();
const failures = [];
const read = (path) => readFileSync(resolve(root, path), 'utf8');
const fail = (message) => failures.push(message);

const trace = read('web/runtime-workflow-trace.js');
const localSecurity = read('web/local-security.js');
const composition = read('server/src/api/dashboardScripts.ts');
const registry = read('server/src/diagnostics/workflowRegistry.ts');
const context = read('server/src/diagnostics/runtimeTraceRequestContext.ts');
const responseBoundary = read('server/src/diagnostics/runtimeTraceResponseBoundary.ts');
const diagnosisRoutes = read('server/src/api/runtimeWorkflowTraceRoutes.ts');
const diagnosis = read('server/src/diagnostics/runtimeTraceDiagnosis.ts');
const manifestGenerator = read('scripts/engineering/generate-runtime-trace-manifest.mjs');
const serverSources = readdirSync(resolve(root, 'server/src'), { recursive: true, withFileTypes: true })
  .filter((entry) => entry.isFile() && entry.name.endsWith('.ts'));

if (composition.indexOf('"/runtime-workflow-trace.js"') < 0) fail('Runtime workflow tracer is no longer part of dashboard composition.');
const firstShared = composition.match(/const SHARED_DASHBOARD_SCRIPTS = \[\s*([^\n]+)/)?.[1] || '';
if (!firstShared.includes('/runtime-workflow-trace.js')) fail('Runtime workflow tracer must remain the first shared dashboard script.');

for (const api of ['currentTraceId', 'currentWorkflowId', 'currentActionId', 'checkpoint', 'automaticRoot', 'registerControl']) {
  if (!trace.includes(api)) fail(`Browser runtime tracer no longer exposes ${api}.`);
}
for (const header of ['X-Email-Shield-Trace-Id', 'X-Email-Shield-Workflow-Id', 'X-Email-Shield-Action-Id']) {
  if (!localSecurity.includes(header)) fail(`Protected fetch correlation header ${header} is missing.`);
}
for (const token of ['AsyncLocalStorage', 'bindRuntimeTraceRequest', 'recordCurrentRuntimeCheckpoint']) {
  if (!context.includes(token)) fail(`Server runtime trace context is missing ${token}.`);
}
if (!responseBoundary.includes('backend_completed') || !responseBoundary.includes('isRuntimeTraceRequestValidated')) {
  fail('Validated server response boundary no longer owns backend_completed evidence.');
}

const ownerCheckpoints = {
  'web/ui-router.js': ['navigation.home.ui_confirmed', 'navigation.scan.ui_confirmed', 'navigation.account.ui_confirmed'],
  'web/scan-monitor.js': ['mailbox.scan.quick.ui_confirmed', 'mailbox.scan.full.ui_confirmed', 'mailbox.scan.spam.ui_confirmed', 'message.trash.ui_confirmed'],
  'web/review-actions.js': ['message.report_scam.ui_confirmed', 'message.move_spam.ui_confirmed', 'message.mark_safe.ui_confirmed', 'message.trust_sender.ui_confirmed'],
  'web/unsubscribe-monitor.js': ['message.unsubscribe.ui_confirmed'],
  'web/analyze-links-actions.js': ['message.analyze_links.ui_confirmed'],
  'web/background-protection.js': ['protection.background.toggle.ui_confirmed'],
  'web/policy-management.js': ['policy.load.ui_confirmed', 'policy.revoke.ui_confirmed', 'policy.import.ui_confirmed', 'policy.export.ui_confirmed'],
  'web/account-plan.js': ['account.profile.register.ui_confirmed', 'account.profile.sign_in.ui_confirmed', 'account.recovery.use.ui_confirmed'],
  'web/account-lifecycle.js': ['account.recovery.rotate.ui_confirmed', 'account.delete.ui_confirmed', 'account.family.delete.ui_confirmed'],
  'web/family-shield.js': ['family.create.ui_confirmed', 'family.join.ui_confirmed', 'family.invite.ui_confirmed', 'family.strict.ui_confirmed'],
  'web/family-guardian-preferences.js': ['family.guardian_preferences.ui_confirmed'],
  'web/scam-check.js': ['scam_check.run.ui_confirmed'],
  'web/shopping-safety.js': ['shopping_safety.run.ui_confirmed'],
  'web/media-authenticity.js': ['media_authenticity.run.ui_confirmed'],
  'web/billing-plan-ui.js': ['billing.plan.load.ui_confirmed', 'billing.purchase.individual.ui_confirmed', 'billing.purchase.family.ui_confirmed', 'billing.purchase.restore.ui_confirmed'],
  'web/operations-dashboard.js': ['community.operations.load.ui_confirmed'],
  'web/consumer-product.js': ['mailbox.health.run.ui_confirmed', 'activity.load.ui_confirmed', 'browser_destination.check.ui_confirmed', 'support.bundle.export.ui_confirmed', 'onboarding.complete.ui_confirmed', 'mailbox.cleanup.ui_confirmed', 'message.undo.ui_confirmed'],
};
for (const [path, checkpoints] of Object.entries(ownerCheckpoints)) {
  const source = read(path);
  for (const checkpoint of checkpoints) {
    if (!source.includes(checkpoint)) fail(`${path} no longer emits ${checkpoint}.`);
  }
}

for (const workflow of ['application.startup', 'provider.restore_sessions', 'protection.background.run', 'protection.realtime.run']) {
  const allServer = [context, ...[
    'server/src/index.ts',
  ].map((path) => { try { return read(path); } catch { return ''; } })].join('\n');
  // Recursive server source is checked by the unit architecture test; this gate
  // requires at least the workflow to remain registered as a permanent contract.
  if (!registry.includes(`"${workflow}"`)) fail(`Automatic workflow ${workflow} is no longer registered.`);
  if (workflow === 'application.startup' && !allServer.includes('application.startup')) fail('Application startup root is no longer wired.');
}

for (const path of ['/api/dev/runtime-trace/manifest', '/api/dev/runtime-trace/diagnosis']) {
  if (!diagnosisRoutes.includes(path)) fail(`Protected runtime diagnosis route ${path} is missing.`);
}
for (const token of ['firstMissingCheckpointId', 'sourceOwner', 'buildId']) {
  if (!diagnosis.includes(token)) fail(`Runtime diagnosis no longer exposes safe ${token} evidence.`);
}

const tracerForbidden = [
  '.textContent', '.innerText', '.value', 'FormData(', 'request.body', 'rawBody', 'error.stack', 'error.message', 'sessionReplay', 'autocapture',
];
for (const token of tracerForbidden) {
  if (trace.includes(token)) fail(`Browser runtime tracer must not inspect or capture ${token}.`);
}
for (const token of ['fileURLToPath', 'EMAIL_SHIELD_BUILD_COMMIT']) {
  if (!manifestGenerator.includes(token)) fail(`Runtime trace manifest generator is missing cross-platform/exact-build token ${token}.`);
}

if (failures.length) {
  for (const message of failures) console.error(`FAIL: ${message}`);
  process.exit(1);
}
console.log(`Runtime trace coverage gate passed: ${Object.keys(ownerCheckpoints).length} browser owners plus server correlation/diagnosis invariants.`);
