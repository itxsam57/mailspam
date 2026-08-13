const SHARED_DASHBOARD_SCRIPTS = [
  "/scan-monitor.js",
  "/unsubscribe-monitor.js",
  "/review-actions.js",
  "/protection-learning.js",
  "/safe-audit.js",
] as const;

const DESKTOP_ONLY_SCRIPTS = [
  "/workspace-restore.js",
  "/scan-history.js",
  "/background-protection.js",
  "/gmail-oauth.js",
  "/outlook-oauth.js",
  "/account-disconnect.js",
  "/policy-management.js",
  "/operations-dashboard.js",
  "/account-plan.js",
  "/account-lifecycle.js",
  "/family-shield.js",
  "/app-shell.js",
  "/scam-check.js",
  "/consumer-product.js",
  "/billing-plan-ui.js",
  "/family-guardian-preferences.js",
] as const;

function scriptTags(paths: readonly string[]): string {
  return paths.map((path) => `<script src="${path}"></script>`).join("");
}

/**
 * The API server is the sole owner of browser module composition. Card
 * enhancers are ordered from the base scan renderer outwards and loaded once.
 * The desktop shell reorganizes the proven panels first; post-shell consumer
 * modules then mount new surfaces only into explicit shell containers.
 */
export function dashboardScriptTags(desktop: boolean): string {
  return scriptTags(desktop
    ? [...SHARED_DASHBOARD_SCRIPTS, ...DESKTOP_ONLY_SCRIPTS]
    : SHARED_DASHBOARD_SCRIPTS);
}
