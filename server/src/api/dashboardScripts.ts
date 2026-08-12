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
] as const;

function scriptTags(paths: readonly string[]): string {
  return paths.map((path) => `<script src="${path}"></script>`).join("");
}

/**
 * The API server is the sole owner of browser module composition. Card
 * enhancers are ordered from the base scan renderer outwards and loaded once;
 * browser modules must never inject sibling scripts themselves.
 */
export function dashboardScriptTags(desktop: boolean): string {
  return scriptTags(desktop
    ? [...SHARED_DASHBOARD_SCRIPTS, ...DESKTOP_ONLY_SCRIPTS]
    : SHARED_DASHBOARD_SCRIPTS);
}
