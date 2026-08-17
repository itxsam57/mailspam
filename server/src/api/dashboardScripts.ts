const SHARED_DASHBOARD_SCRIPTS = [
  "/runtime-workflow-trace.js",
  "/account-selection-state.js",
  "/scan-monitor.js",
  "/unsubscribe-monitor.js",
  "/review-actions.js",
  "/analyze-links-actions.js",
  "/consumer-scan-results.js",
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
  "/developer-controls.js",
  "/app-shell.js",
  "/ui-router.js",
  "/scam-check.js",
  "/consumer-product.js",
  "/health-cleanup-controller.js",
  "/consumer-provider-onboarding.js",
  "/shopping-safety.js",
  "/media-authenticity.js",
  "/consumer-onboarding.js",
  "/billing-plan-ui.js",
  "/family-guardian-preferences.js",
] as const;

function scriptTags(paths: readonly string[]): string {
  return paths.map((path) => `<script defer src="${path}"></script>`).join("");
}

/**
 * The API server is the sole owner of browser module composition. Runtime
 * workflow tracing runs first so every later feature controller can correlate
 * a semantic user action with its protected API and Worker path without
 * inspecting mailbox content. The account selection state boundary then runs
 * before scan-monitor so a consumer selection is reflected synchronously before
 * async account-list refresh/persistence. Card enhancers are ordered from the
 * base scan renderer outwards: canonical review actions publish opaque
 * capabilities first, Analyze Links adds only its explicit token-bound
 * destination action, and consumer projections load after those card owners.
 * Every external dashboard module is deferred so the browser can fetch them in
 * parallel without blocking HTML parsing/first paint; execution order remains
 * deterministic. Developer controls fail closed before the visual shell can
 * expose the base HTML button; app-shell then constructs the visual route
 * containers. ui-router becomes the authoritative navigation/mount contract
 * before consumer feature modules declare route-owned panels. consumer-product
 * constructs the consumer provider cards and settings tools; the dedicated
 * health-cleanup-controller then becomes the sole destructive Inbox Health
 * cleanup owner, reconciling rendered subscription controls against the
 * authoritative cleanupGroups returned by the local Health worker before any
 * Trash mutation is allowed. consumer-provider-onboarding then becomes the
 * authoritative normal-consumer provider interaction boundary while keeping
 * the legacy engineering connector hidden. Shopping Safety and capability-gated
 * Media Authenticity mount after that boundary. scan-monitor owns the scan
 * stream; consumer-scan-results owns only the all-message consumer projection
 * derived from scan-monitor's bounded rows.
 */
export function dashboardScriptTags(desktop: boolean): string {
  return scriptTags(desktop
    ? [...SHARED_DASHBOARD_SCRIPTS, ...DESKTOP_ONLY_SCRIPTS]
    : SHARED_DASHBOARD_SCRIPTS);
}
