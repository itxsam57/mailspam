const SHARED_DASHBOARD_SCRIPTS = [
  "/runtime-workflow-trace.js",
  "/account-selection-state.js",
  "/scan-live-reattach.js",
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
 * before scan-live-reattach and scan-monitor. Reattachment registers first so
 * it owns Stop only when a refreshed document has adopted an already-running
 * server worker; normal scan actions fall through to scan-monitor unchanged.
 * Card enhancers are ordered from the base scan renderer outwards: canonical
 * review actions publish opaque capabilities first, Analyze Links adds only its
 * explicit token-bound destination action, and consumer projections load after
 * those card owners. Every external dashboard module is deferred so the browser
 * can fetch them in parallel without blocking HTML parsing/first paint;
 * execution order remains deterministic. On desktop, workspace-restore runs
 * after the reattachment controller so a refreshed document can adopt the
 * existing server-owned scan worker by observing protected workspace snapshots
 * without starting another scan. Developer controls fail closed before the
 * visual shell can expose the base HTML button; app-shell then constructs the
 * visual route containers. ui-router becomes the authoritative navigation/mount
 * contract before consumer feature modules declare route-owned panels.
 * consumer-product constructs the supported consumer provider, Health, Activity
 * and safety-tool surfaces; unavailable release capabilities are not advertised
 * merely because a dormant capability-gated API exists. The dedicated
 * health-cleanup-controller then becomes the sole destructive Inbox Health
 * cleanup owner, reconciling rendered subscription controls against the
 * authoritative cleanupGroups before any Trash mutation is allowed.
 * consumer-provider-onboarding owns normal provider interaction while keeping
 * legacy engineering connection controls hidden. Shopping Safety mounts as an
 * explicit supported consumer tool.
 */
export function dashboardScriptTags(desktop: boolean): string {
  return scriptTags(desktop
    ? [...SHARED_DASHBOARD_SCRIPTS, ...DESKTOP_ONLY_SCRIPTS]
    : SHARED_DASHBOARD_SCRIPTS);
}
