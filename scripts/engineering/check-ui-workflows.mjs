import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const root = process.cwd();
const webDir = resolve(root, "web");
const failures = [];

function read(path) {
  return readFileSync(resolve(root, path), "utf8");
}

function fail(message) {
  failures.push(message);
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const html = read("web/index.html");
const browserFiles = readdirSync(webDir).filter((name) => name.endsWith(".js")).sort();
const browserSources = browserFiles.map((name) => ({ name, source: read(`web/${name}`) }));
const inlineScripts = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi)]
  .filter((match) => !/\ssrc\s*=/.test(match[0]))
  .map((match) => match[1]);
const executableSource = [...inlineScripts, ...browserSources.map((entry) => entry.source)].join("\n");
const declarationSource = [html, ...browserSources.map((entry) => entry.source)].join("\n");

const buttonIds = new Set();
for (const match of declarationSource.matchAll(/<button\b[^>]*\bid=["']([^"']+)["'][^>]*>/gi)) {
  buttonIds.add(match[1]);
}

for (const id of [...buttonIds].sort()) {
  const escaped = escapeRegExp(id);
  const directLookup = new RegExp(`getElementById\\(\\s*["']${escaped}["']\\s*\\)`);
  const selectorLookup = new RegExp(`querySelector(?:All)?\\(\\s*["'][^"']*#${escaped}(?:[^"']*)["']\\s*\\)`);
  const delegatedIdHandler = new RegExp(`\\.id\\s*===?\\s*["']${escaped}["']`);
  const iteratedIdHandler = browserSources.some(({ source }) => (
    new RegExp(`["']${escaped}["']\\s*,`).test(source) &&
    /getElementById\(\s*id\s*\)\?\.addEventListener\(/.test(source)
  ));
  if (!directLookup.test(executableSource) && !selectorLookup.test(executableSource) && !delegatedIdHandler.test(executableSource) && !iteratedIdHandler) {
    fail(`Button #${id} is rendered but has no direct, delegated, or iterated browser handler reference.`);
  }
}

const routeIds = ["home", "scan", "protection", "family", "history", "account", "settings"];
const shell = read("web/app-shell.js");
const router = read("web/ui-router.js");
const consumer = read("web/consumer-product.js");
const providerOnboarding = read("web/consumer-provider-onboarding.js");
const gmailOAuth = read("web/gmail-oauth.js");
const outlookOAuth = read("web/outlook-oauth.js");
const onboarding = read("web/consumer-onboarding.js");
const developerControls = read("web/developer-controls.js");
const operationsDashboard = read("web/operations-dashboard.js");
const composition = read("server/src/api/dashboardScripts.ts");

for (const route of routeIds) {
  if (!shell.includes(`['${route}',`) && !shell.includes(`[\"${route}\",`)) {
    fail(`App shell no longer declares required route ${route}.`);
  }
  if (!router.includes(`'${route}'`)) fail(`Authoritative UI router no longer declares route ${route}.`);
}
if (/const\s+ROUTES\s*=\s*Object\.freeze\(\[[^\]]*["']community["']/s.test(router)) {
  fail("Community must not remain in the authoritative consumer route set.");
}
if (!router.includes("RETIRED_ROUTES") || !/community\s*:\s*['\"]home['\"]/.test(router)) {
  fail("Authoritative UI router must retire legacy Community navigation to Home.");
}
if (!router.includes("NON_ROUTE_ANCHORS") || !router.includes("mainContent")) {
  fail("Retired route migration must preserve the main-content accessibility anchor.");
}
if (!router.includes("operationsPanel") || !router.includes("routeStack('settings')")) {
  fail("Authoritative UI router must re-home legacy operations diagnostics under Settings.");
}
if (!router.includes("data-route-target=\"community\"") || !router.includes("button.remove()")) {
  fail("Authoritative UI router must remove any legacy Community navigation button.");
}
if (!developerControls.includes("operationsPanel") || !developerControls.includes("email-shield-developer-ui-enabled")) {
  fail("Developer controls no longer own the fail-closed operations-diagnostics presentation boundary.");
}
if (!operationsDashboard.includes("emailShieldDeveloperEnabled") || !operationsDashboard.includes("route.dataset.route === 'settings'")) {
  fail("Operations dashboard must remain inert unless entitled diagnostics are visible under Settings.");
}

if (!shell.includes("data-route-target")) fail("App shell navigation no longer declares data-route-target buttons.");
if (!shell.includes("shell-panel-stack")) fail("App shell no longer provides route-owned panel stacks.");
if (!router.includes("data-route-target") || !router.includes("data-route") || !router.includes("data-app-route")) {
  fail("UI router no longer normalizes the shell/consumer route contracts.");
}
if (!router.includes("mountDeclaredPanels") || !router.includes("MutationObserver")) {
  fail("UI router no longer mounts late-created feature panels into their declared dashboard routes.");
}
if (!router.includes("addEventListener('click'") || !router.includes("navigate(route)")) {
  fail("UI router no longer owns click-to-route navigation.");
}
if (!router.includes("emailShieldNavigate")) fail("UI router no longer exposes the shared navigation API.");

const shellIndex = composition.indexOf('"/app-shell.js"');
const routerIndex = composition.indexOf('"/ui-router.js"');
const consumerIndex = composition.indexOf('"/consumer-product.js"');
const providerOnboardingIndex = composition.indexOf('"/consumer-provider-onboarding.js"');
const onboardingIndex = composition.indexOf('"/consumer-onboarding.js"');
if (!(shellIndex >= 0
    && routerIndex > shellIndex
    && consumerIndex > routerIndex
    && providerOnboardingIndex > consumerIndex
    && onboardingIndex > providerOnboardingIndex)) {
  fail("Desktop dashboard modules are no longer ordered shell -> router -> consumer product -> provider onboarding -> onboarding.");
}

for (const route of ["protection", "history", "family", "settings"]) {
  if (!consumer.includes(`dataset.appRoute = '${route}'`)) {
    fail(`Consumer product no longer declares its ${route} panel ownership.`);
  }
}
if (!onboarding.includes("emailShieldNavigate")) {
  fail("Consumer onboarding must navigate through the authoritative UI router instead of querying shell-private selectors.");
}
if (!onboarding.includes("route('settings')")) {
  fail("Continuous-protection onboarding must open Mailboxes & Settings where Continuous Protection is mounted.");
}
if (!shell.includes("routeContainers.get('settings').append(settingsProtection)")) {
  fail("Continuous Protection must remain mounted under Mailboxes & Settings.");
}
if (shell.includes("routeContainers.get('protection').append(protectionBackground)")) {
  fail("Continuous Protection must not be re-mounted under the Health/Protection route.");
}

const providerOnboardingLocks = [
  "if (!legacyRow.hidden) legacyRow.hidden = true",
  "if (legacyRow.style.display !== 'none') legacyRow.style.display = 'none'",
  "if (legacyRow.getAttribute('aria-hidden') !== 'true') legacyRow.setAttribute('aria-hidden', 'true')",
  "if (!connectBtn.hidden) connectBtn.hidden = true",
  "new MutationObserver(restoreConsumerVisibility)",
  "attributeFilter: ['hidden', 'style', 'aria-hidden']",
  "event.stopImmediatePropagation()",
  "providerByTitle = new Map",
  "button.dataset.consumerProvider = provider",
  "providerButtons.get('outlook')?.remove()",
  "providerButtons.delete('outlook')",
  "consumerCredentialActions",
  "window.emailShieldGoogleOAuth",
  "button.dataset.oauthConfigured",
  "loadOAuthAvailability('gmail')",
];
for (const lock of providerOnboardingLocks) {
  if (!providerOnboarding.includes(lock)) {
    fail(`Consumer provider onboarding regression lock is missing: ${lock}`);
  }
}
if (!providerOnboarding.includes("new URLSearchParams(location.search).get('developer') === '1'")) {
  fail("Consumer provider onboarding must preserve explicit developer acceptance mode while hiding engineering controls normally.");
}
if (!providerOnboarding.includes("void owner.start()")) {
  fail("Consumer Google OAuth card must call the hardened provider owner directly instead of synthesizing a hidden Connect click.");
}
if (providerOnboarding.includes("providerOrder =")) {
  fail("Consumer provider onboarding must not map provider identity by button position.");
}
if (providerOnboarding.includes("window.emailShieldMicrosoftOAuth")) {
  fail("Normal consumer onboarding must not expose Microsoft OAuth while Outlook owner acceptance is deferred.");
}
if (!gmailOAuth.includes("Object.defineProperty(window, 'emailShieldGoogleOAuth'")) {
  fail("Google OAuth module no longer exposes its hardened consumer start boundary.");
}
// Microsoft remains implemented internally for later controlled acceptance even
// though normal consumer onboarding deliberately omits it for the current build.
if (!outlookOAuth.includes("Object.defineProperty(window, 'emailShieldMicrosoftOAuth'")) {
  fail("Microsoft OAuth module no longer exposes its internal hardened consumer start boundary.");
}

const actionableDataAttributes = [
  "data-route-target",
  "data-mobile-route",
  "data-scam-check-mode",
  "data-consumer-sensitivity",
  "data-action",
  "data-select",
];
for (const attribute of actionableDataAttributes) {
  if (declarationSource.includes(attribute) && !executableSource.includes(attribute)) {
    fail(`Action contract ${attribute} is rendered but never referenced by executable browser code.`);
  }
}

if (failures.length) {
  for (const message of failures) console.error(`FAIL: ${message}`);
  process.exit(1);
}

console.log(`UI workflow audit passed: ${buttonIds.size} static button IDs, ${routeIds.length} active dashboard routes, and retired Community migration are wired.`);