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
  if (!directLookup.test(executableSource) && !selectorLookup.test(executableSource)) {
    fail(`Button #${id} is rendered but has no browser lookup/handler reference.`);
  }
}

const routeIds = ["home", "scan", "protection", "family", "community", "history", "account", "settings"];
const shell = read("web/app-shell.js");
const router = read("web/ui-router.js");
const consumer = read("web/consumer-product.js");
const onboarding = read("web/consumer-onboarding.js");
const composition = read("server/src/api/dashboardScripts.ts");

for (const route of routeIds) {
  if (!shell.includes(`['${route}',`) && !shell.includes(`[\"${route}\",`)) {
    fail(`App shell no longer declares required route ${route}.`);
  }
  if (!router.includes(`'${route}'`)) fail(`Authoritative UI router no longer declares route ${route}.`);
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
const onboardingIndex = composition.indexOf('"/consumer-onboarding.js"');
if (!(shellIndex >= 0 && routerIndex > shellIndex && consumerIndex > routerIndex && onboardingIndex > routerIndex)) {
  fail("Desktop dashboard modules are no longer ordered shell -> authoritative router -> consumer modules.");
}

for (const route of ["protection", "history", "family", "settings"]) {
  if (!consumer.includes(`dataset.appRoute = '${route}'`)) {
    fail(`Consumer product no longer declares its ${route} panel ownership.`);
  }
}
if (!onboarding.includes("emailShieldNavigate")) {
  fail("Consumer onboarding must navigate through the authoritative UI router instead of querying shell-private selectors.");
}
if (!onboarding.includes("route('protection')")) {
  fail("Continuous-protection onboarding must open the Protection route where Background Protection is mounted.");
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

console.log(`UI workflow audit passed: ${buttonIds.size} static button IDs and ${routeIds.length} dashboard routes are wired.`);