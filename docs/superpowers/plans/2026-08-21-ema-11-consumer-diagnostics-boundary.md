# EMA-11 Consumer Diagnostics Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: use `superpowers:executing-plans` inline in this ChatGPT session. TDD, systematic debugging, and verification-before-completion are mandatory.

**Goal:** Retire the internal Community operations surface from normal Email Shield consumers while preserving privacy-safe aggregate diagnostics for explicitly development-entitled sessions under Settings.

**Architecture:** `ui-router.js` is the authoritative consumer navigation owner and therefore owns retirement of the legacy Community route, re-homing of the legacy operations panel, and safe hash migration. `developer-controls.js` owns the presentation entitlement boundary. `operations-dashboard.js` remains inert unless that entitlement is proven and Settings is visible. `createConsumerDesktopServer()` owns the canonical HTTP denial so normal consumer mode returns 404 while the internal local diagnostics implementation remains reusable for development mode.

**Tech Stack:** TypeScript/Express, browser JavaScript, Vitest, Chromium CDP engineering smokes, GitHub Actions immutable-SHA matrix.

**Spec:** Linear EMA-11 plus `.engineering/CONTINUATION.json` on `repair/ema-11-consumer-community-boundary-20260820`.

## Global Constraints

- Root-cause repairs only; no timing patches, hidden bypasses, or provider-specific exceptions.
- Normal consumer mode must expose no Community navigation or operations snapshot contract.
- `#community` must migrate safely to Home; unrelated anchors such as `#mainContent` must remain untouched.
- Diagnostics require explicit `?developer=1` plus `developmentEntitlementsEnabled === true` from the protected profile snapshot.
- Aggregate diagnostics must remain `aggregate_only_no_mailbox_identity_or_content` and must not emit subject, sender address, message/account/provider-native IDs, tokens, body, or exception text.
- Preserve existing loopback, same-origin, CSRF, session, CSP, developer-suite, provider, corpus, packaging, and release gates.

---

### Task 1: Preserve and verify the RED contract

**Files:**
- Test: `tests/unit/consumerCommunityBoundary.test.ts`
- Test: `tests/unit/operationsDiagnosticsBoundary.test.ts`

**Interfaces:**
- Consumes: current authoritative router and canonical consumer server.
- Produces: explicit failing contracts for route retirement, entitled diagnostics presentation, and consumer HTTP 404.

- [x] **Step 1: Write the failing tests**

```ts
expect(uiRouter).not.toMatch(/ROUTES[^\n]*community/);
expect(uiRouter).toMatch(/RETIRED_ROUTES[\s\S]*community[\s\S]*home/i);
expect((await fetch(`${consumer.baseUrl}/api/operations/v1/snapshot`, { headers })).status).toBe(404);
```

- [x] **Step 2: Verify RED on immutable SHA**

Run: full `Engineering Gate` against `cb281e7590ad78a8f4c945ceb9771612f3274180`.
Expected: exactly the EMA-11 contracts fail; existing integration/corpus/browser/server/release surfaces remain independently healthy.
Observed: Gate #1436 produced 3 EMA-11 failures with 1,226 existing tests passing, corpus 140/140 malicious and 140/140 legitimate, and all existing Chromium/server/release smokes passing.

### Task 2: Retire Community in the authoritative router

**Files:**
- Modify: `web/ui-router.js`

**Interfaces:**
- Consumes: legacy shell route DOM and `data-route-target`/`data-app-route` contracts.
- Produces: seven active routes, `{ community: 'home' }` retired-route map, legacy-shell sanitizer, safe hash migration.

- [ ] **Step 1: Implement the minimal route retirement**

```js
const ROUTES = Object.freeze(['home', 'scan', 'protection', 'family', 'history', 'account', 'settings']);
const RETIRED_ROUTES = Object.freeze({ community: 'home' });
```

- [ ] **Step 2: Re-home diagnostics and remove legacy Community DOM**

```js
const operationsPanel = document.getElementById('operationsPanel');
const settingsStack = routeStack('settings');
if (operationsPanel && settingsStack) settingsStack.append(operationsPanel);
nav.querySelectorAll('[data-route-target="community"]').forEach((button) => button.remove());
main.querySelector('.app-route[data-route="community"]')?.remove();
```

- [ ] **Step 3: Resolve direct/history `#community` to Home without rewriting `#mainContent`**

```js
const RETIRED_ROUTES = Object.freeze({ community: 'home' });
const NON_ROUTE_ANCHORS = new Set(['mainContent']);
```

### Task 3: Gate diagnostics presentation behind explicit development entitlement

**Files:**
- Modify: `web/developer-controls.js`
- Modify: `web/operations-dashboard.js`

**Interfaces:**
- Consumes: protected `/api/profile/v1/snapshot`, Settings route state.
- Produces: hidden-by-default operations panel; `email-shield-developer-ui-enabled` event/dataset proof; settings-only lazy aggregate load.

- [ ] **Step 1: Hide and mark operations diagnostics before entitlement proof**

```js
operationsPanel.hidden = true;
operationsPanel.dataset.emailShieldDeveloperDiagnostic = 'true';
```

- [ ] **Step 2: Expose only after the existing two-factor development UI boundary succeeds**

```js
if (response.ok && profile.developmentEntitlementsEnabled === true) exposeDeveloperUi();
```

- [ ] **Step 3: Keep the dashboard inert outside entitled Settings**

```js
function diagnosticsVisible() {
  if (panel.dataset.emailShieldDeveloperEnabled !== 'true' || panel.hidden) return false;
  const route = panel.closest('.app-route');
  return Boolean(route && !route.hidden && route.dataset.route === 'settings');
}
```

### Task 4: Enforce canonical consumer HTTP denial

**Files:**
- Modify: `server/src/api/consumerDesktopServer.ts`

**Interfaces:**
- Consumes: `developmentEntitlementsEnabled` from canonical desktop startup.
- Produces: normal-consumer 404 before the legacy operations route; development mode passes through to the existing protected aggregate endpoint.

- [ ] **Step 1: Add the fail-closed consumer composition guard**

```ts
if (localOptions.developmentEntitlementsEnabled !== true) {
  app.use('/api/operations/v1/snapshot', security.validateLoopbackRequest, security.securityHeaders, (_req, res) => {
    res.status(404).json({ error: 'Not found.' });
  });
}
```

### Task 5: Update permanent engineering contracts

**Files:**
- Modify: `scripts/engineering/check-ui-workflows.mjs`
- Modify: `scripts/engineering/smoke-server.mjs`
- Create: `scripts/engineering/smoke-community-boundary.mjs`
- Modify: `package.json`

**Interfaces:**
- Consumes: built canonical server and real Chromium.
- Produces: permanent assertions for seven active routes + one retired route, consumer endpoint 404, entitled aggregate 200, and real browser route/presentation behavior.

- [ ] **Step 1: Make the UI audit reject Community as an active router route**

```js
const routeIds = ['home', 'scan', 'protection', 'family', 'history', 'account', 'settings'];
if (!router.includes("RETIRED_ROUTES") || !router.includes("community: 'home'")) fail('Retired Community route contract is missing.');
```

- [ ] **Step 2: Change compiled consumer server smoke from aggregate 200 to 404; retain developer aggregate privacy assertions**

```js
const operationsResponse = await fetch(`${baseUrl}/api/operations/v1/snapshot`, { headers: protectedHeaders() });
assert(operationsResponse.status === 404, `Consumer operations snapshot returned HTTP ${operationsResponse.status}.`);
```

- [ ] **Step 3: Add real Chromium acceptance**

Consumer assertions: `#community` resolves to `#home`; no Community nav/route remains; operations panel is hidden; protected operations HTTP is 404.
Developer assertions: `?developer=1#settings` plus development entitlement exposes the operations panel and renders the aggregate-only snapshot without runtime errors.

- [ ] **Step 4: Wire the smoke into `smoke:browser`**

```json
"smoke:browser": "... && node scripts/engineering/smoke-community-boundary.mjs && ..."
```

### Task 6: Exact-head qualification and merge

**Files:**
- Modify: `.engineering/CONTINUATION.json`

- [ ] **Step 1: Run the complete immutable-head Engineering Gate**

Required: Windows, macOS, Ubuntu real Secret Service, Gate Summary, full unit/integration/corpus/browser/server/package/release checks.

- [ ] **Step 2: Inspect PR review threads and compare the qualified code head to the final governor-only head**

Required: zero unresolved review threads; final governor commit changes only `.engineering/CONTINUATION.json`.

- [ ] **Step 3: Mark PR #124 ready and squash-merge with the expected-head guard**

- [ ] **Step 4: Record signed main merge SHA in Linear EMA-11 and mark it Done only after evidence exists.**
