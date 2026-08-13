# REG-082 — Browser boot runtime ownership

**Status:** LOCKED

## Regression / required invariant

The desktop dashboard must complete real browser initialization without a renderer-starving synchronous or microtask feedback loop.

`billing-plan-ui.js` must not observe the entire dashboard for `hidden` mutations while also owning writes to `accountDevPlans.hidden`. Billing visibility is driven by the explicit `email-shield-profile-changed` and `email-shield-route-changed` application contracts, and any developer-plan visibility write must be idempotent.

The public navigation contract must continue to have one runtime owner: `ui-router.js`. `app-shell.js` must not republish the immutable `window.emailShieldNavigate` global.

## Root cause fixed

The browser-only failure had two independent layers:

1. `app-shell.js` and `ui-router.js` both attempted to define the same non-configurable `window.emailShieldNavigate` global. That collision was removed on `main` before this regression was formally locked.
2. `billing-plan-ui.js` installed a document-wide `MutationObserver` for `hidden` changes and, from the observer callback, unconditionally wrote `accountDevPlans.hidden = true`. That write could schedule the observer again even when the desired state was already true, producing a self-feeding microtask loop that starved the renderer. The local HTTP server therefore reached `listening` while a real browser appeared to hang.

The billing mutation observer has been removed. Billing now reacts only to explicit profile/route events, and developer visibility is changed only when the DOM state actually needs to change.

## Automated protection

The blocking `smoke:browser` Engineering Gate launches the compiled desktop server and an installed Chromium-family browser on an isolated loopback origin, executes the exact protected dashboard and production deferred-script order, captures uncaught browser errors/rejections, verifies one authoritative public navigation function, renders the application shell, and exercises real Scan -> Home routing.

The smoke also inserts temporary per-script execution checkpoints during the gate so a future renderer lock reports the last production script that returned. Temporary smoke files are deleted after execution and are not production hooks.

**Blocking coverage:** `scripts/engineering/smoke-browser-boot.mjs`, `npm run smoke:browser`, `npm run gate`, immutable Windows/macOS/Ubuntu Engineering Gate.
