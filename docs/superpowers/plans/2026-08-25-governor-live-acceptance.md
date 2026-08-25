# Governor Live Acceptance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Execute a behavior-first release Governor over every currently implemented Email Shield desktop feature, using a real Windows self-hosted runner and real Gmail provider-side truth where applicable, before batching root-cause repairs.

**Architecture:** Keep CI/unit/security evidence separate from live acceptance. A dedicated interactive Windows self-hosted runner executes the local desktop server under the same Windows user that owns the Email Shield native credential-vault entries, launches a real browser against `127.0.0.1`, captures browser/network evidence, and verifies provider mutations independently through controlled test-mail state. Existing confirmed live defects stay open until exact behavioral reproductions pass after repair.

**Tech Stack:** Node.js 22, TypeScript, GitHub Actions, Windows self-hosted runner, Email Shield localhost desktop server, Brave/Chromium browser automation, Gmail OAuth/native Windows credential vault.

**Spec:** `.engineering/TEST_MATRIX.md`, `.engineering/REGRESSION_REGISTER.md`, `docs/THREE_MILESTONE_FINAL_RECONCILIATION.md`, GitHub issue #135.

## Global Constraints

- Do not expose Gmail passwords, OAuth refresh tokens, credential-vault secrets, app passwords or provider message bodies in workflow logs/artifacts.
- Outlook live acceptance remains postponed by owner and cannot be marked accepted.
- A green automated gate does not replace live/provider acceptance where a feature has a real external effect.
- No production bug fix is permitted before a failing behavioral regression reproduces the defect.
- Destructive mailbox actions must target only explicitly marked Governor fixture messages.
- Every repair requires exact-head Windows/macOS/Ubuntu engineering gates plus the applicable live reproduction before closure.

---

### Task 1: Interactive Windows Live Runner

**Files:**
- Create: `.github/workflows/governor-live-windows.yml`
- Create: `tests/live/governor/windowsHarness.mjs`

**Interfaces:**
- Consumes: self-hosted runner label `email-shield-live`, existing local Email Shield persistence/vault.
- Produces: sanitized JSON/HTML/screenshots/logs containing no provider credentials or raw message bodies.

- [ ] Write a failing runner-presence/smoke workflow that checks Node 22, repository checkout, `npm ci`, build, server start, `GET /`, and browser reachability on `127.0.0.1`.
- [ ] Run it on the dedicated interactive Windows runner and verify it fails clearly if the runner or preserved Gmail account state is unavailable.
- [ ] Add the minimal harness required to launch the built desktop app and Brave/Chromium without printing environment secrets.
- [ ] Re-run and require the local Home/Scan surfaces to load.
- [ ] Commit.

### Task 2: Live Scan Truth Harness

**Files:**
- Create: `tests/live/governor/scanLifecycle.live.mjs`
- Modify: `.github/workflows/governor-live-windows.yml`

**Interfaces:**
- Consumes: selected real Gmail test account already authorized in Email Shield native vault.
- Produces: scan lifecycle evidence including scan IDs, counters, subjects of explicitly prefixed Governor fixtures only, and sanitized statuses.

- [ ] Write failing live cases for fresh Quick Scan, Full Audit start/stop, active refresh reattachment, route navigation, mailbox context switch/return, and process restart.
- [ ] Run and confirm known #131 cases fail for the same live behavior while owner-confirmed lifecycle cases pass.
- [ ] Keep all production files unchanged.
- [ ] Commit RED evidence.

### Task 3: Detection Regression Pack

**Files:**
- Create: `tests/unit/governorLiveDetectionRegression.test.ts`
- Create: `tests/live/governor/detection.live.mjs`

**Interfaces:**
- Consumes: synthetic reserved-domain fixture messages and existing deterministic engine.
- Produces: verdict/evidence assertions for safe baseline, identity, URL, intent and incomplete-content behavior.

- [ ] Add a RED regression proving a subject containing the recipient address (for example `Security alert for user@gmail.com`) must not create `EXPLICIT_DOMAIN_CLAIM_MISMATCH` against an authenticated `accounts.google.com` sender merely because the recipient domain appears after `@`.
- [ ] Add RED regressions for #132: HTTP distinction, unrelated brand-like hostname/login path, percent-encoded URL normalization and evidence deduplication.
- [ ] Run focused tests and preserve expected failure output.
- [ ] Add live browser assertions against only `[ESHIELD-GOV]` fixture messages after fresh-scan selection semantics are verified.
- [ ] Commit RED evidence.

### Task 4: Exact-Once Mailbox Actions

**Files:**
- Create: `tests/live/governor/actions.live.mjs`
- Modify: `.github/workflows/governor-live-windows.yml`

**Interfaces:**
- Consumes: Governor fixture IDs and Email Shield opaque action tokens.
- Produces: browser action receipt plus provider-side label/state verification for Trash/Spam and local-policy verification for Safe/Trust/Block/Report.

- [ ] Create fresh fixture messages for each destructive action.
- [ ] Verify each explicit action changes only the intended fixture exactly once.
- [ ] Verify stale/duplicate/replayed tokens fail safely.
- [ ] Verify account switching does not redirect a stale action to another mailbox.
- [ ] Commit evidence.

### Task 5: Unsubscribe and Analyze Links

**Files:**
- Create: `tests/live/governor/unsubscribeLinks.live.mjs`

**Interfaces:**
- Consumes: controlled RFC 8058/manual-unsubscribe fixtures and reserved/safe URLs.
- Produces: explicit completion/fallback state with no raw target leakage.

- [ ] Reproduce #133 mailto fallback without invoking an uncontrolled OS mail client.
- [ ] Verify RFC 8058 one-click only runs when signed-header requirements are satisfied.
- [ ] Verify Analyze Links is explicit-only and never runs during background scans.
- [ ] Commit RED/acceptance evidence.

### Task 6: Policies, Scheduler and Family

**Files:**
- Create: `tests/live/governor/policySchedulerFamily.live.mjs`

**Interfaces:**
- Consumes: owner/dev acceptance entitlement flags only on the live runner, selected Gmail test mailbox, existing protected local persistence.
- Produces: sanitized persistence/isolation evidence.

- [ ] Re-run policy export/import/reversal and invalid-import negative cases.
- [ ] Re-run scheduled protection actual firing, manual priority, pause/resume, disconnect cleanup and restart behavior.
- [ ] Launch isolated owner/dev Family entitlement path without modifying production billing behavior.
- [ ] Exercise Family creation/persistence/isolation/alert/action/removal workflow.
- [ ] Commit evidence.

### Task 7: Security, Privacy and Release Governor

**Files:**
- Create: `tests/live/governor/securityRelease.live.mjs`
- Modify: `.github/workflows/governor-live-windows.yml`

**Interfaces:**
- Consumes: current exact branch head and existing engineering gate.
- Produces: release decision for issue #135.

- [ ] Exercise localhost Host/rebinding rejection, session/CSRF/replay boundaries, browser storage privacy and secret-safe errors from the live packaged shape.
- [ ] Run exact-head Windows live suite.
- [ ] Run standard Windows/macOS/Ubuntu engineering gates and package verification.
- [ ] Compare every #135 row to AUTO/LIVE-UI/GMAIL-TRUTH/PERSIST/ISOLATION/NEGATIVE evidence.
- [ ] Leave every external/postponed row explicitly unclaimed.
- [ ] Only after all applicable rows pass, close Governor #135.
