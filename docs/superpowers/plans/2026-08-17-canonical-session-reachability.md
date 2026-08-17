# Canonical Session Reachability Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to execute this plan task-by-task.

**Goal:** Make reconnect/credential-rotation ownership deterministic so exactly one canonical live session drives automatic protection for each stable mailbox, while exposing truthful per-mailbox reachability to the consumer UI.

**Architecture:** `SessionStore` is the single source of truth for canonical-vs-superseded live-session ownership. A successful replacement transaction promotes the new session only after protected credential storage and persistent registry state succeed; failed replacement leaves the previous canonical session unchanged. Automatic background/realtime consumers resolve canonical ownership through `SessionStore`, while genuinely unexplained duplicate sessions remain fail-closed. Existing metadata-only realtime heartbeat becomes the authoritative source of sanitized per-mailbox reachability (`verifying`, `reachable`, `provider_unavailable`); the browser must never infer readiness merely from selection.

**Tech Stack:** TypeScript/Node server, provider adapters, browser JavaScript, Vitest/unit tests, compiled browser smoke harnesses, GitHub Actions Engineering Gate.

---

## Task 1: RED — canonical replacement lifecycle

**Files:**
- Modify the existing SessionStore/account lifecycle unit-test file(s).
- Read-only reference: `server/src/api/sessionStore.ts`.

**Tests:**
1. Create an old live session for mailbox A, then a replacement with the same stable `policyAccountKey`; after the successful protected-credential/persistence transaction the replacement must resolve as canonical and the old session must be superseded/non-automatic.
2. Force protected credential or persistence failure while creating a replacement; the previous canonical session must remain canonical.
3. Removing the superseded old session must not remove/revoke the replacement or its persistent descriptor.
4. Preserve fail-closed behavior for genuinely ambiguous duplicate ownership that was not created through an intentional replacement transition.

Run the smallest focused test command and prove RED for missing canonical-session behavior before production edits.

## Task 2: GREEN — centralize canonical ownership in SessionStore

**Files:**
- Modify: `server/src/api/sessionStore.ts`
- Modify only lifecycle/persistence helpers required by the root cause.

**Implementation:**
- Track intentional supersession/replacement provider-neutrally by stable mailbox identity.
- Add one central canonical-session resolver/listing API.
- Promote a replacement only after the existing secured credential + persistence transaction has succeeded.
- Keep old sessions available only for transient lifecycle/refcount safety; exclude superseded sessions from automatic ownership and consumer active-account listing.
- Ensure removal of a superseded session cannot revoke/delete the current replacement grant/descriptor.
- Keep unexplained ambiguity fail-closed.

Run focused lifecycle tests to GREEN, then related SessionStore/account tests.

## Task 3: RED/GREEN — background and realtime automatic ownership

**Files:**
- Modify existing background-protection tests and implementation.
- Modify existing realtime service/processor tests and implementation.

**Tests/behavior:**
- Old + replacement for one mailbox: background scheduler uses only canonical replacement.
- Heartbeat probes only canonical replacement; stale superseded credential is never probed.
- Realtime processor accepts intentional superseded overlap by resolving the canonical replacement.
- Genuinely ambiguous duplicate ownership still produces `provider_mismatch`/fail-closed behavior.
- Remove ad-hoc `.find()`/insertion-order ownership selection from automatic consumers and route them through SessionStore.

Verify each RED before the corresponding production change, then GREEN.

## Task 4: RED/GREEN — canonical account listing and per-mailbox reachability

**Files:**
- Modify `/api/accounts` server route/model tests and implementation.
- Modify realtime heartbeat state/tests.

**Behavior:**
- Reconnect returns only one canonical consumer mailbox row.
- New canonical mailbox begins `verifying`.
- Successful metadata-only heartbeat marks that canonical mailbox `reachable`.
- Probe failure marks only that mailbox `provider_unavailable`.
- A stale/superseded session failure cannot poison its replacement or another mailbox.
- Expose only sanitized status; never expose raw provider exceptions, tokens, credential material, or mailbox bodies.

## Task 5: RED/GREEN — fixture checkpoint and truthful Home UI

**Files:**
- Modify fixture adapter/harness to support metadata-only `mailboxCheckpoint()` parity.
- Modify browser/server smoke tests.
- Modify `web/app-shell.js` and only directly related presentation code.

**Behavior:**
- Browser reconnect shows one canonical row.
- Selected mailbox with `verifying` must not display "Protection ready".
- `reachable` may display ready.
- `provider_unavailable` displays a needs-attention state without leaking provider errors.
- Rapid A↔B selection rejects stale health responses.
- Fixture checkpoint remains metadata-only and does not introduce any production/dev entitlement bypass.

## Task 6: Runtime/browser acceptance expansion

Automate high-value acceptance gaps where deterministic fixtures support them:
- MAN-F45 scan presentation: Quick, terminal Full, Spam/Junk, no stale/duplicate counters/cards.
- MAN-F46 Stop→Resume exact checkpoint and refresh resumability.
- MAN-F47 two-account results/policies/actions/history isolation.
- MAN-F48 two-account background status/schedule isolation, manual-scan priority, pause/disconnect cleanup.
- MAN-F49 exactly one visible control per supported message action.
- MAN-F57 broken connection truth.
- MAN-F58 all eight routes repeatedly plus refresh, no blank/frozen/stale/duplicate overlays.

Do not invent a bug when an item is only a proof gap; add runtime acceptance coverage unless root-cause evidence shows a defect.

## Task 7: Verification and PR

1. Run focused changed-area tests.
2. Run relevant compiled browser/runtime smokes.
3. Run the full exact-head Engineering Gate, including Windows, macOS, Ubuntu and real Linux Secret Service checks required by the repository gate.
4. Verify no privacy regression, raw error/token/credential leak, provider-specific scoring fork, or consumer entitlement bypass.
5. Create a PR from `repair/canonical-session-reachability-p0-20260817` to `main` only after the entire wave is green.
6. Freeze/report exact PR head and gate evidence.
7. **Do not merge.** Merge requires a fresh explicit user authorization naming that PR. Outlook real normal-consumer live acceptance remains postponed until the owner can test it.
