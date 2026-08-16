# Protection Lifecycle and Release-Mode Integrity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development or superpowers:executing-plans; use systematic-debugging + TDD for every behavior change.

**Goal:** Close EMA-18 and EMA-23 and establish the backend state needed for EMA-26 without hiding scheduler behavior or weakening entitlement enforcement.

**Architecture:** One persisted `BackgroundProtectionRecord` is authoritative for both scheduler and UI. Mailbox selection/restore never creates an enabled schedule. Consumer release mode excludes development entitlement presentation at composition time; server authorization remains independently fail-closed.

**Tech Stack:** TypeScript, Node timers/persistence, browser JS, Vitest.

## Constraints
- Runtime interval floor remains 30 minutes; maximum 24 hours.
- Account selection is not enablement.
- Disconnect removes/deactivates schedule ownership.
- No production entitlement bypass.

### Task 1: Reproduce hidden scheduler activation
**Files:** Create `tests/unit/backgroundProtectionActivationContract.test.ts`.
- [ ] RED: creating/restoring/selecting a connected account with no saved schedule produces no automatic run.
- [ ] RED: enabled record below 30 minutes is rejected/clamped by authoritative runtime validation, not only UI.
- [ ] RED: disabled record never schedules; disconnect removes account schedule/worker.
- [ ] Run test RED and commit only the test.

### Task 2: One scheduler state machine
**Files:** Modify `server/src/api/backgroundProtection.ts`; modify `server/src/api/backgroundProtectionPersistence.ts`; modify `server/src/api/defaultBackgroundProtectionRepository.ts`.
- [ ] Trace all startup/account-activation call sites before editing and document which currently creates/enables the ~2-minute behavior in the RED test comment.
- [ ] Make `enabled`, interval, next-run and account ownership derive only from repository state.
- [ ] Remove implicit schedule creation from account selection/restore paths; first enable must be explicit.
- [ ] Enforce 30-minute..24-hour whole-minute bounds in repository/service validation.
- [ ] Run `npx vitest run tests/unit/backgroundProtectionActivationContract.test.ts` GREEN and commit exact files.

### Task 3: Consumer control truth
**Files:** Modify `web/background-protection.js`; modify `web/consumer-onboarding.js`; modify `web/consumer-product.js`; create `tests/unit/backgroundProtectionConsumerSurface.test.ts`.
- [ ] RED: no mailbox -> explicit prerequisite; mailbox connected + disabled -> visible disabled state; enabled -> interval/next-run visible; Home step 6 opens this real control.
- [ ] Implement rendering from server state; no synthetic “active” state from selected account.
- [ ] Run test GREEN and commit exact files.

### Task 4: Remove dev entitlement presentation from consumer mode
**Files:** Modify `server/src/api/accountPlatformRoutes.ts`; modify `web/account-plan.js`; modify `web/billing-plan-ui.js`; modify `web/developer-controls.js`; create `tests/unit/releaseModeEntitlementSurface.test.ts`.
- [ ] RED: normal consumer profile cannot render acceptance-plan preview or `development` source as a purchase control; direct dev-switch route remains rejected outside explicit engineering mode.
- [ ] Keep signed production billing/store bridge paths intact.
- [ ] Engineering controls require both explicit engineering runtime state and developer UI request.
- [ ] Run test GREEN and commit exact files.

### Task 5: Closure gate
**Files:** Modify `.engineering/REGRESSION_REGISTER.md`; modify `.engineering/TEST_MATRIX.md`.
- [ ] Run `npm run typecheck`, `npm run test:unit`, `npm run test:integration`, `npm run gate`.
- [ ] Freeze exact head; require Windows/macOS/Linux + summary green.
- [ ] Update EMA-18/23 from exact evidence; EMA-26 remains open until its Wave 6 onboarding acceptance is complete.