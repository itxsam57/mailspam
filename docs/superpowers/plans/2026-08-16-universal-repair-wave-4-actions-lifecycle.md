# Message Actions and Mailbox Lifecycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development or superpowers:executing-plans; use systematic-debugging + TDD for every behavior change.

**Goal:** Close EMA-8, EMA-6, EMA-16 and EMA-25 by repairing capability ownership, unsubscribe truthfulness, cleanup target identity, and disconnect lifecycle.

**Architecture:** Capabilities are action-specific and idempotent; provider mailbox state is final truth for mutations; active profile-mailbox relations share the same disconnect lifecycle as provider sessions.

**Tech Stack:** TypeScript, provider adapters, worker threads, account platform persistence, browser JS, Vitest.

### Task 1: Action capability ownership
**Files:** Modify `server/src/api/protectionActions.ts`; create `tests/unit/messageActionCapabilityOwnership.test.ts`.
- [ ] RED: Analyze Links/Unsubscribe consumption does not prevent later Mark Safe/Report Scam; replay of the same mutating action is rejected/idempotent.
- [ ] Trace the current token/lock owner and replace global used-state with `{message, actionKind}` ownership.
- [ ] Preserve confirmation and provider mutation safeguards.
- [ ] Run test GREEN and commit exact files.

### Task 2: Unsubscribe fallback truth
**Files:** Modify `server/src/workflows/unsubscribe.ts`; modify `server/src/api/consumerUnsubscribeActivityRoutes.ts`; create `tests/unit/unsubscribeFallbackContract.test.ts`.
- [ ] RED: RFC8058 eligible POST stays protected by signed-header requirements; manual service-page fallback never claims completion; invalid/unusable method does not get recorded as successful unsubscribe.
- [ ] Keep provider-vs-service failure ownership explicit and preserve no-cookie/no-provider-credential browser opening.
- [ ] Run test GREEN and commit exact files.

### Task 3: Health cleanup target resolution
**Files:** Modify `server/src/consumer/inboxHealth.ts`; modify `server/src/consumer/mailboxHealth.ts`; modify `server/src/api/consumerProtectionRoutes.ts`; modify `server/src/workers/consumerHealthWorker.ts`; create `tests/unit/healthCleanupTargetResolution.test.ts`.
- [ ] RED: a Health card reporting 1 matching message passes a stable canonical selector/identity to cleanup and provider result must report moved=1 before success title is emitted.
- [ ] RED: matched=0 renders truthful no-move activity rather than “moved messages”.
- [ ] Repair group/selector identity at producer boundary; do not infer success from card count.
- [ ] Run test GREEN and commit exact files.

### Task 4: Disconnect cleans active profile linkage
**Files:** Modify `server/src/platform/accountFamilyService.ts`; modify `server/src/api/accountLifecycleRoutes.ts`; modify `web/account-disconnect.js`; create `tests/unit/mailboxDisconnectLifecycle.test.ts`.
- [ ] RED: link mailbox -> disconnect -> exported/public account state has zero active linked mailboxes; reconnect is idempotent and produces one link.
- [ ] Decide active-vs-historical semantics in the service type; Family targeting uses active links only.
- [ ] Make account/session disconnect invoke the same active-link cleanup transactionally with credential/session teardown.
- [ ] Run test GREEN and commit exact files.

### Task 5: Closure gate
**Files:** Modify `.engineering/REGRESSION_REGISTER.md`; modify `.engineering/TEST_MATRIX.md`.
- [ ] Run `npm run typecheck`, `npm run test:unit`, `npm run test:integration`, `npm run gate`.
- [ ] Freeze exact head; require Windows/macOS/Linux + summary green.
- [ ] Update EMA-8/6/16/25 only from exact test/provider evidence.