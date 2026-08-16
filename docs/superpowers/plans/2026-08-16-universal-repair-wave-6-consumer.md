# Health and Consumer Composition Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development or superpowers:executing-plans; use systematic-debugging + TDD for every behavior change.

**Goal:** Close EMA-17, EMA-15, EMA-11, EMA-12, EMA-13, EMA-26, EMA-27, EMA-28, EMA-29, EMA-30, EMA-24 and EMA-22 after backend correctness is stable.

**Architecture:** Consumer pages are projections of authoritative product capabilities/state. Internal operations stay behind diagnostics/developer boundaries. Onboarding prerequisites are per capability, not one mailbox-wide guard.

**Tech Stack:** TypeScript consumer services, Express routes, vanilla browser JS, Vitest/browser-contract tests.

### Task 1: Health canonical aggregation
**Files:** Modify `server/src/consumer/inboxHealth.ts`; modify `server/src/consumer/mailboxHealth.ts`; modify `server/src/consumer/digitalFootprint.ts`; create `tests/unit/healthConsumerAggregation.test.ts`.
- [ ] RED: duplicate subscription/account-footprint identities canonicalize by stable semantic key while distinct unsubscribe/security meanings remain separate.
- [ ] RED: repeated provider security alerts aggregate/differentiate by service/category/time/count instead of nine indistinguishable cards.
- [ ] Implement canonical aggregation before DTO rendering, not DOM dedupe.
- [ ] Run test GREEN and commit exact files.

### Task 2: Community becomes a consumer threat surface
**Files:** Modify `web/consumer-product.js`; modify `web/operations-dashboard.js`; modify `server/src/api/consumerProtectionRoutes.ts`; create `tests/unit/communityConsumerSurface.test.ts`.
- [ ] RED: normal Community route does not expose provider transport/adaptor counters; consumer surface can render privacy-safe campaign/category/risk/recommended-action summaries from existing verified aggregate intelligence.
- [ ] Move engineering operations UI to developer/diagnostic composition rather than deleting diagnostics.
- [ ] Outlook operational presence must not imply consumer availability while Outlook acceptance is deferred.
- [ ] Run test GREEN and commit exact files.

### Task 3: Activity details and notification ownership
**Files:** Modify `web/consumer-product.js`; modify `web/scan-history.js`; modify `server/src/api/consumerProtectionRoutes.ts`; create `tests/unit/activityAndNotificationSurface.test.ts`.
- [ ] RED: Activity row exposes a privacy-safe detail view using recorded reason codes/timestamp/provider/action state; no raw mail content is added.
- [ ] RED: richer-notification preference is shown only with a real local notification capability/status owner; when unavailable the UI truthfully marks notifications unavailable/deferred instead of presenting an orphan switch.
- [ ] Implement detail and capability projection; do not fabricate OS notification permission.
- [ ] Run test GREEN and commit exact files.

### Task 4: Onboarding capability state machine
**Files:** Modify `web/consumer-onboarding.js`; modify `web/consumer-product.js`; modify `server/src/api/consumerProtectionRoutes.ts`; create `tests/unit/onboardingCapabilityPrerequisites.test.ts`.
- [ ] RED exact owner sequence: step 2 Connect mailbox opens connection; step 3 Review permissions is clickable; step 4 with no mailbox explains/connects rather than masquerading local Scam Check as mailbox scan; step 5 explains mailbox prerequisite or persists a preconnection choice; step 6 opens actual background protection state from Wave 3; Family Open/Not now and Confirm Home are not blocked by mailbox guard.
- [ ] Replace one shared mailbox guard with per-step capability prerequisites and explicit completion semantics.
- [ ] Run test GREEN and commit exact files.

### Task 5: Account feedback and release-incomplete media
**Files:** Modify `web/account-plan.js`; modify `web/billing-plan-ui.js`; modify `server/src/consumer/mediaAuthenticity.ts`; modify `web/consumer-product.js`; create `tests/unit/accountPlanAndMediaReleaseSurface.test.ts`.
- [ ] RED: Restore purchase unsupported bridge result is prominent, accessible and terminal; no entitlement mutation.
- [ ] RED: when no vetted media detector is configured, normal consumer composition does not present a dead primary feature as working; it is hidden/deferred with truthful capability state.
- [ ] Preserve backend fail-closed Media Authenticity semantics; never infer authentic from detector absence.
- [ ] Run test GREEN and commit exact files.

### Task 6: Consumer closure gate
**Files:** Modify `.engineering/REGRESSION_REGISTER.md`; modify `.engineering/TEST_MATRIX.md`.
- [ ] Run `npm run typecheck`, `npm run test:unit`, `npm run test:integration`, `npm run check:browser-boot`, `npm run gate`.
- [ ] Freeze exact head; require Windows/macOS/Linux + summary green.
- [ ] Perform one consolidated owner browser reacceptance only for changed surfaces; do not retest passed provider workflows unless touched.
- [ ] Update each EMA issue only from its explicit acceptance evidence; EMA-14 and Outlook remain external acceptance.