# Universal Email Shield Repair Program — Implementation Plan Index

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement each plan task-by-task. Every production behavior change follows superpowers:test-driven-development and superpowers:systematic-debugging.

**Goal:** Close every confirmed Email Shield defect in EMA-33 without weakening existing security, privacy, provider correctness, or already-working consumer workflows.

**Architecture:** Provider adapters may acquire and normalize provider-native facts, but one provider-neutral Email Shield core owns identity/provenance confidence, structural scam evidence, scoring, uncertainty, verdicts, and product action policy. The repair is split into independently reviewable waves so a failure in one subsystem cannot be hidden inside a large cross-product rewrite.

**Tech Stack:** TypeScript, Node.js, Vitest, provider adapters (Gmail API + IMAP family + deferred Outlook), Portable Core, browser JavaScript consumer shell, GitHub Actions Windows/macOS/Linux Engineering Gate.

## Global Constraints

- Current accepted base before this program: `af48ed7d2b70b9233aba9595d08aa337cc6b7fbf`.
- Approved design: `docs/superpowers/specs/2026-08-16-universal-email-shield-repair-design.md`.
- Linear source of truth: EMA-33 and the linked confirmed defects.
- Detection quality is an Email Shield property, never a mailbox/provider property.
- Provider adapters may normalize evidence/provenance only; no provider-specific thresholds, Safe exceptions, scam vocabularies, brand rules, or verdict forks.
- Missing/untrusted evidence is uncertainty, not safety and not threat evidence.
- Incomplete inspection must never become Safe.
- Hard contradictions override relationship history and user trust.
- Do not solve failures with threshold lowering, broad allowlists, test-only bypasses, production entitlement bypasses, or weaker SSRF/privacy controls.
- Preserve the existing portable-core strict validation boundary; evolve its versioned contract deliberately when canonical fields change.
- RED test must fail for the expected owner-observed behavior before any production repair is written.
- Every repair unit ends with focused GREEN, affected regression suites, and reviewer inspection before the next unit.
- Frozen release heads require the complete Windows/macOS/Linux Engineering Gate. Merge only the exact verified SHA, then rerun the same gate on exact merged `main`.
- Outlook/Microsoft live acceptance stays deferred until the repair program is green.
- Family Shield remains protected by real entitlement enforcement; do not create a production bypass.
- Owner reacceptance is consolidated after code closure and only retests workflows touched by the repairs.

---

## Plan sequence

### Plan 1 — Wave 0 + Wave 1: Universal detection integrity

File: `docs/superpowers/plans/2026-08-16-universal-repair-wave-0-1-detection.md`

Closes/advances: EMA-31, EMA-32, EMA-9, EMA-19, EMA-21.

Deliverable: a provider-neutral provenance model and structural Claim–Transaction–Action detector used by connected-mailbox scans and reused by consumer safety surfaces. Includes the owner regression corpus, hard-ham controls, impossible-evidence rejection, forged-provenance controls, and cross-provider parity gates.

### Plan 2 — Wave 2: Link and destination integrity

Planned file: `docs/superpowers/plans/2026-08-16-universal-repair-wave-2-links.md`

Closes: EMA-7 and EMA-10.

Primary code boundaries: `server/src/workflows/analyzeLinks.ts`, `server/src/api/linkAnalysisActions.ts`, `server/src/util/hardenedFetch.ts`, `server/src/util/domainRelation.ts`, `server/src/util/htmlInteraction.ts` plus existing network architecture tests.

Required outcomes: safe percent-encoded absolute-URL normalization, ordinary public HTTPS inspection reliability, and proof that loopback/private/link-local targets are rejected before outbound connection while redirects/DNS remain pinned and fail closed.

### Plan 3 — Wave 3: Background protection and release-mode integrity

Planned file: `docs/superpowers/plans/2026-08-16-universal-repair-wave-3-protection-release.md`

Closes: EMA-18 and EMA-23; coordinates with EMA-26.

Primary code boundaries: `server/src/api/backgroundProtection.ts`, `backgroundProtectionPersistence.ts`, `defaultBackgroundProtectionRepository.ts`, `web/background-protection.js`, `server/src/api/accountPlatformRoutes.ts`, `web/account-plan.js`, `web/billing-plan-ui.js`, `web/developer-controls.js`.

Required outcomes: one authoritative persisted scheduler state shared by UI/runtime, no implicit ~2-minute activation on mailbox selection, 30-minute minimum enforced at runtime, disconnect lifecycle cleanup, and no development entitlement surface in normal consumer mode while backend denial remains intact.

### Plan 4 — Wave 4: Message/provider action and account lifecycle correctness

Planned file: `docs/superpowers/plans/2026-08-16-universal-repair-wave-4-actions-lifecycle.md`

Closes: EMA-8, EMA-6, EMA-16, EMA-25.

Primary code boundaries: `server/src/api/protectionActions.ts`, `server/src/workflows/unsubscribe.ts`, `blockAndCleanup.ts`, `reportSpam.ts`, `server/src/consumer/inboxHealth.ts`, `mailboxHealth.ts`, `server/src/platform/accountFamilyService.ts`, `accountFamilyPersistence.ts`, live connection/session persistence, and browser action modules.

Required outcomes: action-specific capability/idempotency ownership, truthful unsubscribe fallback, provider-confirmed cleanup target resolution, and disconnect removing active profile-mailbox linkage without erasing legitimate history.

### Plan 5 — Wave 5: Diagnostic truth

Planned file: `docs/superpowers/plans/2026-08-16-universal-repair-wave-5-diagnostics.md`

Closes: EMA-5 and EMA-20.

Primary code boundaries: `server/src/diagnostics/runtimeWorkflowTrace.ts`, `runtimeWorkflowTraceRoutes.ts`, `localOperationalMetrics.ts`, `server/src/community/operationalMetrics.ts`, support bundle/export code, and draft PR #102 only after rebasing/adapting it to repaired workflow ownership.

Required outcomes: one privacy-safe action → workflow → API → service/core/provider/storage → backend terminal → UI terminal trace, plus support metrics that reconcile with the product's authoritative scan/scheduler/action state.

### Plan 6 — Wave 6: Health and consumer composition

Planned file: `docs/superpowers/plans/2026-08-16-universal-repair-wave-6-consumer.md`

Closes: EMA-17, EMA-15, EMA-11, EMA-12, EMA-13, EMA-26, EMA-27, EMA-28, EMA-29, EMA-30, EMA-24, EMA-22.

Primary code boundaries: Health consumer services/worker, `web/consumer-product.js`, `web/consumer-onboarding.js`, `web/app-shell.js`, `web/scan-history.js`, `web/operations-dashboard.js`, notification ownership, Account/Plan, Media Authenticity, and existing final-consumer contract tests.

Required outcomes: differentiated/canonical Health output, consumer-facing Community threat surface instead of engineering operations, real Activity drill-down, notification ownership/deferment, capability-specific onboarding prerequisites, prominent restore-purchase terminal state, and Media Authenticity hidden/deferred until a vetted detector exists.

### Final external acceptance

Not implemented as bypasses:

- EMA-14: real Family entitlement acceptance.
- Outlook/Microsoft: deliberate live acceptance after the repair program is green.
- Other production infrastructure gaps remain tracked by existing engineering roadmap/gap records.

## Program completion gate

The program is DONE only when every confirmed code/workflow issue listed by EMA-33 is root-fixed and regression-locked, exact normalized evidence produces equivalent Email Shield decisions across provider adapters, existing working security/privacy behavior remains green, the full three-OS gate passes on the exact repair head and exact merged `main`, and only deliberate external owner acceptance remains.