# Diagnostic Truth Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development or superpowers:executing-plans; use systematic-debugging + TDD for every behavior change.

**Goal:** Close EMA-5 and EMA-20 after repaired workflow ownership is stable, preserving the strict privacy boundary.

**Architecture:** Runtime tracing records opaque workflow/checkpoint identities and terminal state from the same authoritative services used by the product. Support export is a sanitized projection of those authoritative metrics/traces, never a parallel counter system.

**Tech Stack:** TypeScript, AsyncLocalStorage/runtime trace, operational metrics, Express, Vitest.

## Constraints
- No raw sender/recipient/mailbox identity, subject/body, raw URL, provider-native ID, credential/token, Family private data, device key, typed secret, raw exception/stack.
- HTTP 2xx alone cannot mark workflow success.
- Draft PR #102 is input to review/rebase, not an automatically trusted merge.

### Task 1: Reproduce contradictory diagnostics
**Files:** Create `tests/unit/supportBundleMetricReconciliation.test.ts`.
- [ ] RED: recorded automatic scan/activity must appear in provider/scheduler aggregate; cleanup action attempt/outcome must reconcile with move-to-trash metrics; disabled/no schedule must not report scheduled account.
- [ ] RED: export sanitizer rejects forbidden fields and raw exception/URL/content values.
- [ ] Run test RED and commit only the test.

### Task 2: Repair authoritative operational metrics
**Files:** Modify `server/src/api/localOperationalMetrics.ts`; modify `server/src/community/operationalMetrics.ts`; modify `server/src/api/backgroundProtection.ts`; modify `server/src/workflows/scanWorkflows.ts`; create `tests/unit/operationalMetricsAuthority.test.ts`.
- [ ] RED proves scans/actions/scheduler mutate one authoritative metric contract exactly once.
- [ ] Remove duplicate/unwired counter ownership and instrument actual terminal service boundaries.
- [ ] Run `npx vitest run tests/unit/operationalMetricsAuthority.test.ts tests/unit/supportBundleMetricReconciliation.test.ts` GREEN; commit exact files.

### Task 3: Adapt flight recorder to repaired workflows
**Files:** Modify `server/src/diagnostics/runtimeWorkflowTrace.ts`; modify `server/src/api/runtimeWorkflowTraceRoutes.ts`; modify `web/runtime-workflow-trace.js`; create `tests/unit/runtimeWorkflowTraceRepairedOwnership.test.ts`.
- [ ] Compare draft PR #102 against current repaired main before copying any code; preserve only capabilities whose source ownership still matches.
- [ ] RED: action -> protected API -> service/core/provider/storage -> backend terminal -> UI terminal has deterministic last-good/first-missing; failed terminal cannot be converted to success by 2xx.
- [ ] Implement schema/source ownership for current workflows with opaque IDs and bounded enumerated error codes.
- [ ] Run test GREEN and commit exact files.

### Task 4: Repair privacy-safe support export
**Files:** Modify `server/src/api/consumerProtectionRoutes.ts`; modify `web/consumer-product.js`; modify `tests/unit/supportBundleMetricReconciliation.test.ts`.
- [ ] RED: exported bundle contains reconciled scan/scheduler/action/trace aggregates and no forbidden fields.
- [ ] Build export only from sanitized authoritative snapshots; do not expose raw internal records.
- [ ] Run reconciliation test GREEN and commit exact files.

### Task 5: Closure gate
**Files:** Modify `.engineering/REGRESSION_REGISTER.md`; modify `.engineering/TEST_MATRIX.md`.
- [ ] Run `npm run typecheck`, `npm run test:unit`, `npm run test:integration`, `npm run gate`.
- [ ] Freeze exact head; require Windows/macOS/Linux + summary green.
- [ ] Close/update EMA-5/20 only after exported sample passes both usefulness and privacy regressions.