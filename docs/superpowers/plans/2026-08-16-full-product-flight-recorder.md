# Full-Product Diagnostic Flight Recorder Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expand Email Shield's existing source/dev runtime trace into a privacy-safe whole-product flight recorder that can identify the last-good and first-failed/missing workflow checkpoint, map that boundary to the exact tested source commit/file/function/line, and enforce trace coverage before final live acceptance.

**Architecture:** Keep the existing local recorder and first-loaded browser tracer as the only trace sinks/correlation owners. Add schema-v2 checkpoint events, a static workflow registry, a generated source-ownership manifest, a deterministic diagnosis engine, exhaustive browser/API coverage enforcement, and strategic checkpoint emissions at existing feature/service state transitions without creating second owners for product workflows.

**Tech Stack:** TypeScript 5.9, Node.js 20+, Express 4, Vitest 4, browser JavaScript, existing Email Shield protected local API/session/CSRF/nonce boundary, GitHub Actions engineering gate, optional existing PostHog technical telemetry.

## Global Constraints

- No raw email body, HTML, subject, sender, recipient, mailbox address, account ID, provider-native message ID, attachment body/name, contact list, credentials, OAuth tokens, app passwords, recovery codes, form values, request bodies, raw URLs/query strings, raw exception messages, or stack traces may be recorded.
- Trace failures are fail-soft and must never alter protection behavior.
- Existing mailbox/provider mutation authorization, CSRF, nonce, session, loopback, vault, policy, community, Family, and detection rules are unchanged.
- Normal packaged consumer telemetry behavior remains unchanged; local source/dev tracing remains behind `EMAIL_SHIELD_RUNTIME_TRACE=1` and `npm run dev` source acceptance.
- PostHog remains separately opt-in and may mirror only independently validated sanitized trace fields.
- Outlook/Microsoft remains internally implemented but hidden/postponed from normal consumer acceptance.
- The flight recorder must never become a second owner for scan SSE, account selection, provider onboarding, navigation, message actions, background protection, or any domain workflow.
- Exact frozen PR head must pass Windows, macOS, Ubuntu/Linux Secret Service, full engineering gates and strengthened trace-coverage audit; merged `main` must pass an independent push-triggered three-OS gate before owner final live testing.

---

## File structure

**Core diagnostics**
- Modify `server/src/diagnostics/runtimeWorkflowTrace.ts` — schema-v2 writer/reader, strict validation, build identity.
- Create `server/src/diagnostics/runtimeTraceCheckpoint.ts` — one fail-soft checkpoint emission API for server/domain owners.
- Create `server/src/diagnostics/workflowRegistry.ts` — static workflow/action/checkpoint/terminal graph.
- Create `server/src/diagnostics/workflowDiagnosis.ts` — deterministic diagnosis from records + manifest.
- Create `server/src/diagnostics/checkpointManifest.ts` — typed manifest loader/validator.
- Create `scripts/engineering/generate-runtime-trace-manifest.mjs` — static source scanner producing exact path/function/line/build ownership.
- Create `scripts/engineering/check-runtime-trace-coverage.mjs` — CI invariants for actions, routes, workflows, terminals and checkpoints.
- Create generated `server/src/diagnostics/generated/runtimeTraceManifest.json` — deterministic exact-tree ownership output.

**Browser correlation and feature completion**
- Modify `web/runtime-workflow-trace.js` — exhaustive semantic action registry, workflow IDs, route masking, public safe checkpoint helper, automatic UI terminal checkpoints.
- Modify feature modules only at real completion/branch boundaries: `web/account-selection-state.js`, `web/scan-monitor.js`, `web/background-protection.js`, `web/gmail-oauth.js`, `web/consumer-provider-onboarding.js`, `web/account-disconnect.js`, `web/policy-management.js`, `web/account-lifecycle.js`, `web/family-shield.js`, `web/scam-check.js`, `web/shopping-safety.js`, `web/media-authenticity.js`, `web/consumer-onboarding.js`, `web/billing-plan-ui.js`, `web/family-guardian-preferences.js`, `web/unsubscribe-monitor.js`, `web/review-actions.js`, `web/analyze-links-actions.js`, `web/consumer-scan-results.js`, `web/ui-router.js`, `web/workspace-restore.js`, `web/operations-dashboard.js`.

**Server/domain boundaries**
- Modify representative authoritative owners rather than every helper: `server/src/index.ts`, `server/src/api/runtimeWorkflowTraceRoutes.ts`, `server/src/api/consumerDesktopServer.ts`, `server/src/api/backgroundProtection.ts`, `server/src/api/accountLifecycleRoutes.ts`, `server/src/api/accountPlatformRoutes.ts`, `server/src/api/consumerProtectionRoutes.ts`, scan/provider worker owners, Gmail OAuth/credential connection routes, Family/account services, Scam Check routes, personal-policy routes, community/operations routes, and provider-session restoration owner discovered in current tree.
- Modify `server/src/telemetry/technicalTelemetry.ts` — independently validate new v2 mirror properties.

**Tests/docs/gates**
- Extend `tests/unit/runtimeWorkflowTrace.test.ts`, `runtimeWorkflowTraceApi.test.ts`, `runtimeWorkflowTraceBrowser.test.ts`, `runtimeWorkflowScanTrace.test.ts`, `runtimeWorkflowTraceTelemetry.test.ts`.
- Create `tests/unit/runtimeTraceCheckpoint.test.ts`, `runtimeTraceManifest.test.ts`, `workflowDiagnosis.test.ts`, `runtimeTraceCoverage.test.ts`.
- Add representative integration/failure-injection tests under `tests/integration/`.
- Modify `scripts/engineering/check-ui-workflows.mjs`, `package.json`, `docs/technical-telemetry.md`, and final acceptance/handoff docs.

---

### Task 1: Schema v2 and one checkpoint emission contract

**Files:**
- Modify: `server/src/diagnostics/runtimeWorkflowTrace.ts`
- Create: `server/src/diagnostics/runtimeTraceCheckpoint.ts`
- Test: `tests/unit/runtimeWorkflowTrace.test.ts`
- Test: `tests/unit/runtimeTraceCheckpoint.test.ts`

**Interfaces:**
- Produces `RuntimeWorkflowTraceRecordV2`, `RuntimeWorkflowTraceEventV2` and backward-readable v1 record union.
- Produces `recordRuntimeCheckpoint(input: RuntimeCheckpointInput): boolean`.
- `RuntimeCheckpointInput` contains only `traceId`, `workflowId`, `actionId`, `checkpointId`, `stage`, `outcome` plus existing bounded safe metadata.

- [ ] **Step 1: Write RED schema-v2 tests.** Assert `schemaVersion: 2`, required `workflowId`/`buildId`, checkpoint acceptance, v1 read compatibility, and rejection of unknown fields such as `subject`, `email`, `accountId`, `url`, `message`, `stack`, `requestBody`.

```ts
expect(recorder.record({
  traceId,
  workflowId: 'family.create',
  actionId: 'family.create',
  checkpointId: 'family.create.state_persisted',
  stage: 'workflow',
  outcome: 'success',
})).toBe(true);
expect(recorder.record({ ...safe, subject: 'secret' } as never)).toBe(false);
```

- [ ] **Step 2: Run focused RED tests.**

```bash
npm run test:unit -w server -- runtimeWorkflowTrace.test.ts runtimeTraceCheckpoint.test.ts
```

Expected: failure because v2/checkpoint API does not exist.

- [ ] **Step 3: Implement strict v2 validation and backward reading.** Keep rotation/file mode/fail-soft behavior; writer emits only v2; reader accepts existing v1 plus v2 but never upgrades old records into product state.

```ts
export interface RuntimeWorkflowTraceEventV2 {
  traceId: string;
  workflowId: string;
  actionId: string;
  stage: RuntimeWorkflowTraceStage;
  outcome: RuntimeWorkflowTraceOutcome;
  checkpointId?: string;
  buildId: string;
  // only existing bounded safe optionals
}
```

- [ ] **Step 4: Implement one server checkpoint helper.** It obtains the initialized recorder, validates the literal checkpoint input through the recorder, returns false on any trace failure, and never throws into product code.

```ts
export function recordRuntimeCheckpoint(input: RuntimeCheckpointInput): boolean {
  try {
    return runtimeWorkflowTrace()?.record({ ...input, buildId: runtimeTraceBuildId() }) ?? false;
  } catch {
    return false;
  }
}
```

- [ ] **Step 5: Run focused tests, typecheck, commit.**

```bash
npm run test:unit -w server -- runtimeWorkflowTrace.test.ts runtimeTraceCheckpoint.test.ts
npm run typecheck
```

---

### Task 2: Workflow registry, exact source manifest, and diagnosis engine

**Files:**
- Create: `server/src/diagnostics/workflowRegistry.ts`
- Create: `server/src/diagnostics/checkpointManifest.ts`
- Create: `server/src/diagnostics/workflowDiagnosis.ts`
- Create: `scripts/engineering/generate-runtime-trace-manifest.mjs`
- Create: `server/src/diagnostics/generated/runtimeTraceManifest.json`
- Test: `tests/unit/runtimeTraceManifest.test.ts`
- Test: `tests/unit/workflowDiagnosis.test.ts`

**Interfaces:**
- Produces `WORKFLOW_REGISTRY` keyed by stable workflow IDs.
- Produces `diagnoseRuntimeWorkflow(records, manifest, workflowId): WorkflowDiagnosis`.
- Generator statically finds literal `recordRuntimeCheckpoint({ checkpointId: '...'` and browser `.checkpoint('...')` calls, resolves source path, nearest named function/owner, 1-based line, exact build/commit identity.

- [ ] **Step 1: Write RED manifest tests.** Prove deterministic generation, duplicate checkpoint rejection, nonexistent registry checkpoint rejection, and exact source line/path/function ownership.

- [ ] **Step 2: Write RED diagnosis tests** for happy path, explicit failure, first missing checkpoint, provider variant, cancellation/rejection, and backend-success/UI-confirmation-missing.

```ts
expect(diagnosis).toMatchObject({
  terminalOutcome: 'incomplete',
  lastSuccessfulCheckpoint: 'family.create.response_returned',
  firstMissingCheckpoint: 'family.create.ui_confirmed',
  suspectedOwner: { path: 'web/family-shield.js' },
});
```

- [ ] **Step 3: Implement static workflow graph.** Register all current normal-consumer families from the approved spec: startup/state; provider onboarding/restore; quick/full/spam/stop/resume/history; message actions; background/realtime protection; settings/policies/activity/health/undo; Check Anything; Family/Guardian; community/operations; account/subscription/lifecycle; Shopping Safety; Media Authenticity; onboarding/support. Outlook is `internalOnly: true`.

- [ ] **Step 4: Implement source manifest generator.** It must reject dynamic checkpoint IDs; never handwrite line numbers; normalize repository-relative paths; derive build identity from `EMAIL_SHIELD_BUILD_COMMIT`/Git exact head during gate generation; emit stable sorted JSON.

- [ ] **Step 5: Implement deterministic diagnosis.** It must never infer success from HTTP 2xx alone and must use graph terminals/checkpoints only.

- [ ] **Step 6: Generate manifest, run tests/typecheck, commit.**

```bash
node scripts/engineering/generate-runtime-trace-manifest.mjs
npm run test:unit -w server -- runtimeTraceManifest.test.ts workflowDiagnosis.test.ts
npm run typecheck
```

---

### Task 3: Exhaustive browser action/API correlation and UI-terminal checkpoints

**Files:**
- Modify: `web/runtime-workflow-trace.js`
- Modify: `scripts/engineering/check-ui-workflows.mjs`
- Test: `tests/unit/runtimeWorkflowTraceBrowser.test.ts`
- Test: `tests/unit/runtimeTraceCoverage.test.ts`

**Interfaces:**
- Browser trace context becomes `{traceId, workflowId, actionId, provider?, scanType?, startedAt}`.
- Public API gains `checkpoint(checkpointId, outcome, safeExtra?)` and `automaticRoot(actionId, workflowId, safeExtra?)`.
- Every consumer API path maps to a masked route family; supported workflows may not depend on `/api/other`.

- [ ] **Step 1: Write RED inventory tests.** Inventory static IDs, `data-route-target`, `data-mobile-route`, `data-scam-check-mode`, `data-consumer-sensitivity`, `data-action`, `data-select`, provider cards and known dynamic button factories. Assert every reachable consumer action maps to an action/workflow registration.

- [ ] **Step 2: Write RED route-mask tests.** Parse literal `/api/...` browser calls and require a non-`/api/other` mask for every supported consumer workflow path.

- [ ] **Step 3: Expand semantic registry and protected correlation.** Preserve trusted-click ownership and synthetic-click rejection. Add exact workflow IDs rather than only `expectedWorkflow` labels.

- [ ] **Step 4: Add safe checkpoint/automatic-root browser APIs.** No DOM text/form value/request body may be accepted as metadata; safe fields are enum/label/numeric only.

- [ ] **Step 5: Strengthen UI workflow CI audit.** A rendered consumer action without trace registration is a gate failure; a registered action without reachable UI/automatic root is also a failure.

- [ ] **Step 6: Run browser/coverage tests and `npm run check:web`, commit.**

---

### Task 4: Instrument browser feature owners at meaningful completion boundaries

**Files:**
- Modify the browser modules listed in File Structure.
- Test: extend `tests/unit/runtimeWorkflowTraceBrowser.test.ts`; add focused source-ownership assertions.

**Interfaces:**
- Feature modules call only `window.emailShieldRuntimeTrace?.checkpoint('<literal-id>', '<outcome>', safeExtra)`.
- They do not create trace IDs, send telemetry directly, or own persistence.

- [ ] **Step 1: Add RED source tests** requiring registered completion/failure checkpoints in each consumer module family.
- [ ] **Step 2: Instrument navigation/account/workspace/onboarding owners.** Record requested/applied/stale-suppressed/visible completion boundaries.
- [ ] **Step 3: Instrument provider onboarding and account disconnect owners.** Gmail/iCloud/Yahoo/IMAP normal consumer variants; Outlook internal only.
- [ ] **Step 4: Instrument scan UI stream/result/history/stop/resume boundaries** while preserving scan-monitor as sole EventSource owner.
- [ ] **Step 5: Instrument message actions/unsubscribe/analyze-links/protection-learning/undo boundaries.**
- [ ] **Step 6: Instrument background/settings/policy/activity/health/operations boundaries.**
- [ ] **Step 7: Instrument Scam Check, Shopping Safety, Media Authenticity, Family/Guardian, account lifecycle, billing boundaries.**
- [ ] **Step 8: Regenerate manifest, run browser/unit/check:web tests, commit.**

---

### Task 5: Instrument authoritative server/domain/background checkpoints

**Files:**
- Modify existing authoritative route/service/worker owners discovered in current tree; do not introduce duplicate state machines.
- Test: representative unit/integration tests plus failure injection.

**Interfaces:**
- Server checkpoint emissions receive trace ID propagated from protected request header/query or create an automatic background root using a new opaque UUID.
- Domain code never receives browser-visible account/mail identities as trace metadata.

- [ ] **Step 1: RED integration test provider connection.** Expect request validation → provider/auth attempt → durable connection persistence → response checkpoint; inject provider/persistence failure and verify exact failing boundary.
- [ ] **Step 2: RED scan integration.** Expect provider enumeration/read → batch policy → normalization/security inspection → portable-core → policy/community/family evaluation → checkpoint persistence → SSE/UI completion. Preserve provider-specific batch evidence.
- [ ] **Step 3: RED message-mutation integration.** Report/Block/Trash/Spam/Safe/Trust/Unsubscribe/Analyze Links must distinguish local persistence, provider mutation, community/family side effects and response.
- [ ] **Step 4: RED automatic-background test.** Scheduler/realtime run creates a trace root without user click and records start/read/evaluate/mutate/checkpoint/finalize/retry/cancel boundaries.
- [ ] **Step 5: RED Scam Check, Family, policy/settings and account lifecycle representative tests.**
- [ ] **Step 6: Add strategic `recordRuntimeCheckpoint` calls to real existing owners only.** Do not log every helper entry/exit.
- [ ] **Step 7: Add startup/vault/repository/session restore automatic checkpoints** with fixed failure codes only; raw native/storage exceptions remain excluded.
- [ ] **Step 8: Regenerate manifest; run focused integration + unit + typecheck/build; commit.**

---

### Task 6: Protected diagnosis API and optional PostHog v2 mirror

**Files:**
- Modify: `server/src/api/runtimeWorkflowTraceRoutes.ts`
- Modify: `server/src/telemetry/technicalTelemetry.ts`
- Modify: `docs/technical-telemetry.md`
- Test: `tests/unit/runtimeWorkflowTraceApi.test.ts`
- Test: `tests/unit/runtimeWorkflowTraceTelemetry.test.ts`

**Interfaces:**
- Dev-only protected reads:
  - `GET /api/dev/runtime-trace/current`
  - `GET /api/dev/runtime-trace/manifest`
  - `GET /api/dev/runtime-trace/diagnosis?traceId=<uuid>`
- Responses contain only sanitized IDs/status/source location/build metadata.

- [ ] **Step 1: RED API tests.** Require loopback + session + CSRF + same-origin; reject disabled runtime; diagnosis never exposes raw content/error/url/account identity.
- [ ] **Step 2: Implement manifest/diagnosis endpoints** using current-run records only.
- [ ] **Step 3: RED PostHog tests.** New workflow/checkpoint/build/location fields accepted only after independent validation; unknown/sensitive fields prevent capture.
- [ ] **Step 4: Implement remote v2 mirror** without enabling telemetry automatically and without browser autocapture/session replay/profile identity.
- [ ] **Step 5: Run focused tests/typecheck; update telemetry doc; commit.**

---

### Task 7: Permanent coverage gate, controlled acceptance, and full qualification

**Files:**
- Create/modify: `scripts/engineering/check-runtime-trace-coverage.mjs`
- Modify: `package.json`
- Create/modify representative fixture/browser smoke for flight recorder acceptance.
- Modify final engineering handoff/acceptance documentation.

**Interfaces:**
- `npm run check:trace-coverage` generates/checks manifest and verifies action/workflow/route/checkpoint/terminal invariants.
- `npm run check:web` includes trace coverage or gate runs it as an explicit immutable step.

- [ ] **Step 1: Add RED gate tests** proving a synthetic unregistered button, missing route mask, duplicate checkpoint, missing terminal and stale manifest all fail.
- [ ] **Step 2: Add controlled fixture/browser flight-recorder smoke** proving:
  1. click → visible completion;
  2. background workflow without click;
  3. injected backend failure → exact failing source owner;
  4. suppressed UI confirmation → first missing UI checkpoint;
  5. Gmail/iCloud provider-specific scan/batch evidence remains correct;
  6. prohibited content cannot enter local/remote records.
- [ ] **Step 3: Wire permanent gate command** into the engineering gate before packaging/release qualification.
- [ ] **Step 4: Run focused local verification.**

```bash
npm run check:trace-coverage
npm run check:web
npm run typecheck
npm run build
npm run test:unit -w server
npm run test:integration -w server
```

- [ ] **Step 5: Freeze exact branch head and run the repository Engineering Gate on GitHub Actions.** Do not merge a different SHA from the green SHA.
- [ ] **Step 6: Review exact diff for privacy/ownership regressions.** Confirm no scan/provider/action second owner, no telemetry auto-enable, no sensitive-field expansion, Outlook still hidden.
- [ ] **Step 7: Merge only qualified exact head to `main` and require independent push-triggered Windows/macOS/Ubuntu gate on the merged SHA.**
- [ ] **Step 8: Update final owner handoff with exact merged SHA and simple Windows commands:**

```cmd
git checkout main
git pull origin main
npm ci
npm run dev
```

Final live feature testing begins only after the post-merge gate is green.

---

## Plan self-review

- **Spec coverage:** every design section is owned by Tasks 1–7, including schema v2, manifest, graph diagnosis, browser inventory, automatic roots, server checkpoints, protected API, PostHog, failure injection and exact-head/post-merge gates.
- **Privacy boundary:** no task permits raw message/account/credential/URL/error data; unknown fields remain fail-closed.
- **Ownership boundary:** instrumentation emits evidence only; existing UI/service/worker owners remain authoritative.
- **Type consistency:** `workflowId`, `actionId`, `checkpointId`, `buildId`, `recordRuntimeCheckpoint`, browser `.checkpoint`, and `WORKFLOW_REGISTRY` are stable across tasks.
- **No placeholders:** implementation owners that must be discovered from the current tree are constrained to existing authoritative files/services; no unspecified new product state or behavior is introduced.
