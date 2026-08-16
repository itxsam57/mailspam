# Runtime Workflow Tracing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Record privacy-safe, correlated browser-to-backend workflow traces during source/live testing so a failed action can be diagnosed without guessing which provider, button, route, worker path, or workflow the tester used.

**Architecture:** A local bounded JSONL recorder is the source of truth and starts automatically in `npm run dev`/fixture developer mode. A browser semantic-action recorder correlates allowlisted controls to same-origin API calls with opaque trace IDs; the server records safe route/response metadata and scan workers record provider-safe execution checkpoints. Existing PostHog technical telemetry remains opt-in and receives only an allowlisted sanitized diagnostic mirror when explicitly enabled.

**Tech Stack:** TypeScript/Node.js, Express, browser JavaScript, existing PostHog transport, Vitest, GitHub Engineering Gate.

## Global Constraints

- Never record email body, subject, sender/recipient/mailbox identity, account ID, provider-native/message ID, raw URL, attachment filename/content, credentials, OAuth/app-password values, personal-policy values, raw exception text, or stack traces.
- No browser autocapture, session replay, DOM text capture, or arbitrary request-body capture.
- Trace IDs are opaque UUIDs; trace metadata uses fixed allowlists and bounded enum/string values.
- Local trace files rotate and are bounded; tracing must never block or change protection behavior.
- Remote PostHog mirror remains disabled unless existing telemetry opt-in and token configuration are present.
- Outlook remains postponed/hidden from consumer acceptance work.

---

### Task 1: Local trace recorder and privacy contract

**Files:**
- Create: `server/src/diagnostics/runtimeWorkflowTrace.ts`
- Test: `tests/unit/runtimeWorkflowTrace.test.ts`

**Interfaces:**
- Produces `createRuntimeWorkflowTraceRecorder(options)` with `record(event)`, `readCurrent(limit)`, `runId`, and `enabled`.
- Event schema contains only run/trace IDs, timestamp, stage, action/workflow/provider/scan type/component/step/outcome, safe route template, HTTP status, duration and bounded counters/error codes.

- [ ] Write failing tests for allowlist rejection, sensitive-key rejection, bounded rotation, fail-soft writes, and stable run/trace IDs.
- [ ] Run targeted test and confirm RED.
- [ ] Implement recorder with JSONL rotation under the managed data directory.
- [ ] Run targeted test and confirm GREEN.

### Task 2: Developer trace API and startup wiring

**Files:**
- Modify: `scripts/dev.mjs`
- Modify: `scripts/dev-fixtures.mjs`
- Modify: `server/src/index.ts`
- Modify: `server/src/api/consumerDesktopServer.ts`
- Create: `server/src/api/runtimeWorkflowTraceRoutes.ts`
- Test: `tests/unit/runtimeWorkflowTraceApi.test.ts`

**Interfaces:**
- `npm run dev` and fixture developer mode set `EMAIL_SHIELD_RUNTIME_TRACE=1` unless explicitly disabled.
- Engineering-only endpoints accept sanitized browser events and expose current sanitized trace; endpoints are loopback/protected and unavailable in normal packaged runtime.

- [ ] Write failing route/startup tests.
- [ ] Run targeted tests and confirm RED.
- [ ] Wire recorder and protected developer routes.
- [ ] Run targeted tests and confirm GREEN.

### Task 3: Browser semantic action and API correlation

**Files:**
- Create: `web/runtime-workflow-trace.js`
- Modify: `web/index.html`
- Test: `tests/unit/runtimeWorkflowTraceBrowser.test.ts`

**Interfaces:**
- Explicit registry maps stable control IDs/data-actions to `actionId` and `expectedWorkflow`.
- Known control clicks create a trace ID; same-origin `/api/` fetches receive `X-Email-Shield-Trace-Id`; EventSource scan URLs receive an opaque `trace_id` query value.
- No DOM text, form values, request bodies, account IDs, or raw URLs are sent to the recorder.

- [ ] Write failing source-contract tests for semantic controls and forbidden capture.
- [ ] Run targeted tests and confirm RED.
- [ ] Add browser recorder/correlation layer and load it before feature modules.
- [ ] Run targeted tests and confirm GREEN.

### Task 4: Server/API and scan Worker checkpoints

**Files:**
- Modify: `server/src/api/server.ts`
- Modify: `server/src/workers/scanWorker.ts`
- Modify: scan worker launcher/composition file(s) that construct worker data.
- Test: `tests/unit/runtimeWorkflowScanTrace.test.ts`

**Interfaces:**
- Valid trace IDs propagate into scan worker data.
- Scan trace records safe checkpoints including route accepted, worker started, resolved provider family/page size, provider connect/list/fetch/evaluate/persist progression, completion/failure classification.
- Error fields are fixed classifications only.

- [ ] Write failing correlation/checkpoint tests.
- [ ] Run targeted tests and confirm RED.
- [ ] Add propagation and safe checkpoints without changing scan behavior.
- [ ] Run targeted tests and confirm GREEN.

### Task 5: Optional PostHog diagnostic mirror and operator visibility

**Files:**
- Modify: `server/src/telemetry/technicalTelemetry.ts`
- Modify: `tests/unit/technicalTelemetry.test.ts`
- Modify: `docs/technical-telemetry.md`
- Add/modify diagnostics UI only in engineering mode if needed.

**Interfaces:**
- Only a narrow allowlist of workflow-trace event fields can be mirrored remotely.
- Local JSONL remains authoritative if PostHog is absent/unreachable.

- [ ] Write failing tests proving remote mirror rejects sensitive/unknown fields and stays opt-in.
- [ ] Run targeted tests and confirm RED.
- [ ] Implement mirror and engineering visibility.
- [ ] Run targeted tests and confirm GREEN.

### Task 6: Whole-repo verification and integration

- [ ] Run focused privacy + workflow trace tests.
- [ ] Run complete Engineering Gate on immutable PR head across Windows/macOS/Ubuntu Secret Service.
- [ ] Review final diff against every Global Constraint and remove any accidental sensitive capture.
- [ ] Merge only the exact tested SHA.
- [ ] Run an independent post-merge Engineering Gate on `main` and require final Gate Result Summary success.
