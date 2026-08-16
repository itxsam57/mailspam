# Full-Product Diagnostic Flight Recorder Design

Date: 2026-08-16
Base main: `af48ed7d2b70b9233aba9595d08aa337cc6b7fbf`
Status: approved product direction; implementation must remain behind the existing source/dev diagnostic boundary.

## 1. Purpose

Email Shield needs final live acceptance to produce enough privacy-safe evidence to diagnose failures without guessing which provider, feature, UI owner, backend owner, or workflow transition was exercised.

The existing runtime workflow trace is retained as the authoritative local sink, but it is too scan-centric. This design expands it into a whole-product diagnostic flight recorder that covers consumer UI actions, protected API calls, domain/service transitions, background work, provider/vault/storage/community/family boundaries, persistence, and visible UI completion.

The recorder exists to answer, for every tested feature:

1. What user or automatic action started the workflow?
2. What was expected to happen?
3. Which provider/account-independent workflow variant was selected?
4. Which meaningful internal checkpoints completed?
5. Which checkpoint was the last confirmed good step?
6. Which required next checkpoint failed or never appeared?
7. Which source file/function/line in the exact tested commit owns each checkpoint?
8. Did the workflow finish successfully, partially, fail, cancel, reject, or become incomplete?
9. Did the backend succeed while the UI failed to render/confirm the result?

## 2. Non-negotiable constraints

- No raw email body, HTML, subject, sender, recipient, mailbox address, account ID, provider-native message ID, attachment body/name, contact list, credentials, OAuth tokens, app passwords, recovery codes, form values, request bodies, raw URLs/query strings, raw exception messages, or stack traces may be recorded.
- Trace failures are fail-soft and must never alter protection behavior.
- Existing mailbox/provider mutation authorization, CSRF, nonce, session, loopback, vault, policy, community, Family, and detection rules are unchanged.
- Normal packaged consumer telemetry behavior remains unchanged. Local source/dev tracing continues to start automatically only under the existing `EMAIL_SHIELD_RUNTIME_TRACE=1` development path.
- PostHog remains separately opt-in. The local recorder is authoritative; remote telemetry may mirror only independently validated sanitized fields.
- Outlook/Microsoft remains implemented internally but hidden/postponed from normal consumer acceptance until controlled live testing is possible.
- The feature must not introduce a second owner for scan SSE, account selection, provider onboarding, navigation, message actions, or any existing workflow.

## 3. Chosen architecture

Three approaches were considered:

1. **More button logging.** Low effort, but still leaves backend failures and successful-API/failed-render cases ambiguous.
2. **Hand-log every function.** High apparent detail but creates noise, maintenance drift, privacy risk, and instrumentation-driven bugs.
3. **Structured flight recorder with stable workflow checkpoints and generated source ownership.** Chosen.

The chosen architecture has five layers:

### 3.1 Semantic action capture

The existing `web/runtime-workflow-trace.js` remains the first browser module. It captures trusted human interactions and creates one opaque trace root.

Coverage expands from the current static control map to all actionable UI contracts used by the product, including static IDs, delegated `data-*` controls, provider cards, route controls, settings controls, dynamically generated message actions, lifecycle confirmations, policy actions, Family/Guardian actions, billing/account controls, Scam Check modes, Shopping Safety, Media Authenticity, and onboarding actions.

Unknown actionable controls remain traceable as `ui.unregistered_action`, but CI must fail if a rendered consumer action remains unregistered in the final implementation.

### 3.2 Protected request correlation

The existing protected fetch/EventSource correlation remains authoritative. Every trace-aware protected API request records masked route template, method, bounded duration and status without request bodies or dynamic identifiers.

The route masker becomes exhaustive for all consumer API families. Any API not explicitly classified is recorded only as `/api/other`, and CI must prove no supported consumer workflow depends on `/api/other` for its expected path.

### 3.3 Stable workflow checkpoints

Meaningful internal transitions use a shared checkpoint helper rather than free-form logging.

Example checkpoint IDs:

- `family.create.request_validated`
- `family.create.entitlement_verified`
- `family.create.state_persisted`
- `family.create.response_returned`
- `family.create.ui_confirmed`
- `message.report.local_rule_persisted`
- `message.report.provider_trash_requested`
- `message.report.community_evidence_submitted`
- `background.run.account_loaded`
- `background.run.provider_page_read`
- `background.run.policy_applied`
- `background.run.checkpoint_persisted`

Checkpoint IDs are stable product contracts. They identify meaningful state transitions, not every function entry/exit.

Each checkpoint event carries only strict allowlisted metadata such as trace ID, workflow ID, checkpoint ID, stage, component, outcome, provider enum where safe, scan type, masked route template, fixed error code, bounded counters/retries/duration, and build identity.

### 3.4 Generated source ownership manifest

Every checkpoint declaration is statically discoverable. A build/test generator produces a manifest for the exact commit containing:

- checkpoint ID
- workflow ID
- component ID
- source path relative to repository root
- function/owner label
- 1-based source line
- exact Git commit SHA/build identity

The manifest is generated, never handwritten. CI fails on duplicate checkpoint IDs, unresolved checkpoint declarations, missing source ownership, stale manifest output, or workflow references to nonexistent checkpoints.

Line numbers are therefore tied to the exact tested commit. When code moves, regeneration changes the manifest automatically.

The recorder does not claim that every logical defect is literally on the checkpoint line. Instead, the diagnostic report identifies the exact checkpoint boundary and owning function/source location. Same-repository exceptions may additionally record a sanitized mapped error-location ID derived from an allowlisted same-origin/same-repo frame; raw stack/error text is never stored.

### 3.5 Workflow expectation graph and diagnosis

A workflow registry defines required checkpoints and allowed branches for each supported workflow.

It supports:

- ordered required steps
- optional steps
- provider-specific variants
- success/partial/rejected/cancelled branches
- background roots with no user click
- expected UI confirmation after successful backend mutation

A diagnostic analyzer consumes the local trace plus the exact checkpoint manifest and reports:

- action/workflow tested
- provider/scan variant when applicable
- terminal outcome
- last successful checkpoint
- first failed checkpoint, or first required missing checkpoint
- backend-success/UI-incomplete mismatches
- retry/timing/status summary
- owning file/function/line/commit for the last-good and suspected-next boundary
- fixed sanitized failure code

The analyzer must not infer success from HTTP 2xx alone.

## 4. Trace schema v2

The current v1 record is extended in a backward-readable way. New fields are allowlisted and bounded.

Required concepts:

- `schemaVersion: 2`
- `runId`
- `traceId`
- `workflowId`
- `actionId`
- `stage`
- `checkpointId` when a checkpoint is emitted
- `outcome`
- `buildId` / exact commit identity

Optional safe fields include:

- provider enum
- scan type
- component ID
- step ID
- masked route template
- HTTP method/status
- bounded duration
- page size/max messages/item count/retry count
- fixed error code
- sanitized error-location ID
- parent trace ID for automatic sub-workflows when required

Unknown fields are rejected before local persistence and again before optional remote mirroring.

## 5. Workflow coverage required before final live testing

The flight recorder is not complete until every current normal-consumer feature belongs to a registered workflow family.

### 5.1 App/startup/state

- application start
- protected-state initialization
- native vault initialization/use
- encrypted repository initialization/read/migration failure
- stored mailbox restoration
- workspace restoration
- account selection/reconciliation
- route navigation/mounting

### 5.2 Provider onboarding

- Gmail OAuth readiness/start/callback/status/persistence/restore
- iCloud credential connect/persistence/restore
- Yahoo credential connect/persistence/restore
- generic TLS IMAP connect/persistence/restore
- account disconnect
- Outlook internal workflow remains traceable for future controlled testing but absent from normal consumer onboarding

### 5.3 Scanning

- Quick Scan
- Full Mailbox Audit
- Spam/Junk Scan
- Stop
- Resume
- scan history/checkpoint restoration
- provider enumeration/read
- bounded batch policy
- normalization/security inspection
- portable-core analysis
- policy/community/family evaluation
- result counters
- persistence
- SSE delivery
- consumer result rendering

### 5.4 Message safety/actions

- Block Sender
- Block Domain
- Trash
- Report Scam
- Move to Spam/Junk
- Mark Safe
- Trust Sender
- Unsubscribe/manual handoff/verified one-click completion
- Analyze Links
- protection-learning confirmation event
- provider mutation/undo where supported

### 5.5 Continuous protection

- Background Protection toggle/configuration
- scheduler tick
- realtime trigger normalization
- polling fallback
- worker start/read/evaluate/mutate/checkpoint/finalize
- retry/backoff/cancellation
- startup restoration of protection state

### 5.6 Personal protection/settings

- sensitivity profile changes
- personal policy read/import/export/reset/clear/revoke/bulk-revoke
- settings persistence
- activity/history/health/cleanup/undo views and actions
- notification preferences where present

### 5.7 Check Anything / consumer analysis

- text
- link
- `.eml`
- image/QR
- local OCR bridge when enabled
- explanation generation/projection
- safe action projection

### 5.8 Family / Guardian

- Family Shield create/invite/join/remove/leave/delete
- strict-mode/state changes
- guardian preferences
- private family campaign sharing
- family warning/quarantine and confirmed-trash decision path
- device/account authorization boundaries used by Family operations

### 5.9 Community / operations

- community feed refresh/verification/application
- report evidence submission
- warning/confirmed/legitimacy evidence path
- privacy-safe operations dashboard refresh
- campaign radar/operations controls that are consumer-visible

### 5.10 Account / subscription / lifecycle

- profile/account load
- plan display
- purchase/subscription verification boundary
- recovery-code rotation
- device revocation
- sign out everywhere
- metadata export
- Family deletion prerequisite
- Email Shield account deletion
- billing UI state transitions

### 5.11 Additional consumer modules

- Shopping Safety
- Media Authenticity capability checks/actions
- onboarding/first-run steps
- support/diagnostic export where exposed

## 6. Browser coverage enforcement

The existing UI workflow audit is extended so final CI inventories all actionable consumer controls, not only static `<button id=...>` elements.

It must understand the repository's actionable contracts such as:

- static button IDs
- `data-route-target`
- `data-mobile-route`
- `data-scam-check-mode`
- `data-consumer-sensitivity`
- `data-action`
- `data-select`
- provider cards
- dynamically generated buttons created by known feature modules

Every supported action must resolve to a registered `actionId` + `workflowId`.

CI fails for:

- rendered action with no workflow registration
- workflow registration with no reachable action or automatic root
- consumer API family used by a workflow but missing route masking
- workflow with no terminal observable completion path

## 7. Background/automatic trace roots

Automatic work cannot depend on the ten-second browser click window.

The recorder creates new trace roots for:

- application startup phases
- mailbox restoration
- scheduled background scans
- realtime protection runs
- community refresh
- automatic retry/recovery loops
- other recurring protection jobs

A background root records a fixed action such as `system.background_tick` and the registered workflow. No user/account identity is included.

## 8. Error handling and missing-step detection

Errors are classified to fixed codes at the owner boundary. Raw exception text is never persisted.

The analyzer distinguishes:

- explicit failure checkpoint
- rejection by policy/security/input validation
- provider failure
- vault/storage failure
- partial/incomplete inspection
- cancellation
- timeout/inactivity
- missing expected next checkpoint
- successful backend mutation with missing UI confirmation
- stale-response suppression due to account-selection generation change

A workflow that begins but produces neither an allowed terminal state nor the required next checkpoint is diagnosable as incomplete rather than silently disappearing.

## 9. Local diagnostic API/report

The existing protected dev trace API is extended rather than replaced.

Required dev-only reads:

- current records
- current checkpoint/build manifest identity
- workflow diagnosis summary

The diagnosis endpoint returns only sanitized IDs/status/location metadata and is protected by the same loopback/session/CSRF/same-origin requirements.

No endpoint may expose mailbox content, raw request data, raw stack traces, credentials, account identifiers, or dynamic URLs.

## 10. Optional PostHog mirror

The existing `email_shield_workflow_trace` event remains opt-in.

The remote mirror may carry the new sanitized workflow/checkpoint/build/location identifiers only after independent server-side validation. It must continue to omit identity/content/raw URLs/raw errors and keep GeoIP/profile/session replay/autocapture disabled.

Remote telemetry is diagnostic convenience, not acceptance authority.

## 11. Testing strategy

Implementation follows TDD.

### 11.1 Contract tests

- schema v2 accepts only allowlisted fields and rejects unknown/sensitive fields
- v1 remains readable where required for local migration/diagnosis
- generated checkpoint manifest is deterministic for an exact source tree
- duplicate/missing/stale checkpoint ownership fails CI
- route masking covers every registered consumer API family
- sensitive payloads never reach recorder/PostHog

### 11.2 Workflow graph tests

For every registered workflow family:

- happy path identifies all required checkpoints and terminal success
- missing checkpoint identifies last-good + first-missing owner
- explicit failure identifies exact failing checkpoint
- optional/provider branch does not create false missing-step alerts
- backend success with absent UI completion is reported as incomplete

### 11.3 Browser tests

- all actionable controls are registered
- dynamic message/action buttons are covered
- trusted clicks create one trace root
- synthetic clicks cannot overwrite human/provider context
- account selection changes do not cross-contaminate traces
- long-running SSE retains correlation

### 11.4 Server/integration tests

Representative end-to-end flows must prove checkpoint propagation through:

- provider connection
- scan
- message mutation
- background protection
- Scam Check
- Family operation
- account lifecycle operation
- policy/settings operation

### 11.5 Failure injection

Tests deliberately fail selected checkpoints to prove diagnosis points to the correct owning boundary without recording raw exception text.

### 11.6 Full engineering gate

Exact frozen PR head must pass Windows, macOS, Ubuntu/Linux Secret Service, full unit/integration/corpus/browser/server/package/release gates, and the strengthened trace-coverage audit. After merge, exact merged `main` must pass an independent push-triggered three-OS gate before owner final live testing.

## 12. Migration and rollout

- Keep existing file path `diagnostics/runtime-workflow-trace.jsonl` and bounded rotation.
- Upgrade writer to schema v2 while allowing the diagnostic reader to ignore/understand existing v1 records safely.
- Do not migrate old trace files into product state.
- Do not enable remote telemetry automatically.
- Final owner testing starts only from the qualified merged `main` after this recorder is accepted.

## 13. Final acceptance criterion for the recorder

Before Email Shield final feature testing begins, a controlled fixture/browser acceptance must demonstrate all of the following:

1. A UI-started workflow can be traced from click to visible completion.
2. A background workflow can be traced without a click.
3. A deliberately injected backend failure reports the exact failing checkpoint and generated source owner.
4. A deliberately suppressed UI confirmation after backend success reports the first missing UI checkpoint.
5. Provider-specific scan evidence still identifies provider and bounded batch behavior.
6. CI proves every current consumer action/workflow is registered.
7. Privacy tests prove prohibited content/identity/credentials/raw URLs/raw errors cannot enter local or remote trace records.
8. Exact-head and post-merge engineering gates are green.

Only after those eight conditions are satisfied is the recorder considered strong enough to support final live product acceptance.