# Email Shield — Protection Lifecycle / Security P0 Closure

Date: 2026-08-17
Program: EMA-33
PR: #105
Base main: `d94bd7de31dafe8af7eb040525f0849b5bbf5135`
Issues: EMA-18 / EMA-23
Supplemental IDs: REG-092 / A-74 / MAN-023

## REG-092 locked behavior

### Background Protection schedule

- A newly enabled Background Protection schedule first becomes due after the selected 30–1440 minute interval, never after a hard-coded one minute.
- Failure backoff, disconnect deferral, scan-conflict deferral, protected persistence and single global background concurrency remain unchanged.
- Manual Quick, Full Mailbox Audit and Spam/Junk scans keep their existing execution semantics.

### Realtime polling fallback

- A timer tick by itself is never evidence of mailbox change and never fabricates a Quick scan or Activity record.
- Polling fallback remains active through a provider-neutral metadata checkpoint probe; the fix does **not** disable fallback protection or merely lengthen the timer.
- The first trusted checkpoint establishes a protected local baseline without scanning.
- An unchanged checkpoint performs no scan.
- A changed checkpoint creates exactly one replay-safe `poll` mailbox-change event and enters the existing shared bounded Quick-scan processor.
- Poll event identity is derived from the **previous checkpoint → new checkpoint transition**. A failed transition retries with the same event identity, while a later legitimate recurrence of an older checkpoint after an intervening success is treated as a new transition rather than an old duplicate.
- A failed processor result never advances the checkpoint.
- A failed protected-state acknowledgement save never publishes the replay key or checkpoint in memory; the identical event remains retryable.
- Poll baselines and successful changed checkpoints survive process restart through the existing encrypted inbound-event repository.
- One provider probe failure does not starve another connected account; metadata probes run independently while actual protection work still enters the shared serialized protection path.
- Overlapping polling ticks are coalesced while a probe cycle is already active.
- Genuine normalized push/IDLE events continue through the same replay-safe inbound coordinator and shared protection processor.

### Provider heartbeat privacy / transport boundary

- `EmailAdapter.mailboxCheckpoint()` is an optional metadata-only capability composed through the existing shared adapter factory. The polling path never calls `fetchPage`, message normalization, body-part acquisition or the scan worker to decide whether a mailbox changed.
- Gmail derives its heartbeat from profile/history metadata and returns only a SHA-256 digest of the history checkpoint.
- Outlook derives its heartbeat from Inbox/Junk folder counts plus latest immutable message metadata and returns only a SHA-256 digest. The heartbeat path never requests raw `/$value` message content.
- iCloud, Yahoo and generic IMAP derive their heartbeat from selected Inbox/Junk mailbox metadata (`uidValidity`, `uidNext`, `exists`) and return only a SHA-256 digest. The heartbeat path never performs IMAP message search/fetch/body acquisition.
- Raw message bodies, subjects, sender addresses, URLs, credentials and raw provider message IDs do not become durable polling checkpoints.
- The short-lived probe connection uses the same secure adapter configuration and native credential vault boundary as existing provider operations and is always disconnected in `finally`.

### Development entitlement isolation

- `EMAIL_SHIELD_ENABLE_DEVELOPMENT_ENTITLEMENTS` is launcher capability, not ordinary `.env.local` configuration.
- Normal `npm run dev` strips a stale value after local environment loading.
- The dedicated fixture/engineering launcher can explicitly reassert the capability.
- A real TypeScript declaration (`scripts/development-entitlement-boundary.d.mts`) keeps this JavaScript launcher boundary inside strict type checking; no `ts-ignore` or equivalent bypass is used.
- Backend entitlement authorization remains authoritative; packaged/start/release paths do not gain a development entitlement bypass.

## A-74 automated evidence

- `tests/unit/backgroundProtectionCoordinator.test.ts` locks configured first-run timing, conflicts, failures and removal semantics.
- `scripts/engineering/smoke-background-protection.mjs` proves a genuinely due compiled background scan.
- `tests/unit/realtimeProtectionService.test.ts` locks baseline/unchanged silence, changed-checkpoint execution, restart persistence, exact retry identity, recurring-checkpoint transition identity, provider-failure isolation, overlapping-poll coalescing, startup silence and genuine push/IDLE replay safety.
- `tests/unit/realtimeMailboxCheckpointArchitecture.test.ts` locks metadata-only Gmail/Outlook/IMAP heartbeat ownership and the shared adapter-factory probe path while forbidding normal page/body fetch ownership.
- `tests/unit/inboundProtectionCoordinator.test.ts` locks processor-failure retry and protected-state-save atomicity so an acknowledgement is not published in memory before durable persistence succeeds.
- `tests/unit/providerInboundSources.test.ts` retains strict normalized push/IDLE source coverage.
- `tests/unit/developmentEntitlementLaunch.test.ts` locks normal-source stripping and dedicated-fixture authority.
- Existing account-platform API tests and compiled server smoke retain backend 403/development isolation coverage.
- The five-provider integration corpus remained 140/140 malicious caught and 140/140 legitimate Safe throughout the RED/GREEN sequence.

## TDD evidence

### EMA-18 scheduler

- RED `81c215a4c7f0a48be3779818e230fba231481376` / Gate #1184 proved a 60-minute schedule was incorrectly first queued at +60 seconds.
- Production owner fix `00fdb46507e05ab688427116f00bc11f98d94008` routes first-enable timing through the configured interval. Stale test/smoke clocks were corrected without weakening production timing.

### EMA-18 metadata polling fallback

- Strong realtime/provider RED `00d5be83f8157c59a80cb4471b4f78729b8686b9` / Gate #1198 proved the five required realtime behaviors were absent and Gmail/Outlook/IMAP had no metadata heartbeat capability/shared probe. Existing unrelated tests and corpus remained healthy.
- Initial metadata-fallback GREEN `5283d9cb5ac04c23783484d2e858c6bca6d5f8e5` / Gate #1199 passed Windows, macOS, Ubuntu with real Linux Secret Service, and Gate Result Summary.

### Replay identity recurrence

- RED `0f5d050110100db836694130690a0b530f52ea27` / Gate #1200 proved `A → B → C → B` incorrectly dropped the second transition to B as an old duplicate; one intended test failed while 1,150 tests passed.
- GREEN `8d7f81e1097ca81a2cc4f809ccedf6e582f36036` / Gate #1201 keys replay identity by previous→new checkpoint transition and passed Windows, macOS, Ubuntu with real Linux Secret Service, and Gate Result Summary.

### Durable acknowledgement atomicity

- RED `2f8b43f4f38b594c2a45a4ea53ce0e5de0a47a8c` / Gate #1202 proved an encrypted-state `save()` failure left the live coordinator checkpoint at `"42"` even though durable state remained empty; exactly one intended test failed while 1,151 tests passed.
- GREEN `5862f0a8d76a59268fece8c6432501f388b6312a` / Gate #1203 persists a cloned next snapshot before swapping any live replay/checkpoint state and passed Windows, macOS, Ubuntu with real Linux Secret Service, and Gate Result Summary.

### EMA-23 development entitlement isolation

- Development entitlement RED began at `3d151f04ed360c17f87965129f56615372e1836e`.
- Launcher isolation was implemented through the dedicated boundary/fixture launcher sequence ending before the realtime closure work; strict TypeScript initially exposed the missing `.mjs` declaration during RED verification.
- The declaration and final integrated launcher behavior are included in `5283d9cb5ac04c23783484d2e858c6bca6d5f8e5` and are covered by the all-platform Gate #1199 and subsequent all-platform GREEN gates.

## Security / privacy review

No detection threshold changed. No provider-specific detector or score path was added. No mailbox content is fetched to decide whether polling fallback should scan. No raw mailbox content enters replay/checkpoint persistence. No Family/paid entitlement bypass was introduced. No `.env.local` value can silently enable development entitlement during normal source launch. Existing credential-vault, encrypted local-state, loopback/origin/CSRF, shared scan-worker and provider-normalizer boundaries remain in force.

## MAN-023 final owner acceptance

Owner acceptance remains deliberately separate from CI and is deferred to the final consolidated live test after integration:

1. Configure Background Protection for 30 minutes and confirm the displayed first due time is approximately 30 minutes away, not one minute.
2. Leave a connected mailbox unchanged across multiple realtime polling ticks and confirm no synthetic ~2-minute Quick-scan Activity appears.
3. Cause a controlled real mailbox change on a provider available in the acceptance environment and confirm bounded protection occurs without requiring a fabricated clock-trigger scan.
4. Restart Email Shield with the mailbox unchanged and confirm the persisted baseline prevents a startup scan; then make a later controlled change and confirm protection still runs.
5. Confirm manually started Quick/Full/Spam scans remain normal.
6. Confirm normal source mode has no development-plan preview/entitlement mutation control even if an old local flag existed.
7. Confirm the dedicated fixture launcher exposes engineering-only controls only in that explicit mode.
8. Confirm packaged consumer launch remains free of development entitlement controls.

Real Outlook mailbox acceptance remains postponed to the final consolidated provider test. Family acceptance still requires a legitimate entitlement. This closure record does not claim either live acceptance before the owner performs it.
