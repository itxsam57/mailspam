# Email Shield — Protection Lifecycle / Security P0 Closure

Date: 2026-08-17
Program: EMA-33
PR: #105
Base main: `d94bd7de31dafe8af7eb040525f0849b5bbf5135`
Supplemental IDs: REG-092 / A-74 / MAN-023

## REG-092 locked behavior

- A newly enabled Background Protection schedule first becomes due after the selected 30–1440 minute interval, never after a hard-coded one minute.
- Failure backoff, disconnect deferral, scan-conflict deferral, protected persistence and single global background concurrency remain unchanged.
- The realtime timer is housekeeping only. A clock tick is not evidence of mailbox change and must never fabricate a Quick scan or Activity record.
- Genuine normalized push/IDLE events continue through the replay-safe inbound coordinator and shared protection processor.
- Provider source normalizers exist for Gmail Pub/Sub, Microsoft Graph and IMAP exists signals, but this closure does not claim external push/IDLE runtime infrastructure that is not actually wired and owner-tested. Scheduled Background Protection remains the provider-neutral fallback.
- `EMAIL_SHIELD_ENABLE_DEVELOPMENT_ENTITLEMENTS` is launcher capability, not `.env.local` configuration. Normal `npm run dev` strips a stale value after local env loading; dedicated `dev:fixtures` reasserts it from an argv-only launcher signal.
- Backend entitlement authorization remains authoritative; packaged/start/release paths do not gain a development entitlement bypass.

## A-74 automated evidence

- `tests/unit/backgroundProtectionCoordinator.test.ts` locks configured first-run timing, conflicts, failures and removal semantics.
- `scripts/engineering/smoke-background-protection.mjs` proves a genuinely due compiled background scan.
- `tests/unit/realtimeProtectionService.test.ts` locks zero processor calls for idle/startup housekeeping and replay-safe processing for genuine events.
- `tests/unit/providerInboundSources.test.ts` retains strict metadata-only provider normalizer coverage.
- `tests/unit/developmentEntitlementLaunch.test.ts` locks normal-source stripping and dedicated-fixture authority.
- Existing `tests/unit/accountPlatformApi.test.ts` and compiled server smoke retain backend 403/development isolation coverage.

## TDD evidence

Scheduler RED: `81c215a4c7f0a48be3779818e230fba231481376` (Gate #1184), proving +60 seconds was returned where +60 minutes was configured. Product fix: `00fdb46507e05ab688427116f00bc11f98d94008`; stale due-test/smoke clocks were corrected without additional product behavior at `6e467b68f3ea7270cf16a4f4d841bd4265dcfca1`.

Realtime RED: `98c43ae925b5102af271b6426cf5d7b315d732e0`, replacing old tests that required fabricated poll scans with zero-scan idle/startup behavior plus genuine-event replay safety. Product fix: `29bc149fe53e61ff7cc8d2e34188bbb0212b7e5e`.

Development entitlement RED: `3d151f04ed360c17f87965129f56615372e1836e`; launcher boundary implementation/wiring ends at `b059da875dea946bc540e73e47fb527c6a41fcfd` before this closure record.

## Security / privacy review

No detection threshold changed. No provider-specific detector was added. No mailbox content is used by the housekeeping timer. No polling event is fabricated. No Family/paid entitlement bypass was introduced. No `.env.local` value can silently enable development entitlement during normal source launch. Existing protected state, credential vault, loopback/origin/CSRF and provider-normalizer boundaries remain in force.

## MAN-023 final owner acceptance

After merge + independent main gate:
1. Configure Background Protection for 30 minutes and confirm the displayed next run is approximately 30 minutes away, not one minute.
2. Leave the connected mailbox idle for at least several minutes; confirm no synthetic ~2-minute Quick-scan Activity appears.
3. Confirm a manually started Quick/Full/Spam scan still behaves normally.
4. If a genuinely wired provider event source is available in the acceptance environment, verify it triggers bounded protection; otherwise record it as unavailable rather than claiming realtime push coverage.
5. Start normal source mode and confirm no development-plan preview / entitlement mutation control appears even if an old local flag existed.
6. Start the dedicated fixture launcher only for engineering acceptance and confirm fixture/development controls are available there.
7. Packaged consumer launch remains free of development entitlement controls.

Outlook real mailbox acceptance remains postponed and Family acceptance still requires a legitimate entitlement.