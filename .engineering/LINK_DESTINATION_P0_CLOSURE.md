# Email Shield — Link / Destination Integrity P0 Closure

Date: 2026-08-17
Program owner: EMA-33
Repair PR: #104
Base main: `aed9e5eac3e1f6d68e25fa34066738fda49d9894`

## Status

The code/automation portion of P0 Link / Destination Integrity is closed on the repair branch once the final immutable three-platform Engineering Gate for this document head is green. Real public-network and owner-browser acceptance remains external/manual and is not represented as CI evidence.

This additive record supplements the historical Regression Register/Test Matrix and follows the Wave 0/1 supplemental IDs with REG-091, A-73 and MAN-022.

## Locked architecture contract — REG-091

1. Attacker-controlled destinations have one shared canonicalization boundary in `server/src/util/htmlInteraction.ts`.
2. HTML entities are decoded as part of static message extraction, while a whole-percent-encoded absolute HTTP(S) destination may be decoded exactly once.
3. Percent decoding is never recursive. Partially/mixed encoded ordinary URLs are not promoted into the whole-encoded path.
4. Encoded `javascript:`, `data:`, `file:` and other non-web schemes remain inert evidence rather than becoming executable/network destinations.
5. Encoded URL credentials/userinfo are rejected by canonicalization and remain non-authorizing evidence.
6. Encoded private/loopback/link-local/metadata HTTP(S) URLs may canonicalize only so the existing downstream SSRF/network-safety owner can block them before fetching.
7. Raw/display URL evidence is preserved separately from the canonical network destination.
8. Check Anything Link mode and scanned-message Analyze Links reuse the same `DestinationAnalysisCoordinator`; there is no second destination fetcher.
9. Pasted Message, submitted `.eml` and image Scam Check modes do not automatically browse destinations.
10. Destination network analysis remains explicit user action only and preserves DNS pinning, per-redirect revalidation, credentials denial, private-address blocking, size/time/content bounds and non-execution of fetched content.
11. A successful benign content inspection means only that the bounded fetched text did not expose the implemented credential-trap/malware/risk signatures. It is never presented as proof the site or message is safe.
12. Network failure/unsupported content/capacity exhaustion/incident disablement remains fail-closed as unavailable/error rather than benign.

## Automated closure matrix — A-73

Blocking coverage includes:

- `tests/unit/linkDestinationNormalization.test.ts` — one-pass whole encoding, double encoding, non-web schemes, credentials, loopback and malformed escapes.
- `tests/unit/linkDestinationDownstreamParity.test.ts` — canonical public destination reaches classification while unsafe/invalid forms remain owned by downstream fail-closed controls.
- `tests/unit/scamCheckUrlDestinationIntegration.test.ts` — protected Check Anything Link route invokes the shared destination coordinator, encoded Link canonicalizes before analysis, and Message mode stays network-free.
- `tests/unit/scamCheckDestinationWeb.test.ts` — consumer Link UI renders destination inspection separately from the local scam verdict and does not call benign inspection proof of safety.
- `tests/unit/destinationAnalysisCoordinator.test.ts` — bounded workers, input order, credential-trap escalation, deterministic malware, cache/coalescing, fixed retention, short error TTL, capacity fail-closed, LRU budget and 10,000-client coalescing.
- `tests/unit/hardenedFetchDnsPin.test.ts` — DNS pinning, mixed public/private DNS denial, redirect revalidation, private IPv4/IPv6 denial, credential/non-HTTP denial, body/content limits and redirect cap.
- full provider corpus/core/provider-compatibility/browser/server/package/release gates remain mandatory.

## TDD evidence

### EMA-7 whole-percent-encoded URL defect

Initial RED SHA: `59f137b07ee1645b9c1aa5542e1d86f6bc11aba8` — Engineering Gate #1169.

The test-only change demonstrated that a fully encoded absolute HTTP(S) URL was not canonicalized by the shared message interaction boundary.

Initial GREEN: `eee35cf0b0592dbcf9bade88500787e44b08a1c0`.

Self-review then added a mixed/partially encoded adversarial regression at RED SHA `85d6fd3a0d59bb2c23f2c3d03e31c7bb59685575`, proving the initial recognizer was too permissive for the intended whole-encoded contract. The recognizer was tightened at `63580df14d8a09a4ae96b95eeb8cc5041ca798be` and downstream parity was locked at `c963147a5fe16c3603242f168f3eeb9ba7a70103`.

### EMA-10 Check Anything route-composition defect

RED SHA: `2af9899dda1c097a967fbca10fad82cd6f5912a9`.

The protected real desktop route proved that Link mode did not invoke destination analysis, while Message mode correctly remained network-free.

API GREEN converged `/api/scam-check/v1/analyze` Link mode onto the existing `DestinationAnalysisCoordinator` and injected the same coordinator through `createConsumerDesktopServer`.

### Consumer result-truth defect

Browser RED SHA: `409059c114be6ea91ac5c8c474b8d6fea29e036f` — Engineering Gate #1177.

The test-only commit produced exactly two intended browser contract failures while 195 existing test files and 1,139 existing tests passed on the reviewed macOS run. The five-provider corpus remained 140/140 malicious non-Safe and 140/140 legitimate Safe.

Browser GREEN SHA: `669db0ba4c4d2dd14839b1a01eb20e8047410b28`.

The consumer Link UI now distinguishes inspected benign content, credential trap, malware, blocked unsafe target, unavailable/error and other destination-risk classifications from the local scam verdict. Benign destination inspection explicitly says it is not proof the site or message is safe.

### Shared service contract cleanup

Code head before closure documentation: `e750f3ab3b063005b6486a1aadc40325e113d481`.

`DestinationAnalysisCoordinator` and `analyzeLinks()` now formally accept only the `links` slice they consume. Both the scanned-message route and Check Anything route therefore reuse the service without fake `CanonicalEnvelope` casts or a second transport path.

## Security/diff review

The Wave 2 changes preserve the EMA-33 non-negotiables:

- no provider-specific detector or verdict branch;
- no threshold lowering or Safe shortcut;
- no raw mailbox content added to diagnostics/community;
- no second destination network client;
- no automatic destination browsing during Quick/Full/Spam/background/realtime mailbox scans;
- no weakened private/loopback/link-local/metadata denial;
- no DNS rebinding relaxation or redirect validation bypass;
- no URL credentials authorization;
- no fetched content execution;
- no arbitrary remote AI service added;
- no consumer claim that a successful bounded destination inspection proves safety.

The deterministic transport suite is already comprehensive; no production hardened-fetch change was made without a reproducible transport defect.

## Manual owner reacceptance — MAN-022

After PR #104 is merged and an independent exact-main gate is green, perform the Link/Destination portion during the final consolidated live test:

1. Check Anything → Link: ordinary public HTTPS page. Expected: local scam verdict plus a separate destination result; successful bounded inspection must not claim the site is proven safe.
2. Check Anything → Link: a fully percent-encoded public absolute HTTPS URL. Expected: one-pass canonicalization and the same explicit destination-analysis path rather than `Malformed URL` solely because the full URL was encoded.
3. Check Anything → Link: loopback/private/link-local/metadata/credential URL controls. Expected: blocked/error, never benign, with no unsafe connection.
4. Check Anything → Message containing a URL. Expected: local message analysis only; destination browsing does not occur merely because a URL appears in pasted text.
5. Connected-mailbox suspicious message → Analyze Links. Expected: token-bound explicit action uses the same destination-analysis semantics and remains account/message scoped.
6. Public-network acceptance: use at least one known ordinary HTTPS destination and one deterministic safe test destination available at acceptance time. If the environment/network prevents trusted acquisition, show `Destination inspection unavailable` rather than Safe.

CI does not possess the owner browser/network environment, so MAN-022 remains manual until the final live test.

## Scope reconciliation

This record closes only the Link/Destination code/automation wave. The EMA-33 sequence continues with Protection Lifecycle/Security, Message Actions/Lifecycle, Diagnostics and Consumer/Health/Onboarding. Outlook real-mailbox and legitimate Family-entitlement acceptance remain external constraints and are not to be bypassed.
