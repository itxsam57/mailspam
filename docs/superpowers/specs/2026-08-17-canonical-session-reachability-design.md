# Canonical Mailbox Session and Reachability Design

Date: 2026-08-17
Base: `main` at `6d59937b665fed40d1e6f8c711f0d1dc695d3e0e`
Branch: `repair/canonical-session-reachability-p0-20260817`

## Problem

Email Shield intentionally permits temporary same-mailbox session overlap during credential rotation/reconnect. The encrypted persistent connection registry stores only the newest descriptor, but the in-memory session store keeps both sessions live.

That overlap conflicts with automatic protection:

- Background Protection resolves a stable mailbox identity with the first matching session and can continue using the older authorization.
- Realtime polling deduplicates by provider + stable mailbox identity and likewise keeps the first session it encounters.
- Realtime processing rejects more than one matching session as `provider_mismatch`, so a legitimate reconnect can prevent a changed mailbox from being processed even when the new credential is valid.
- Home currently treats selection as protection readiness and cannot distinguish a restored-but-unverified mailbox from one whose provider heartbeat is failing.

The root cause is the absence of an authoritative active-session owner for a stable mailbox identity. The Home wording is a downstream symptom.

## Goals

1. A stable mailbox identity has exactly one canonical session eligible for new scans/background/realtime work.
2. A newly secured reconnect becomes canonical only after protected credential storage and live-connection persistence succeed.
3. The previous same-mailbox session may remain temporarily addressable for bounded cleanup, but is marked superseded and is never selected for new automatic work.
4. Disconnecting/removing a superseded session must not revoke the provider grant, remove the current persistent descriptor, or delete credentials still referenced by the canonical session.
5. Genuine unexplained duplicate active sessions that are not in a valid canonical/superseded relationship remain fail-closed.
6. Provider reachability is derived from the existing metadata-only realtime heartbeat; no additional provider probe or message download is introduced.
7. Consumer status exposes only sanitized per-mailbox state: `verifying`, `reachable`, or `provider_unavailable`, plus bounded timestamps/reason enums. No raw provider exception text, mailbox content, provider-native IDs, addresses, tokens, credentials, or policy-account keys are exposed.
8. Home must never say `Protection ready` for an unverified or unavailable selected mailbox.
9. Failure of account A must not downgrade healthy account B.
10. Outlook remains implemented at the shared provider boundary but normal-consumer live acceptance stays postponed.

## Non-goals

- No detector/scoring/threshold changes.
- No new provider-specific scanning path.
- No second background scheduler or heartbeat.
- No weakening of OAuth validation, credential vault, CSRF/local API security, Community privacy, or Family authorization.
- No automatic branch merge.

## Chosen Architecture

### 1. SessionStore owns canonicality

Extend `AccountSession` with an internal lifecycle role, represented without exposing stable mailbox identity to the browser:

- `canonical` — eligible for all new work.
- `superseded` — retained only for bounded cleanup/removal; never selected for new work.

`SessionStore` gains canonical lookup helpers by stable mailbox identity/provider. Callers that need automatic work use those helpers instead of scanning raw `list()` output.

A successful live reconnect is committed atomically inside the existing serialized vault lifecycle:

1. secure/write new credentials;
2. create the new session in provisional/canonical-candidate form;
3. persist the newest encrypted connection descriptor;
4. only then promote the new session to canonical and demote the previous canonical session(s) for the same stable mailbox identity to superseded.

If persistence/session initialization fails, rollback removes the candidate and leaves the previous canonical session unchanged.

Fixture sessions remain deterministic and follow the same canonical lookup contract, but do not gain a production credential bypass.

### 2. Removal and revocation semantics

`remove(id)` distinguishes canonical from superseded sessions.

- Removing a superseded session never removes the current persistent descriptor and never revokes the provider grant solely because it is being removed.
- Removing the final canonical live session performs the existing persistent-descriptor removal and provider revocation flow.
- Vault reference counts remain authoritative for protected credential deletion.
- If a canonical session is removed while a valid superseded predecessor still exists, Email Shield does not silently reactivate stale credentials. That mailbox becomes disconnected/unavailable and requires an explicit reconnect. This avoids rollback to credentials the user intentionally replaced.

### 3. Automatic protection consumes canonical sessions

Background Protection, realtime polling, and realtime processing resolve only canonical sessions.

Realtime processing still fails closed when the store reports ambiguous canonical state or a provider mismatch. We do not change the rule to `pick any duplicate`.

### 4. Per-mailbox reachability from the existing heartbeat

`RealtimeProtectionService` keeps a bounded in-memory reachability record keyed internally by stable mailbox identity/provider:

- `verifying`: canonical session exists but no successful metadata heartbeat has completed for its current session generation.
- `reachable`: latest metadata checkpoint probe succeeded, including unchanged checkpoint/baseline cases.
- `provider_unavailable`: latest probe threw at the provider boundary.

The record also contains a session-generation/token so a late response from a superseded session cannot overwrite the new canonical session's status.

A successful unchanged heartbeat marks the mailbox reachable but does not trigger a scan or Activity entry. A probe failure marks only that mailbox unavailable. Global realtime status may continue to report aggregate errors for diagnostics.

### 5. Sanitized local API and Home truth

Inject a narrow reachability/status reader into the protected consumer desktop composition, following the existing dependency-injection pattern used by Background Protection.

Expose account-scoped status through the protected local API. The browser receives only:

- transient `accountId`;
- provider/label already exposed today;
- `protectionState`: `verifying | reachable | provider_unavailable`;
- optional bounded timestamp;
- safe reason enum when unavailable.

Home behavior:

- no selected mailbox -> `Connect or select a mailbox`;
- selected `verifying` -> `Mailbox connected — verifying protection`;
- selected `reachable` -> `Protection ready for selected mailbox`;
- selected `provider_unavailable` -> `Mailbox connection needs attention`, with a safe route to Mailboxes & Settings/reconnect.

Browser updates are guarded by the existing account-selection generation so stale A->B->A responses cannot repaint the wrong account.

## Error Handling / Security

- Raw provider errors remain server-side and are never serialized in protection status.
- A reachability read failure degrades to `verifying`/safe unavailable copy; it never invents `reachable`.
- Reconnect promotion is fail-closed: persistence failure leaves the old canonical owner intact and rolls back the candidate.
- Automatic protection never falls back from a removed new canonical session to superseded stale credentials.
- No mailbox body, subject, sender, recipient, URL, provider message ID, token, credential, or stable policy-account key is added to the consumer API.

## TDD / Verification Sequence

### RED 1 — canonical replacement transaction

Add SessionStore tests proving:

- first same-mailbox session is canonical;
- successful secured reconnect promotes the new session and supersedes the old one;
- persistence failure during reconnect leaves the old session canonical and removes the candidate;
- removing old superseded session cannot revoke/remove the new descriptor;
- removing canonical does not silently reactivate superseded credentials;
- genuinely ambiguous state remains fail-closed.

### GREEN 1

Implement the minimal SessionStore lifecycle role + canonical lookup/promotion semantics.

### RED 2 — automatic consumers

Add tests proving Background and Realtime always use the canonical new session after reconnect and never the superseded one. Preserve provider mismatch failure for genuine ambiguity.

### GREEN 2

Replace raw `list().find`/first-dedupe resolution with the SessionStore canonical contract.

### RED 3 — reachability

Add realtime tests with two accounts where one probe succeeds and one fails. Assert:

- success records `reachable` even when checkpoint is unchanged;
- failure records only that mailbox as `provider_unavailable`;
- new canonical generation starts `verifying` and stale old-session completion cannot overwrite it;
- no raw provider error text is exposed.

### GREEN 3

Add the bounded per-mailbox reachability registry to the existing realtime heartbeat.

### RED 4 — protected API/Home

Add local API + browser tests proving:

- unverified selected account never says `Protection ready`;
- unavailable selected account visibly needs attention;
- healthy account B remains ready when A fails;
- account switching rejects stale status;
- reconnect produces one canonical consumer mailbox row/owner for new work;
- reconnect guidance routes to Settings without exposing provider internals.

### GREEN 4

Inject the reachability reader into consumer desktop composition and wire Home to the protected status.

### Runtime-strengthening acceptance

Extend real Chromium coverage for the consolidated final wave:

- broken/restored connection truth;
- reconnect canonical ownership;
- Full terminal scan;
- Spam/Junk scan;
- Stop -> Resume exact checkpoint;
- two-account scan/background isolation;
- one visible action of each kind per message;
- all eight routes repeatedly + refresh without blank/frozen/stale overlays.

Real provider owner acceptance remains separate from CI; Outlook live acceptance remains postponed.

## Acceptance Criteria

This wave is complete only when:

1. RED commits fail for the intended missing contracts before production implementation.
2. GREEN commits pass targeted tests and the full Engineering Gate on the exact branch head across Windows, macOS, Ubuntu + real Linux Secret Service, and Gate Result Summary.
3. Detection corpus/regression vault remains unchanged/green.
4. No new raw mailbox/provider secret data crosses the consumer API.
5. A real reconnect cannot leave automatic protection selecting the older session.
6. Home cannot claim ready without successful provider heartbeat evidence.
7. PR remains unmerged until explicit per-PR user authorization.