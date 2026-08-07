# Email Shield — Milestone 1 Closure Record

**Status:** CLOSED  
**Owner acceptance date:** 2026-08-07  
**Accepted main build:** `3d70e85fcad16bded8e27d31ebeff00031a2a592`  
**Post-merge Engineering Gate:** run 165 — Windows PASS, Ubuntu PASS, combined summary PASS

## Closure basis

Milestone 1 is formally closed because the automated engineering gate passed on both supported CI operating systems and the owner completed the final targeted browser acceptance retest with all required checks passing.

Final owner retest results:

- **A — Fixture Spam/Junk discovery:** PASS
- **B — Spam/Junk movement persists across rescan:** PASS
- **C — Sender block is visible and reversible:** PASS
- **D — Previously reported campaign state is visible and remains separate from provider Spam/Junk movement:** PASS
- **E — Stale browser tab after process restart fails clearly instead of hanging on scan startup:** PASS

## Locked owner-found regressions

The closure build includes permanent regression protection for:

- `REG-037` — provider fixtures expose Inbox, Spam/Junk and Trash correctly;
- `REG-038` — exact fixture Trash/Spam movements remain moved across adapter recreation;
- `REG-039` — stale tabs validate protected session state before EventSource scan startup;
- `REG-040` — sender/domain blocks are visibly reversible and persisted policy/report state is disclosed on rescan.

## What this closure means

Milestone 1's transport architecture, canonical provider contract, local scan lifecycle, fixture workflows, protected local API, provider-neutral actions, deterministic verdict pipeline, bounded IMAP extraction, live iCloud validation, community-report client behavior, and owner-visible regression set are accepted as the stable base for Milestone 2.

Milestone 1 must not be reopened merely to absorb later product scope. Any future regression in a locked Milestone 1 invariant is a defect and must be fixed against this accepted baseline.

## Explicitly deferred — not part of Milestone 1 closure

The following remain open product/deployment work and do not invalidate Milestone 1 closure:

- persisted scan history and resumable scan cursors across refresh/restart/rate limits;
- guided Gmail OAuth onboarding;
- guided Outlook OAuth onboarding;
- OS keychain / credential-vault-backed key and token custody;
- complete searchable policy-management centre;
- production community-service deployment operations and gateway abuse protection;
- production QR decoder;
- controlled real-destination Analyze Links validation;
- deeper mailbox-derived relationship history;
- previously observed detection false-negative coverage gaps that were intentionally deferred for later structural detection work.

These items must remain tracked as later milestone work rather than being silently reported as completed.
