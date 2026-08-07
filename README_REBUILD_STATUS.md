# Rebuild status

## Milestone 1 — CLOSED

Milestone 1 was formally accepted on **2026-08-07** after the final owner browser retest passed and the post-merge Engineering Gate passed on both Windows and Ubuntu.

Accepted baseline build:

`3d70e85fcad16bded8e27d31ebeff00031a2a592`

Formal closure record:

`docs/MILESTONE_1_CLOSURE.md`

## Accepted Milestone 1 foundation

- Dedicated killable Worker thread per scan
- Cooperative cancellation plus forced termination
- Operation-scoped provider adapters with one canonical provider contract
- Gmail, iCloud, Outlook, Yahoo and generic IMAP fixture coverage
- Actual IMAP UID search and UIDVALIDITY-aware cursors
- Bounded readable IMAP MIME extraction without attachment-body fetching
- Partial-content verdict protection
- Stable provider action identifiers and exact provider confirmation
- Deterministic Safe / Review / High Risk / Confirmed Threat / Unknown verdict pipeline
- Explainable privacy-reduced diagnostics
- Quick, Full and Spam/Junk scan workflows
- Responsive stop/restart scan lifecycle
- Stale-tab session validation before scan EventSource startup
- Account-scoped encrypted personal policy persistence
- Reversible sender/domain blocks
- Mark Safe, Trust sender, Trash, Spam/Junk, unsubscribe and scam-report action boundaries
- Localhost-only protected desktop API with HttpOnly session, CSRF, same-origin mutation nonce, replay protection, Host checks and redaction
- Provider-neutral community-report client and signed-feed verification architecture
- Live iCloud hard-test coverage
- Windows and Ubuntu engineering gates
- Permanent regression register and browser handoff workflow

## Later milestone work — not claimed complete

Milestone 1 closure does **not** claim completion of:

- persisted scan-history presentation after browser refresh;
- resumable scan cursors across restart/rate limits;
- guided Gmail OAuth onboarding;
- guided Outlook OAuth onboarding;
- OS-keychain / credential-vault-backed key and provider-token custody;
- complete searchable policy-management centre;
- production community-service deployment operations and gateway abuse defence;
- production QR decoder;
- controlled real-destination Analyze Links validation;
- deeper mailbox-derived relationship history;
- structural detection work for known deferred false-negative coverage gaps.

Those remain explicit Milestone 2+ work and must not be represented as already complete.

## Run

```bash
npm install
npm run gate
npm run dev
```

The accepted Milestone 1 baseline should remain green. Any regression in its locked invariants is a defect, not new scope.
