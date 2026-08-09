# Rebuild status

## Milestone 1 — CLOSED

Milestone 1 was formally accepted on **2026-08-07** after the final owner browser retest passed and the post-merge Engineering Gate passed on both Windows and Ubuntu.

Accepted baseline build:

`3d70e85fcad16bded8e27d31ebeff00031a2a592`

Formal closure record:

`docs/MILESTONE_1_CLOSURE.md`

## Accepted Milestone 1 foundation

The following list records the Milestone 1 baseline as accepted at closure. Later Milestone 2 work may deliberately strengthen these boundaries; the current behavior is governed by the regression register and test matrix.

- Dedicated killable Worker thread per scan
- Cooperative cancellation plus forced termination
- Operation-scoped provider adapters with one canonical provider contract
- Gmail, iCloud, Outlook, Yahoo and generic IMAP fixture coverage
- Actual IMAP UID search and UIDVALIDITY-aware cursors
- Bounded readable IMAP MIME extraction
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

## Milestone 2 — IN PROGRESS

Milestone 2 is not formally closed. The following engineering bricks are implemented and regression-locked on the current rebuild line:

- guided Gmail desktop OAuth with PKCE, stable identity, protected refresh-token custody and owner-accepted live Gmail reconnect/scan flow;
- guided Outlook public-client PKCE architecture, stable Graph identity and protected refresh-token rotation, with real-Outlook owner acceptance still open;
- one cross-platform native credential-vault abstraction covering Windows Credential Manager, macOS Keychain and Linux Secret Service;
- personal-policy encryption-key migration into protected native custody;
- complete selected-account Personal Policy Management Centre with strict policy-only import/export;
- encrypted resumable scan history, provider cursor checkpoints, restart recovery and detached-dashboard continuation;
- encrypted account-local relationship history with HMAC-only identities and replay-safe persistence;
- bounded local PNG/JPEG QR decoding with provider-neutral link evidence and no cloud decoder;
- hardened explicit Analyze Links transport with per-hop DNS validation/socket pinning, SSRF/rebinding protection and strict resource limits;
- mailbox-derived RFC thread-continuity and mid-thread Reply-To anomaly detection using account-local HMAC history;
- bounded attachment-hash threat intelligence: provider-neutral 4-attachment / 2 MiB exact-hash limits, local raw-MIME hashing, selected-part IMAP acquisition, complete-part validation, inline-attachment parity, QR-byte reuse, privacy-reduced diagnostics and fail-closed signed-hash coverage;
- bounded provider-neutral HTML interaction normalization: quoted/unquoted and entity-obfuscated destinations, accepted BASE-relative navigation, form/formaction and META-refresh targets, companion plain-text URLs, inert SCRIPT/STYLE raw text, fail-closed content/tag/destination limits, and reuse of the existing signed-intelligence/community privacy path.

The exact current security and behavior claims are defined by `.engineering/REGRESSION_REGISTER.md`, `.engineering/TEST_MATRIX.md` and the feature-specific security contracts under `.engineering/`.

## Remaining known gaps — not accepted as complete

The current register intentionally keeps these deployment/live-acceptance items open:

- **GAP-001** — production Google OAuth publication/consent verification;
- **GAP-002** — controlled real Microsoft/Outlook owner acceptance;
- **GAP-004** — public community-service deployment, DNS/TLS, monitoring, backups and operational key rotation;
- **GAP-005** — controlled real-destination Analyze Links validation against deliberately managed public infrastructure;
- **GAP-008** — production gateway reporter reputation and volumetric/DDoS abuse defence.

Manual visible acceptance items in the regression register also remain manual until the owner performs them. A green engineering gate does not convert those live/deployment claims into completed work.

## Run

```bash
npm install
npm run gate
npm run dev
```

Milestone 1 locked invariants and every later `REG-*` entry must remain green. A regression is a defect, not new scope. Milestone 2 must not be declared closed until its remaining registered gaps and required owner acceptance are actually completed.