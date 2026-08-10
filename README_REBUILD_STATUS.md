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

## Milestone 2 — CANONICAL PRODUCTION HARDENING IN PROGRESS

Milestone 2 is not formally closed. The August 10 whole-code closure audit remains valid for the narrower desktop-beta boundary it audited, but the recovered canonical three-milestone specification also requires 10,000-client community capacity, anti-rollback feeds, scalable destination-analysis coordination, metrics/abuse operations and Windows-first packaging. The authoritative reconciliation is `.engineering/CANONICAL_ROADMAP_GAP_AUDIT.md`; external owner/deployment work remains in `docs/MILESTONE_2_LIVE_ACCEPTANCE.md`.

The following engineering bricks are implemented and regression-locked on the current rebuild line:

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
- bounded provider-neutral HTML interaction normalization: quoted/unquoted and entity-obfuscated destinations, accepted BASE-relative navigation, form/formaction and META-refresh targets, companion plain-text URLs, inert SCRIPT/STYLE raw text, fail-closed content/tag/destination limits, and reuse of the existing signed-intelligence/community privacy path;
- attachment type-integrity enforcement using provider-neutral canonical MIME metadata, Unicode-safe filename normalization, same-category no-double-count scoring and spoof-resistant evidence display, without new attachment downloads or provider permissions;
- RFC-aware author-domain authentication alignment for sender trust and bounded-content Safe gating: DMARC pass qualifies, explicit DMARC failure is authoritative negative, and SPF/DKIM fallback is accepted only from same-result RFC 8601 identities aligned with RFC5322.From, with no new DNS or provider lookup;
- Public Suffix List-backed registrable-domain boundary with ICANN/private, deep, wildcard and exception rule support, replacing handwritten suffix guesses across authentication, identity and link-domain trust decisions without runtime network lookup;
- bounded signed community-feed acquisition and validation: streamed 32 KiB receipt / 4 MiB feed ceilings, strict v1 entry and identity fan-out bounds, exact Ed25519 signature encoding, verified-cache failover, and capacity-safe accepted-report semantics without claiming public deployment or gateway abuse controls;
- encrypted community disaster-recovery tooling and signing-key rotation preparation: bounded authenticated recovery bundles, owner-only passphrase-file custody, validated atomic restore to a new data path, and self-verifying two-key overlap packages while production restore/rotation execution remains live deployment work;
- production community readiness integrity: `/health` now requires the real aggregate-build/sign/self-verify path, returns generic 503 on failure, bounds repeated probe cost with short process caching, and uses race-safe first-use signing-key initialization without claiming production load-balancer/monitoring acceptance;
- public community error-surface integrity: typed internal failures and strict version-1 runtime report validation now feed a stable JSON/no-store unauthenticated error boundary, preventing Express stacks, raw storage/crypto diagnostics, paths or attacker-controlled fields from crossing the dedicated public service while keeping deployment/gateway controls live;
- encrypted community aggregate-state integrity: successful AES-256-GCM decryption is now followed by strict nested writer-state validation for campaign/reporter identities, timestamps, scores/verdicts, indicator support and evidence counters before stats/feed/report/readiness/backup use the state, without lowering the existing campaign ceiling or claiming deployed restore acceptance;
- recoverable community aggregate storage boundary: live encrypted aggregate reads/writes now share the existing 192 MiB disaster-recovery source budget, reserve bounded storage/signing-key space, reject oversized database files before allocation and fail before encrypting/persisting a report that would make the authoritative state un-backupable;
- community aggregate storage-key read integrity: the existing 32-byte local encryption key now preserves atomic creation while using same-descriptor regular-file/exact-size validation, no-follow where supported, generated-buffer zeroing and fail-closed malformed/symlink handling before key bytes are cached;
- Authentication-Results provenance integrity: raw MIME SPF/DKIM/DMARC/ARC results are now non-authoritative unless the acquisition boundary explicitly marks their producer trusted; unproven pass cannot manufacture identity/Safe/history and unproven fail cannot manufacture threat evidence/downgrade, while synthetic corpus provenance is explicit and shared across all fixture consumers;
- RFC 8058 one-click unsubscribe integrity: automatic POST now requires lossless/unambiguous raw list headers plus exact REG-066 trusted DKIM domain+selector correlation and signed coverage of both required headers; ambiguity or resource-limit exhaustion falls back to the existing manual unsubscribe path while user confirmation and hardened pinned-public HTTPS transport remain unchanged;
- local persistence descriptor/read/commit integrity: encrypted/security-state reads are same-descriptor and pre-allocation bounded, plaintext/encrypted envelope ceilings are distinct, raw private key files require owner-only POSIX modes, failed replacement preserves the previous valid database, and resumable-scan persistence failures are explicit;
- dependency security closure: reviewed Vitest/Microsoft/Google dependency upgrades preserve the existing OAuth/vault/runtime contracts and reduce the accepted installed npm advisory inventory to zero without force-fixing or hand-editing the lockfile;
- scalable durable community ingestion: encrypted append-only report journaling plus bounded atomic snapshot compaction removes whole-database work from each request, 10,000 independent reporters are exercised through the production validation/dedupe/signing path, committed journal records survive restart, incomplete crash tails are removed safely, backup/restore includes the journal, and reporter-derived state expires after a fixed 90-day retention period;
- signed-feed rollback integrity: clients persist an encrypted monotonic generation/digest checkpoint, reject older signed generations and same-generation equivocation across restart/cache paths, permit identical trusted-key overlap and retain only the newest still-fresh verified feed after rejection;
- scalable explicit destination analysis: one process-wide four-slot coordinator bounds the wait queue, coalesces identical in-flight work, uses an HMAC-keyed fixed-expiry 512-entry in-memory LRU cache with no URLs or bodies in cached values, exposes aggregate-only counters, fails overload closed and passes a 10,000-client shared-destination burst without outbound duplication while preserving the existing DNS-pinned egress boundary;

The exact current security and behavior claims are defined by `.engineering/REGRESSION_REGISTER.md`, `.engineering/TEST_MATRIX.md` and the feature-specific security contracts under `.engineering/`.

## Remaining known gaps — not accepted as complete

The current register intentionally keeps these deployment/live-acceptance items open:

- **GAP-001** — production Google OAuth publication/consent verification;
- **GAP-002** — controlled real Microsoft/Outlook owner acceptance;
- **GAP-004** — public community-service deployment, DNS/TLS, monitoring, backups and operational key rotation;
- **GAP-005** — controlled real-destination Analyze Links validation against deliberately managed public infrastructure;
- **GAP-008** — production gateway reporter reputation and volumetric/DDoS abuse defence.

Manual visible acceptance items in the regression register also remain manual until the owner performs them. A green engineering gate does not convert those live/deployment claims into completed work.

The remaining canonical buildable Milestone 2 rows are the wider privacy-safe operational metrics boundary and Windows-first packaging/release preparation. Scalable community ingestion, monotonic signed-feed rollback protection and bounded cached destination-analysis coordination are implemented and regression locked. These are code requirements, not live-test substitutes.

## Run

```bash
npm install
npm run gate
npm run dev
```

Milestone 1 locked invariants and every later `REG-*` entry must remain green. A regression is a defect, not new scope. Milestone 2 must not be declared closed until its remaining registered gaps and required owner acceptance are actually completed.
