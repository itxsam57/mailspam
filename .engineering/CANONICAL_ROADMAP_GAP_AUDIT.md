# Email Shield — Canonical Three-Milestone Gap Audit

## Authority

This audit reconciles the repository against `Email_Shield_Three_Milestone_Engineering_Feature_Workflow_Specification.docx` version 1.0 (August 2026). That specification is the product source of truth. Later repository documents may strengthen a boundary, but may not shrink or rename the canonical milestone acceptance gates.

Status meanings:

- **CLOSED** — implemented, automatically verified and owner/live accepted where the specification requires it.
- **IMPLEMENTED** — real code and blocking automated coverage exist; external acceptance may remain.
- **PARTIAL** — some production path exists, but at least one required producer, consumer, scale, security or acceptance path is missing.
- **MISSING** — no production implementation satisfying the requirement exists.
- **EXTERNAL** — repository work can prepare the boundary, but completion requires owner credentials, signing identity, public infrastructure or platform-store acceptance.

## Milestone 1 — Complete Testable Cross-Adapter Protection Core

**Overall: CLOSED.** The accepted closure record is `docs/MILESTONE_1_CLOSURE.md`. Later Milestone 2 changes are guarded as regressions and do not reopen Milestone 1.

The current code retains the canonical provider contract, Gmail/iCloud/Outlook/Yahoo/IMAP fixture parity, deterministic corpus, Quick/Full/Spam workflows, real cancellation, resumable cursors, bounded MIME handling, explicit Analyze Links, action separation, privacy-reduced reporting, local policy state, signed-feed verification and the complete Engineering Gate.

## Milestone 2 — Verified Community Intelligence and Production Hardening

| Canonical requirement | Status at audit | Evidence / exact remaining work |
|---|---|---|
| Privacy-preserving report ingestion and mailbox deduplication | IMPLEMENTED | Reporter HMAC proof, strict report schema, encrypted aggregate state and independent-reporter dedupe are locked. |
| Campaign fingerprinting and cross-provider correlation | IMPLEMENTED | Canonical report construction covers campaign, sender, Reply-To domain, destination domain and bounded attachment hashes through one provider-neutral path. |
| Brigade-resistant warning/confirmed thresholds | IMPLEMENTED | Independent-reporter and weighted evidence thresholds are locked; production edge/Sybil controls remain external. |
| Signed feed publishing, rotation, rollback protection and offline cache | IMPLEMENTED/EXTERNAL | Ed25519 signing, bounded verification, encrypted monotonic generation/digest acceptance, trusted multi-key overlap, verified offline cache and rotation preparation are implemented. The production key-rotation ceremony remains external. |
| Scalable isolated destination-analysis workers, cache and strict egress | IMPLEMENTED/EXTERNAL | The explicit local path now has a process-wide bounded worker coordinator, bounded queue, same-destination request coalescing, HMAC-keyed fixed-expiry LRU classification cache, aggregate-only telemetry and 10,000-client burst proof. DNS validation, per-hop socket pinning and resource limits remain locked. Controlled public-infrastructure acceptance remains external under GAP-005. |
| Rate limiting, abuse controls, health, metrics and structured diagnostics | IMPLEMENTED/EXTERNAL | Per-reporter daily limits, generic public errors and proof-based readiness now feed a fixed-cardinality aggregate registry, bearer-protected disabled-by-default Prometheus endpoint and fixed-schema JSON-line diagnostics with no attacker/mailbox/report values. Production edge enrollment/reputation/DDoS controls and deployed monitoring remain external under GAP-004/GAP-008. |
| Disaster recovery | PARTIAL | Encrypted backup, restore-to-new-path validation and signing overlap tooling exist. The production restore/rotation ceremony remains external. |
| Provider action reliability, retries and idempotency | IMPLEMENTED | Operation-scoped adapters, bounded retry-before-progress and opaque action replay prevention are locked. |
| Windows-first packaging and macOS/mobile shared-core planning | IMPLEMENTED | The host-targeted portable builder packages the exact Node 22 runtime, compiled app/web and lockfile-derived production dependency closure; normalized SHA-256 manifest/release ID, full re-hash, dev/secret/symlink rejection and bundled-runtime loopback smoke run on Windows/macOS/Linux CI. The cross-platform core/platform plan fixes the future boundary. Signed installers/update/rollback and actual mobile shells remain Milestone 3/external. |
| Security/privacy review and adversarial corpus expansion | IMPLEMENTED | Security contracts, privacy gates, 280 cross-provider corpus scans and zero-advisory dependency gate exist. Continued regression-vault growth belongs to Milestone 3. |
| 10,000 simulated clients report and consume signed rules without duplicate inflation | IMPLEMENTED | Encrypted append-only report journaling and bounded snapshot compaction remove whole-database work per request. The blocking production-path test covers 10,000 independent reporters, exact dedupe, restart recovery, signed confirmed-feed consumption and fixed 90-day retention. |
| Live/deployment acceptance | EXTERNAL | Google publication, real Outlook lifecycle, controlled public Analyze Links infrastructure, community DNS/TLS/storage/monitoring and gateway abuse protection remain in `docs/MILESTONE_2_LIVE_ACCEPTANCE.md`. |

Milestone 2's repository-buildable rows are implemented. Formal milestone closure still requires the external/live acceptance rows to pass or be explicitly re-scoped by the product owner; automated simulations do not close them.

## Milestone 3 — Release-Ready Cross-Platform Product and Continuous Protection

| Canonical requirement | Status at audit | Exact remaining work |
|---|---|---|
| Production installers, signed releases, updates and rollback | IMPLEMENTED/EXTERNAL | Host artifacts now carry the packaged lifecycle CLI; exact Ed25519 update envelopes bind target/version/commit/release ID and the full portable-manifest digest. Pinned overlap trust, before/after-copy verification, strictly newer updates, atomic activation, fail-closed repair, signed one-step rollback and guarded uninstall/data preservation are blocking-tested against the actual packaged runtime. Native installer wrapping, production release-key ceremony, Authenticode/Developer ID/notarization and distribution acceptance remain external. |
| Scheduled background protection | IMPLEMENTED | Per-account 30-minute-to-24-hour schedules use separate native-vault-backed encrypted persistence, one global Worker slot, manual-scan priority, bounded Quick scans, progress/deadline enforcement, retry backoff, pause/resume and privacy-reduced visible status. The compiled Worker smoke proves the production path. Native OS background-task/notification acceptance remains platform work. |
| Windows, macOS, Android and iOS clients using the shared engine | PARTIAL | A strict version-1 portable core now has bounded runtime validation, I/O-free transitive dependency enforcement, ECMAScript-only hashing, desktop workflow routing and exact five-provider/adversarial JSON vectors. Real Windows/macOS/Android/iOS shells and their native bridge/store acceptance remain; signing/notarization/store review is external. |
| Multi-account management and per-account policy parity | IMPLEMENTED/PARTIAL | Multiple account sessions, policies, histories and schedules are account-key scoped; conflicting manual/background work cannot cross accounts and disconnect removes its schedule. Complete owner-visible multi-account and native-platform acceptance remain. |
| Accessibility, localization readiness and safety education | IMPLEMENTED/PARTIAL | The dashboard now has labelled controls/landmarks, selected-state semantics, live status, accessible layer/table text, visible focus, higher-contrast secondary text, reduced-motion/forced-color/narrow layouts and no third-party fonts. A strict extensible catalog with shared locale date/number formatting and a visible deterministic safety guide are blocking-tested. Owner keyboard/screen-reader/zoom/high-contrast review and professional non-English translation remain manual. |
| Privacy-safe operational dashboards | IMPLEMENTED/EXTERNAL | The protected no-store desktop view exposes only fixed-cardinality adapter/scan/feed/background/destination/review aggregates, with closed labels and no mailbox/content/identity/destination/exception values; community Prometheus metrics retain the separate fixed aggregate boundary. Deployed alert/on-call integration remains GAP-004. |
| Automated Regression Vault expansion | IMPLEMENTED | Two-stage attested sanitization and exact-digest fixed-role approval enforce provenance, placeholder-only contact/destination data, SHA-256, sorting/dedupe and Safe/non-Safe outcomes across all five adapters before source admission. The compiled vault gate blocks the Engineering Gate and direct release signing. |
| Long-term provider compatibility tests and release gates | IMPLEMENTED/EXTERNAL | A reviewed version-1 capability snapshot requires the same scan/action/canonical-core surface for all five providers and executes fixture connect/folder/fetch/cancel/Spam/Trash parity in both the full gate and release signing. Owned live-provider compatibility remains external. |
| Public privacy, security, threat-model and incident-response documentation | IMPLEMENTED | Public root documents now describe exact local/community data flows and retention, private disclosure, assets/trust boundaries/residual risk, severity/containment/key/privacy playbooks and truthful mobile/deployment limitations; a blocking documentation contract prevents silent removal/stale milestone claims. |
| Final cost controls, capacity tests and deployment documentation | IMPLEMENTED/EXTERNAL | Runtime-owned schema-v1 workload planning exposes exact network/storage/concurrency/background budgets, operator-priced deterministic cost arithmetic and a reviewed baseline under a 70% storage target. The gate adds a low-heap compiled background performance budget to the existing 10,000-reporter/capacity/package proofs. Actual infrastructure load, price, recovery and alert acceptance remain external. |

## Implementation order

1. Milestone 2 scalable durable community ingestion, retention and 10,000-client proof.
2. Milestone 2 isolated destination-analysis coordinator, bounded cache and capacity proof.
3. Milestone 2 privacy-safe metrics and operational boundary; keep gateway/DNS/TLS acceptance external.
4. Milestone 3 scheduled background protection and complete account-scoped control surface.
5. Milestone 3 portable shared-core/platform contract and client/release architecture.
6. Milestone 3 reproducible signed release manifests, updater/rollback and platform packaging automation.
7. Milestone 3 accessibility/localization/safety education.
8. Milestone 3 operational dashboard, regression-vault intake, provider compatibility and release gates.
9. Milestone 3 public security/privacy/incident/deployment/cost documentation and final acceptance reconciliation.

Every brick requires a focused regression suite followed by the unchanged complete Engineering Gate. External acceptance is never converted into a code PASS by simulation.

The final line-by-line disposition is `docs/THREE_MILESTONE_FINAL_RECONCILIATION.md`. Milestone 3 is not formally closed: Android/iOS mailbox application shells remain missing repository code, while native signing/background/store, provider, deployment and assistive-technology gates require external acceptance.
