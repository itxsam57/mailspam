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
| Rate limiting, abuse controls, health, metrics and structured diagnostics | PARTIAL | Per-reporter daily limits, generic public errors and proof-based readiness exist. Privacy-safe metrics, production edge rate/reputation/DDoS controls and deployed monitoring remain missing/external. |
| Disaster recovery | PARTIAL | Encrypted backup, restore-to-new-path validation and signing overlap tooling exist. The production restore/rotation ceremony remains external. |
| Provider action reliability, retries and idempotency | IMPLEMENTED | Operation-scoped adapters, bounded retry-before-progress and opaque action replay prevention are locked. |
| Windows-first packaging and macOS/mobile shared-core planning | MISSING | No release package, installer, signed manifest, updater or explicit portable-core boundary exists. |
| Security/privacy review and adversarial corpus expansion | IMPLEMENTED | Security contracts, privacy gates, 280 cross-provider corpus scans and zero-advisory dependency gate exist. Continued regression-vault growth belongs to Milestone 3. |
| 10,000 simulated clients report and consume signed rules without duplicate inflation | IMPLEMENTED | Encrypted append-only report journaling and bounded snapshot compaction remove whole-database work per request. The blocking production-path test covers 10,000 independent reporters, exact dedupe, restart recovery, signed confirmed-feed consumption and fixed 90-day retention. |
| Live/deployment acceptance | EXTERNAL | Google publication, real Outlook lifecycle, controlled public Analyze Links infrastructure, community DNS/TLS/storage/monitoring and gateway abuse protection remain in `docs/MILESTONE_2_LIVE_ACCEPTANCE.md`. |

Milestone 2 must not be called closed until the missing buildable rows are implemented and the external acceptance rows pass or are explicitly re-scoped by the product owner.

## Milestone 3 — Release-Ready Cross-Platform Product and Continuous Protection

| Canonical requirement | Status at audit | Exact remaining work |
|---|---|---|
| Production installers, signed releases, updates and rollback | MISSING | Build reproducible platform artifacts, signed release/update manifests, verified updater staging, rollback and uninstall cleanup; platform certificate/notarization acceptance is external. |
| Scheduled background protection | MISSING | Build quota-aware resource-bounded schedules, protected persistence, single-scan exclusion, pause/resume and visible status. |
| Windows, macOS, Android and iOS clients using the shared engine | PARTIAL | Desktop server runs on Windows/macOS/Linux and engine behavior is provider neutral, but no explicit portable core or mobile client boundary exists. Build a platform-neutral core contract and real platform shells within platform limits; store signing remains external. |
| Multi-account management and per-account policy parity | IMPLEMENTED/PARTIAL | Multiple account sessions and account-scoped policies exist. Scheduled protection and complete visible multi-account acceptance remain. |
| Accessibility, localization readiness and safety education | MISSING | Build keyboard/focus/screen-reader semantics, locale-safe message catalog/formatting and user-facing deterministic safety guidance; complete visible acceptance is owner-controlled. |
| Privacy-safe operational dashboards | MISSING | Build protected feed/adapter/error/capacity/abuse review views from aggregate counters only, without report bodies, raw mailbox identities or secrets. |
| Automated Regression Vault expansion | PARTIAL | Fixed corpus and one-command gate exist. Add versioned anonymized intake/approval, provenance, dedupe and release-blocking vault expansion. |
| Long-term provider compatibility tests and release gates | PARTIAL | Fixture conformance and three-OS CI exist. Add provider capability contracts, compatibility snapshots and release blocking against drift. |
| Public privacy, security, threat-model and incident-response documentation | MISSING | Produce documents matching implemented data flows, trust boundaries, retention, response and disclosure process. |
| Final cost controls, capacity tests and deployment documentation | PARTIAL | Bounded resources and deployment runbook exist. Add executable capacity budgets, low-resource/background tests, production sizing and cost evidence. |

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
