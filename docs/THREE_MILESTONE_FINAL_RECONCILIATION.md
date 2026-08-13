# Three-Milestone Final Engineering Reconciliation

Date: 2026-08-13  
Authority: `Email_Shield_Three_Milestone_Engineering_Feature_Workflow_Specification.docx` v1.0 plus the accepted pre-native completion contract `docs/FINAL_CONSUMER_COMPLETION_MILESTONE.md`.

This record separates repository implementation from owner, provider, deployment, signing and native-platform acceptance. A green repository gate never substitutes for a real external gate.

## Outcome

| Milestone | Repository implementation | Formal status | What remains outside repository code closure |
|---|---|---|---|
| 1 — cross-adapter protection core | Complete and regression locked | **CLOSED** | None; closure evidence is `docs/MILESTONE_1_CLOSURE.md`. |
| 2 — community intelligence and hardening | Every repository-buildable canonical row is implemented | **CODE-COMPLETE / EXTERNAL ACCEPTANCE OPEN** | GAP-001/002/004/005/008 and required owner-visible checks. |
| 3 — release-ready continuous consumer product | Repository-buildable release lifecycle, continuous protection, portable engine/bridges, account/family/billing lifecycle, consumer safety surfaces, accessibility/localization architecture, operations, Regression Vault/provider gates and capacity/release contracts are implemented | **CODE-COMPLETE / FINAL OWNER GATE OPEN** | Final literal-head three-OS gate and owner live acceptance; native Windows/macOS/Android/iOS shells, store signing/distribution and production infrastructure remain the next/external phase. |

The project must not be described as all three milestones formally closed until final owner/external acceptance is complete. Repository code completion and production publication are different states. Android/iOS mailbox application shells are not implemented in this repository; they are the next native wrapping phase after the final pre-app gate. Native application wrapping therefore is not counted as an unfinished repository workstream inside `FINAL_CONSUMER_COMPLETION_MILESTONE.md`.

## Milestone 2 external acceptance

- GAP-001: publish/verify the production Google OAuth application and consent surface.
- GAP-002: complete controlled real-Outlook connect/scan/action/disconnect/reconnect acceptance.
- GAP-004: deploy the public community service with DNS/TLS, persistent storage, monitoring, backup/restore and a real signing-key overlap/switchover/retirement ceremony.
- GAP-005: validate Analyze Links against deliberately controlled public destination/redirect/DNS infrastructure.
- GAP-008: deploy and prove gateway enrollment/reputation/rate/DDoS controls.
- Complete the visible/manual register without recording credentials, mailbox bodies or private provider identifiers.

These external gates remain real launch work; they do not represent missing local product code and may not be simulated as PASS.

## Milestone 3 canonical reconciliation

| Canonical row | Repository evidence | Remaining non-repository/owner gate |
|---|---|---|
| Production releases/update/rollback | Reproducible portable packages; exact Ed25519 envelope; pinned overlap trust; install/newer update/atomic activation/repair/rollback/guarded uninstall lifecycle | Native MSI/PKG/DMG/app wrapping, production signing-key custody, Authenticode/Developer ID/notarization/store distribution. |
| Continuous mailbox protection | Encrypted per-account schedules, bounded Worker, manual priority, replay-safe inbound event state, provider source normalization and realtime processor/service | OS-native background scheduling/notifications and live provider notification subscriptions on packaged applications. |
| Shared Windows/macOS/Android/iOS engine contracts | Schema-v1 I/O-free portable core, exact five-provider/adversarial vectors, account/family sync and mobile scam-channel/native bridge contracts | Native shell acquisition/storage/scheduling/action/UI implementation and native corpus execution begin after pre-app acceptance. |
| Multi-account policy parity | Account-keyed policies/history/schedules/actions, scan conflict isolation and disconnect cleanup | Owner multi-account review against the release candidate. |
| Consumer Check Anything / explainability | Text/link/EML/image/QR deterministic paths, limitations/provenance and safe-action guidance | Owner UX acceptance and native OCR/camera/share integrations where applicable. |
| Protection sensitivity / personalization | Three profiles with hard-threat invariants; relationship history is evidence rather than allowlist; reset/export controls | Owner behavioral review on representative accounts. |
| Family Guardian / campaign radar | Family privacy boundary, trusted assistance, ownership/revocation, signed campaign intelligence and consumer radar surfaces | Owner multi-device Family acceptance and deployed signed-feed operation. |
| Inbox/Mailbox Health / activity / Undo | Subscription/cleanup/security indicators, Digital Account Footprint, privacy-safe activity and provider-capability-gated Undo | Live-provider destructive/recovery acceptance. |
| Browser/mobile/intervention safety contracts | Hardened URL verdict, DNS-pinned transport, SMS/notification/share/calendar/QR contracts and callback/payment/remote-access guidance | Native browser/mobile bridge packaging and live controlled destination infrastructure. |
| Account/privacy/subscription lifecycle | Trusted devices, recovery rotation, sign-out/deletion/export, Family lifecycle, billing-verifier interfaces and idempotent entitlement ledger | Real merchant/store activation and production receipt verification. |
| Accessibility/localization/safety | Landmarks/labels/focus/live status/tables/contrast/reduced motion/forced colors/narrow layout, strict catalog/fallback and contextual safety education | Owner screen-reader/keyboard/200%/400% zoom/high-contrast review and professional translations. |
| Privacy-safe operations/support | Fixed-scope local support bundle, protected operations metrics, incident controls, key separation and recovery/rotation runbooks | Deployed alert/on-call pipeline and operator-specific contacts/legal notices. |
| Regression Vault/provider compatibility | Sanitized approved sample controls, five-provider fixtures, adversarial consumer scenarios and release-gate execution | Ongoing reviewed sample intake and owned live-provider matrix. |
| Cost/capacity/deployment | Executable budgets, 10,000-client production-path stress, low-heap background smoke and deployment sizing/runbooks | Production-shaped load/cost/backup-recovery proof on selected infrastructure. |
| Consumer first-run / zero-confusion dashboard | Eight-step setup now requires real account/mailbox presence, completed scan, successful sensitivity save and enabled continuous protection; Family is explicit optional choice; local Scam Check remains usable before connection | Owner browser acceptance on the frozen release candidate. |

## Final pre-app decision

A repository release candidate is eligible for owner/external acceptance only when the **unchanged literal PR head SHA** passes the Engineering Gate on Windows, macOS and Ubuntu. Pull-request CI must checkout `github.event.pull_request.head.sha`, assert `git rev-parse HEAD` equals that SHA, and then pass typecheck, production build, portable-core/provider vectors, Regression Vault, capacity, public-document checks, unit/integration/corpus suites, browser wiring, compiled services/background smokes, portable package verification, signed release lifecycle and dependency audits.

PR #73 is the final pre-native closure branch. It remains unmerged until that literal-head gate is green and the owner completes the generated visible/destructive/recovery acceptance checklist. If acceptance finds a reproducible defect, reproduce it, add regression coverage where technically possible, fix the root cause, rerun the complete exact-head gate, and repeat the failed owner/external check.
