# Three-Milestone Final Engineering Reconciliation

Date: 2026-08-11  
Authority: `Email_Shield_Three_Milestone_Engineering_Feature_Workflow_Specification.docx` v1.0

This record separates code completion from owner, provider, deployment and platform acceptance. “Green” repository evidence never substitutes for a real external gate.

## Outcome

| Milestone | Repository implementation | Formal status | What prevents formal closure |
|---|---|---|---|
| 1 — cross-adapter protection core | Complete and regression locked | **CLOSED** | None; closure evidence is `docs/MILESTONE_1_CLOSURE.md` |
| 2 — community intelligence and hardening | Every repository-buildable canonical row is implemented | **CODE-COMPLETE / EXTERNAL ACCEPTANCE OPEN** | GAP-001/002/004/005/008 and required owner-visible items |
| 3 — release-ready cross-platform continuous product | Release lifecycle, desktop scheduling, portable core, account isolation, accessibility/localization foundation, operations, Regression Vault, provider gates and public/capacity documentation are implemented | **PARTIAL** | Android/iOS mailbox application shells are not implemented; native distribution/background/store and owner accessibility/provider/deployment acceptance remain external |

The project must not be described as all three milestones formally closed. The remaining mobile shells are real product code, not an external ceremony. The other open items require identities, infrastructure, devices, provider accounts or subjective owner review unavailable to repository CI.

## Milestone 2 external acceptance

- GAP-001: publish/verify the production Google OAuth application and consent surface.
- GAP-002: complete controlled real-Outlook connect/scan/action/disconnect/reconnect acceptance.
- GAP-004: deploy the public community service with DNS/TLS, persistent storage, monitoring, backup/restore and a real signing-key overlap/switchover/retirement ceremony.
- GAP-005: validate Analyze Links against deliberately controlled public destination/redirect/DNS infrastructure.
- GAP-008: deploy and prove gateway enrollment/reputation/rate/DDoS controls.
- Complete the visible/manual register without recording credentials, mailbox bodies or private provider identifiers.

## Milestone 3 canonical row reconciliation

| Canonical row | Repository evidence | Remaining gate |
|---|---|---|
| Production installers/releases/update/rollback | Reproducible portable packages; exact Ed25519 envelope; pinned overlap trust; verified install/newer update/atomic activation/repair/one-step rollback/guarded uninstall | native MSI/PKG/DMG wrapping, production key custody, Authenticode/Developer ID/notarization/distribution acceptance |
| Scheduled background protection | encrypted per-account schedules; one bounded Worker; manual priority; progress/deadline/backoff; protected UI/API; low-heap compiled smoke | Windows/macOS OS background/notification behavior and owner acceptance |
| Windows/macOS/Android/iOS shared engine | schema-v1 I/O-free portable core, desktop routing and exact all-provider/adversarial JSON vectors | actual Android/iOS acquisition/storage/scheduling/action/UI shells and native corpus execution are missing |
| Multi-account policy parity | account-keyed policies/history/schedules/actions; scan conflict isolation; disconnect schedule cleanup | owner multi-account review on production platform clients |
| Accessibility/localization/safety | landmarks/labels/focus/live status/tables/contrast/reduced motion/forced colors/narrow layout; strict catalog/English fallback/Intl; safety guide | owner assistive-technology/zoom/high-contrast review and professional translations |
| Privacy-safe operations | protected no-store fixed-cardinality adapter/scan/feed/background/review dashboard plus bearer-protected community metrics | deployed alert/on-call pipeline is GAP-004 |
| Regression Vault | attested sanitization, exact-digest role approval, provenance/dedupe/hash/privacy validation and all-five-provider release gate | ongoing reviewed sample intake is an operational process |
| Provider compatibility | versioned five-provider capability snapshot plus executable fixture contract; release signing reruns it | live provider compatibility matrix needs owned accounts/devices |
| Public privacy/security/threat/incident documents | root public documents with data flows, disclosure, threats/residual risk and incident playbooks; documentation gate | operator-specific contacts/legal notices must be supplied by each deployment |
| Cost/capacity/deployment | runtime-owned executable budgets/cost worksheet, 10,000-reporter production-path test, low-heap background smoke, sizing/alert/deployment runbook | production-shaped load/cost/recovery evidence on the selected infrastructure |

## Release decision

A repository release candidate is eligible for owner/external acceptance only when the unchanged exact-head Engineering Gate passes on Windows, macOS and Ubuntu, the Regression Vault/provider/capacity/documentation gates pass, the host package and signed lifecycle verify, and no blocking advisory exists. Production publication additionally requires every applicable external gate above.

If any acceptance step finds a reproducible defect, the affected milestone returns to engineering: reproduce, add a regression where technically possible, fix the root cause, run the complete exact-head gate, then repeat the failed external check.
