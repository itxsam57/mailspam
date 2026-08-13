# Final Milestone Status Ledger

This is the live code-status ledger for PR #73. The acceptance authority is `docs/FINAL_CONSUMER_COMPLETION_MILESTONE.md`.

`IMPLEMENTED` means production-path repository code exists and blocking automated coverage exists. It does **not** mean a provider, operating-system, store, deployment, signing-key or owner-visible external acceptance step has been simulated or waived.

| Workstream | Repository state | Evidence boundary |
|---|---|---|
| A — Near-real-time inbound protection | IMPLEMENTED | Replay-safe encrypted event state, provider source normalization, serialized protection execution, family parity and realtime service/processor regressions. |
| B — Check Anything | IMPLEMENTED | Message, URL, `.eml`, PNG/JPEG, QR and local visual-text bridge converge on deterministic analysis with bounded inputs. |
| C — Explainability and safe action | IMPLEMENTED | Consumer explanation contract, provenance, limitations and independently sourced verification guidance are wired to Check Anything and protection surfaces. |
| D — Protection sensitivity | IMPLEMENTED | High Protection, Balanced and Low Noise profiles exist with invariant tests proving hard threats cannot be downgraded. |
| E — Family Guardian / trusted assistance | IMPLEMENTED | Privacy-safe family summary/preferences, high-risk categories, explicit trusted-assistance packet, revocation/ownership controls and Family-vs-global consensus separation. |
| F — Campaign radar | IMPLEMENTED | Verified community trend/rate intelligence and consumer Family radar UI with fail-closed unavailable state. |
| G — Inbox Health and cleanup | IMPLEMENTED | Subscription inventory, safe unsubscribe/catch-trash foundations, bounded explicit cleanup, local rules, activity and provider-safe Undo. |
| H — Mailbox Health | IMPLEMENTED | Provider-capability compromise indicators and spam-bomb/security-alert checks report unsupported checks as unavailable, never safe. |
| I — Browser/link defense | IMPLEMENTED | Explicit local URL verdict contract, hardened destination analysis, DNS-pinned transport and privacy-minimal future bridge. |
| J — Mobile scam-channel contracts | IMPLEMENTED | SMS, notification, share-sheet, explicit clipboard, calendar and QR contracts with permission minimization and generic notification payload policy. |
| K — Remote-access/payment-risk intervention | IMPLEMENTED | Local behavioral combination contract covers remote-support, transfer/crypto/gift-card pressure and callback verification guidance without endpoint surveillance claims. |
| L — Attachment/malware expansion | IMPLEMENTED | MIME/type/hash/QR, magic mismatch, executable/script policy, bounded archive/decompression/nesting/password-protection handling and signed known-bad hash support. |
| M — Identity exposure | IMPLEMENTED | Explicit-consent privacy-preserving prefix lookup interfaces for email/password exposure with no plaintext password upload. |
| N — Account/privacy/subscription lifecycle | IMPLEMENTED | Device/recovery/sign-out/deletion/export/family lifecycle plus billing verification interfaces, idempotent event ledger, entitlement states and production development-switch boundary. |
| O — Notifications/activity/undo/recovery | IMPLEMENTED | Unified privacy-safe local activity, generic notification policy and provider-capability-gated reversible actions. |
| P — Personalization safety | IMPLEMENTED | Account-local relationship history remains evidence rather than trust; explicit feedback, drift/takeover handling and reset/export controls are bounded and private. |
| Q — Consumer onboarding/dashboard | IMPLEMENTED | Canonical eight-step first-run journey requires observed account/mailbox/scan/continuous-protection state, explicit successful sensitivity save, permission review and Family decision before Home completion. Local Scam Check remains available before connection. |
| R — Accessibility/localization/safety education | IMPLEMENTED | Keyboard/focus/ARIA structure, narrow layout, forced colors, reduced motion, strict localization catalog and contextual safety education have blocking source/regression coverage. Owner assistive-technology review remains external. |
| S — Privacy-safe support diagnostics | IMPLEMENTED | User-exported fixed-scope support bundle excludes credentials, tokens, subjects, sender addresses, raw URLs, Family private data and device secrets. |
| T — Production service readiness | IMPLEMENTED | Configuration validation, gateway/reputation hooks, metrics, key separation/rotation/recovery runbooks and incident kill switches preserve local scanning. DNS/TLS/cloud deployment remains external. |
| U — Competitive Regression Vault / red team | IMPLEMENTED | Adversarial scenario coverage includes calendar, download/extension lure, polished phishing, multilingual scams, known-contact takeover, BEC and image-only phishing plus the five-provider corpus/Vault. |
| V — Release economics/plan packaging | IMPLEMENTED | Free/Individual/Family entitlement architecture and bounded local/network service boundaries exist without hardcoded commercial prices. |
| W — Final pre-app acceptance | ENGINEERING COMPLETE / OWNER ACCEPTANCE OPEN | Literal-head Engineering Gate #675 passed Windows, macOS and Ubuntu on `59e122d940effa6d5287204bda6741a929401807`. The final documentation-only freeze must receive the same literal-head gate before handoff; owner visible/destructive/recovery acceptance remains the only milestone-closing action after that. |
| Native Windows/macOS/Android/iOS wrapping | AFTER THIS MILESTONE | Native shells, store packaging/signing/background entitlements and distribution acceptance intentionally begin only after W owner acceptance closes. |

## Closure evidence

The final branch repeatedly passed the full Engineering Gate during implementation. Integration Gate #665 passed Windows, macOS and Ubuntu and exercised the complete gate, but it exposed a process defect: ordinary pull-request checkout had tested GitHub's synthetic merge ref rather than the literal PR head. PR #73 repaired that ownership boundary. Pull-request jobs now explicitly checkout `github.event.pull_request.head.sha` and assert `git rev-parse HEAD` equals the expected immutable SHA before any gate work begins.

The first full gate after that repair, Gate #675, passed all three operating systems and the combined summary on exact branch head `59e122d940effa6d5287204bda6741a929401807`. It includes strict typecheck, production build, portable-core and five-provider vectors, provider compatibility, Regression Vault, capacity/public-doc gates, unit/API/regression and integration/corpus suites, browser source/privacy wiring, compiled desktop/community/account/background smokes, portable package verification, signed release lifecycle and dependency audits.

## Formal completion rule

Repository-buildable feature scope A–V is code-complete and automated engineering acceptance is green. Because this ledger itself records that result, its final documentation-only commit must pass the same immutable three-OS gate before owner handoff. Formal milestone closure then requires the owner to complete the visible/destructive/recovery checklist against that frozen release candidate. External provider/deployment/store/native acceptance cannot be converted into a repository PASS by simulation.
