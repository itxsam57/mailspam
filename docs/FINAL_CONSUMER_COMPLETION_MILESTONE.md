# Email Shield — Final Consumer Completion Milestone

Status: ACTIVE
Branch: `milestone/final-consumer-completion`
Base accepted main: `e16a55d43a8ac6ab17f0758d08a5f2ff51dfb96d`

## Authority and goal

This is the final product-engineering milestone before Email Shield is wrapped into native Windows, macOS, Android and iOS applications.

The milestone is intentionally broad: it closes every remaining repository-buildable consumer-product gap, recovers useful previously planned features, and incorporates publicly observable competitor product patterns only where they can be implemented independently without copying proprietary code, trade secrets, branding or protected assets.

The product remains local-first. Mailbox bodies, private conversations, credentials, device secrets and personal relationship history must not become centralized product telemetry. Remote services may receive only narrowly scoped, privacy-reduced data necessary for account entitlement, explicit user-submitted checks, signed threat intelligence, abuse prevention or other separately consented features.

Native application wrapping is the acceptance boundary after this milestone, not part of this milestone's feature implementation.

## Non-negotiable product promise

Email Shield protects the user and the people they care about from scams across email and adjacent scam channels while keeping private communications private.

Every feature must preserve:

- provider neutrality;
- local-first content processing;
- deterministic security evidence as the authoritative protection layer;
- explicit, reversible user actions where safe;
- privacy-reduced community/family intelligence;
- native secret custody;
- bounded CPU, memory, network and storage use;
- explainable verdicts;
- fail-closed trust boundaries;
- exact-head Windows/macOS/Linux engineering gates;
- no silent conversion of external/live acceptance into a simulated PASS.

## Scope: one final milestone

### Workstream A — Near-real-time inbound protection

Build event-driven or near-real-time protection above the existing scheduled background scanner.

Required outcomes:

- Gmail push/change notification adapter where provider capabilities permit it.
- Microsoft Graph change-notification adapter where provider capabilities permit it.
- IMAP IDLE support where the server and provider permit reliable use.
- Bounded polling fallback when push/IDLE is unavailable.
- Provider event normalization into one canonical inbound-message event.
- Deduplication, restart recovery, bounded backlog and replay protection.
- Immediate evaluation through the same portable detection pipeline used by manual scans.
- Configurable action mode: notify only, quarantine/spam for suspicious, trash only for sufficiently hard locally confirmed/cryptographically trusted threat states according to locked protection semantics.
- Family threat policy parity and manual-scan priority.
- Privacy-safe desktop/mobile notification contract.
- Scheduled protection remains a fallback safety net.

Acceptance: deterministic fixtures plus provider-capability contract tests, restart/replay tests, duplicate-event tests, burst tests and compiled runtime smoke.

### Workstream B — Consumer Scam Check / “Check Anything”

Create one portable local-first analysis surface that accepts suspicious material outside a connected mailbox.

Inputs:

- pasted email/message text;
- URL;
- copied sender/domain;
- screenshot/image;
- QR code image;
- email file (`.eml`) where available;
- selected text shared from another app through future native bridges.

The engine must normalize these into bounded evidence and reuse existing identity, message-intent, link, destination, QR, brand-impersonation and global-intelligence layers wherever technically applicable.

Add a local explanation result containing:

- verdict;
- confidence band, without fabricated precision;
- scam category;
- strongest supporting signals;
- strongest contradictory/safety signals;
- safe next action;
- explicit warning when evidence is insufficient.

Optional AI/language-model explanations may be added later as a non-authoritative presentation layer only. They may not override deterministic security evidence, and cloud inference requires separate explicit consent and redaction architecture.

Acceptance: adversarial text/link/image/QR corpus, malformed-input limits, offline behavior and privacy gate.

### Workstream C — Explainability and safe-action guidance

Turn every significant verdict into consumer-readable evidence.

Required:

- “Why this was flagged” card;
- plain-language sender/authentication/domain/link/attachment/community/family explanation;
- safe verification guidance using independently obtained official channels rather than suspicious message links/numbers;
- “What should I do?” actions;
- distinction between suspicious, warning and confirmed threat;
- reason provenance so UI wording cannot imply a signal was observed when it was inferred or unavailable;
- accessibility-safe wording and localization keys.

No explanation may reveal family members’ mailbox contents or community reporter identities.

### Workstream D — Protection sensitivity and automation controls

Introduce consumer protection profiles without creating bypasses for hard security failures.

Profiles:

- High Protection;
- Balanced (default);
- Low Noise.

Profiles may change treatment of soft/ambiguous evidence and notification thresholds, but cannot suppress hard authentication contradictions, confirmed signed threat intelligence, explicit personal blocks or other locked hard-threat states.

Allow per-account overrides and Family Shield owner defaults while preserving adult member autonomy where required.

Acceptance: invariant tests proving sensitivity cannot downgrade hard threats.

### Workstream E — Family Guardian / trusted-person assistance

Complete Family Shield as a consumer safety system, not just a shared threat feed.

Required:

- privacy-preserving family activity summary;
- configurable high-risk category alerts (banking, crypto/investment, gift cards, government/legal, delivery/payment, romance, job/task, remote-access/refund/support and account takeover patterns);
- “Ask a trusted person” flow that shares a specific suspicious item only after explicit user consent;
- family member cannot browse another member’s mailbox/history by default;
- optional vulnerable-member protection profile with clear consent and emergency disable/recovery path;
- family warning vs confirmed semantics remain separate from global community consensus;
- one member’s report may protect the family immediately but may not independently create a global confirmed threat;
- revoke member/device/invite immediately invalidates family authorization.

### Workstream F — Scam-wave / regional campaign radar

Build privacy-safe proactive campaign warnings inspired by the useful behavior of scam-radar products without centralizing private inbox content.

Required:

- aggregate privacy-reduced campaign fingerprints;
- region only at coarse user-selected level and optional;
- emerging campaign detection based on independent reporters, novelty and rate change;
- signed campaign-advisory feed;
- example warning patterns generated from sanitized templates, never reconstructed private messages;
- actionable “what scammers are asking people to do” guidance;
- no precise user location requirement;
- no raw mailbox content in campaign telemetry.

### Workstream G — Inbox Health and safe cleanup

Expand the existing unsubscribe/block infrastructure into a consumer value layer.

Required:

- subscription/newsletter inventory;
- bulk unsubscribe with existing RFC 8058-safe path preferred;
- catch-and-trash rule after an unsubscribe request when a sender continues mailing and the user explicitly enables it;
- pause/mute/read-later style local rules;
- bulk cleanup by sender/category/age with destructive-action confirmation;
- sender/domain screening for previously unseen senders as an optional mode, not default quarantine for all users;
- separate trusted-contact/relationship context from an unconditional allowlist;
- activity history and undo where the provider action can be safely reversed;
- “keep newest” type cleanup only for explicitly selected low-risk categories;
- mailbox storage/volume summary from provider metadata where available without uploading content.

### Workstream H — Mailbox Health / compromise indicators

Add provider-capability-driven account-compromise checks where APIs expose reliable data.

Potential checks, gated by provider support and least privilege:

- suspicious or newly created forwarding rules;
- suspicious inbox/filter rules;
- unexpected delegates/send-as identities;
- provider security-alert messages recognized through deterministic trusted-provider identity rules;
- suspicious auto-delete/redirect behavior;
- unexpected connected-app/session indicators only where official provider APIs expose them safely.

Email Shield must never claim a mailbox compromise solely from an email-content heuristic. Unsupported provider checks must be shown as unavailable, not silently treated as safe.

### Workstream I — Browser and link defense foundation

Prepare a local-first web protection service and future browser-extension/native-web-filter contract.

Required:

- local URL verdict API backed by existing hardened destination analysis and signed threat intelligence;
- real-time block/warn response contract;
- phishing/typosquat/redirect-chain/destination-risk reasoning;
- download URL/filename/type risk handoff contract;
- future extension bridge must send minimal URL/security context and never browsing history by default;
- no passive cloud browsing telemetry;
- optional explicit site-report action with privacy-reduced fingerprinting.

The actual store-distributed browser extension may be packaged after the core contract is accepted, but the engine/API and tests belong here.

### Workstream J — Mobile scam-channel protection contracts

Before native shells, complete the engine contracts required for Android/iOS:

- SMS/text analysis;
- Android notification text/link analysis;
- iOS SMS filtering classifier contract within platform constraints;
- shared-content/share-sheet analysis;
- clipboard analysis only on explicit user action;
- calendar-invite URL/scam analysis where platform permission is granted;
- QR scan from camera/image;
- push notification payloads containing no private message body by default;
- strict permission minimization and per-feature consent.

### Workstream K — Remote-access / payment-risk intervention signals

Add scam-prevention warnings for high-risk behavioral combinations without pretending Email Shield is a banking or endpoint-EDR product.

Where the future native platform can reliably expose signals, define contracts for:

- remote-access software active while a financial scam pattern is present;
- suspicious message asking to install remote support software;
- gift-card/crypto/bank-transfer urgency plus impersonation evidence;
- call-back phone-number extraction and warning to verify through independently sourced official channels.

Desktop implementation may detect only locally available process/application state through a narrowly scoped native bridge. No broad process inventory may be uploaded.

### Workstream L — Attachment and malware defense expansion

Strengthen the existing MIME/type/hash/QR attachment layer.

Required:

- archive container inspection with strict decompression limits;
- executable/script/macro-capable type policy;
- extension-vs-magic mismatch;
- nested attachment depth limits;
- encrypted/password-protected archive risk indication;
- known-bad hash feed support through signed intelligence;
- optional local static analysis modules where practical;
- explicit privacy architecture before any cloud sandbox integration;
- attachment quarantine/removal action only where provider capability allows safe deterministic behavior.

### Workstream M — Identity exposure and credential-risk features

Add low-cost consumer identity-security value without turning Email Shield into a data-broker surveillance company.

Required foundation:

- local breach-check workflow using k-anonymity or other privacy-preserving lookup where a vetted public/provider API permits it;
- credential-compromise warning contract without uploading plaintext passwords;
- email-address breach exposure checks only after explicit user opt-in;
- family member exposure summary without revealing unnecessary breach details to other members;
- recovery guidance and direct links only to independently verified official services.

Credit monitoring, insurance and financial-account surveillance are deliberately outside the core unless a future regulated partner is added; they are not required for Email Shield consumer completion.

### Workstream N — Account, privacy and subscription lifecycle completion

Finish the consumer account service around the foundation already merged.

Required:

- trusted-device list and revoke;
- recovery-code rotation;
- lost-device recovery;
- sign-out everywhere;
- explicit account deletion;
- delete family/circle;
- leave family;
- export privacy-safe account metadata;
- clear local scan/history/personal-learning data independently;
- remote account deletion must not require uploading local mailbox data;
- plan entitlement cache with expiry/fail-safe semantics;
- real billing verifier interfaces for Apple, Google and web billing;
- receipt/subscription event idempotency;
- grace period, cancellation and restore-purchase states;
- family seat limits and transfer rules;
- no development entitlement switch in production builds.

Actual store/web merchant activation remains an external launch gate.

### Workstream O — Notifications, activity, undo and recovery

Create one consumer-facing protection activity model across manual, background, event-driven, family and community actions.

Required:

- protected/flagged/quarantined/reported/blocked/unsubscribed history;
- generic notification content by default;
- optional richer local-only notification preview;
- reversible actions surfaced as Undo only when reversal is technically valid;
- false-positive/report-safe feedback;
- explain what changed and why;
- restore-from-trash/spam where provider support and retention allow;
- never promise recovery after provider deletion retention has elapsed.

### Workstream P — Personalization and relationship learning safety

Complete adaptive protection without creating dangerous permanent trust.

Required:

- relationship history remains evidence, never an allowlist;
- explicit “this is safe / this is scam” feedback;
- decaying behavioral confidence;
- sender-pattern drift detection;
- compromised-known-contact handling;
- local-only personal learning by default;
- export/reset controls;
- family learning is not silently shared across members.

### Workstream Q — Consumer onboarding and zero-confusion dashboard

Rebuild the consumer flow around outcomes, not internal architecture.

Required first-run sequence:

1. Create or sign in to Email Shield account, with a local-only mode available where feasible.
2. Connect mailbox(es).
3. Explain exactly what permissions are requested and why.
4. Run first protection scan.
5. Choose Balanced/High/Low Noise profile.
6. Configure background/real-time protection.
7. Optionally create/join Family Shield.
8. Show one simple protection-status home screen.

Home must answer:

- Am I protected?
- What happened recently?
- Is anything waiting for me?
- Are my family members protected?
- Are any permissions/connections broken?

Advanced operations/debug information stays out of the primary consumer navigation.

### Workstream R — Accessibility, localization and consumer safety education completion

Required:

- keyboard-only acceptance;
- screen-reader acceptance;
- 200%/400% zoom and narrow layout acceptance;
- high contrast/forced colors;
- reduced motion;
- professional localization-ready catalog with no security meaning encoded only by color;
- scam-safety education linked contextually to detected scam category;
- trusted-person verification guidance;
- no shame/blame language for scam victims.

Professional translations remain external content work, but the product architecture and testable layout must be complete.

### Workstream S — Support and diagnostics without surveillance

Add a privacy-reviewed support bundle users can export themselves.

May contain:

- app/core version;
- OS/runtime version;
- provider adapter type;
- generic error codes;
- permission/connection status;
- gate/release identifier;
- aggregate scan/action counts;
- service health state.

Must not contain credentials, access/refresh tokens, mailbox bodies, subject lines, private sender addresses, family private data, raw URLs or device private keys.

### Workstream T — Production community/account infrastructure readiness

Close repository-buildable parts needed before external deployment:

- account-service deployment configuration validation;
- community-service gateway integration contract;
- enrollment/reporter reputation hooks;
- rate/DDoS boundary documentation;
- signed-key rotation runbooks;
- backup/restore drills executable against staging;
- privacy-safe metrics/alerts;
- separate account/community signing and storage keys;
- tenant/environment separation;
- no production secret defaults;
- incident kill switches for community feed, link analysis and account sync without disabling local scanning.

External DNS/TLS/cloud deployment and key ceremony remain acceptance steps after code completion.

### Workstream U — Competitive regression corpus and red-team expansion

Expand the Regression Vault around product behaviors publicly offered by major competitors while independently implementing our own detection logic.

Required scenario families:

- full-context message scams where links alone look benign;
- QR/quishing;
- hidden/cloaked redirects;
- support/refund callback scams;
- known-contact account takeover;
- business email compromise;
- romance/gift-card/crypto/investment/job/task scams;
- malicious calendar invites;
- fake shopping/storefront/fake-review indicators where sufficient evidence is locally observable;
- malicious browser-extension/download lure text;
- remote-access/social-engineering sequences;
- spam-bomb/security-alert hiding patterns;
- AI-written low-grammar-error phishing;
- image-only phishing;
- multilingual scam language vectors;
- adversarial legitimate controls for every class.

No competitor proprietary detection corpus or private test assets may be copied.

### Workstream V — Release economics and plan packaging

Keep the product inexpensive by placing expensive network/cloud work behind bounded, cacheable and privacy-safe services while preserving useful free/local capabilities.

Target packaging architecture:

- Free: local manual Scam Check, limited mailbox scan/protection, core explainability and basic community warnings.
- Individual: continuous mailbox protection, multi-mailbox, advanced cleanup, browser/link defense, advanced threat intelligence and full activity controls.
- Family: Individual features plus Family Shield, trusted-person assistance, family campaign alerts and family seat/device management.

Final prices are a commercial decision and are not hardcoded into the engine.

### Workstream W — Final pre-app acceptance gate

This milestone is complete only when:

- every repository-buildable workstream above has real production-path code or is explicitly documented as platform-only/external with no false completion claim;
- unchanged exact-head Engineering Gate passes Windows, macOS and Ubuntu;
- deterministic adversarial corpus and Regression Vault pass;
- privacy contract tests pass;
- low-memory/background/event burst tests pass;
- account/family cross-device service smoke passes;
- browser/mobile bridge contracts pass;
- release package verifies;
- dependency audit reports no blocking advisory;
- manual owner acceptance checklist covers the consumer UI and all destructive/recovery paths;
- canonical reconciliation is updated line by line.

Only after this gate is green does the project move to native application wrapping and store/distribution acceptance.

## Competitive behaviors deliberately absorbed

Publicly documented market behaviors worth independently implementing include:

- real-time phishing/email alerts and mailbox labels;
- safe-browsing/link blocking before page load;
- text/SMS and notification scam analysis;
- on-demand analysis of messages, screenshots, links and QR codes;
- explanation of why content was flagged;
- adjustable protection sensitivity;
- proactive emerging-scam/campaign alerts;
- family-oriented protection and protected-device management;
- mailbox/newsletter cleanup, screening and activity history;
- account/breach exposure warnings;
- remote-access plus financial-scam intervention signals;
- local/on-device processing wherever practical.

These are product behaviors, not copied implementations. Email Shield's implementation must remain independently engineered around its existing portable deterministic engine and local-first privacy model.

## Explicit exclusions before native app wrapping

The following are not required to complete this code milestone because they depend on native packaging, regulated services or external commercial operations:

- production App Store / Play Store publication;
- Authenticode / Apple Developer ID notarization ceremonies;
- production merchant activation and tax handling;
- credit bureau monitoring;
- identity-theft insurance underwriting;
- staffed 24/7 human support;
- proprietary dark-web datasets requiring a commercial data license;
- copying competitor source code, models, private APIs, private test corpora or trade secrets.

Where a later partner can provide one of these safely, it must be integrated behind a separately reviewed adapter and consent boundary.

## Engineering order inside this single milestone

The milestone remains one milestone but is executed in dependency order:

1. canonical final-gap/feature registry and invariant tests;
2. near-real-time inbound event architecture;
3. Check Anything + explainability + sensitivity profiles;
4. Family Guardian + campaign radar;
5. Inbox Health + Mailbox Health;
6. browser/link-defense core and mobile scam-channel contracts;
7. attachment/malware expansion and high-risk intervention contracts;
8. account/privacy/billing lifecycle completion;
9. notifications/activity/undo/personal-learning completion;
10. consumer onboarding/dashboard/accessibility/localization/support bundle;
11. production account/community infrastructure readiness;
12. competitive Regression Vault expansion, performance/privacy/security closure and final exact-head acceptance.

No substep may bypass the full milestone invariants to make a demo appear complete.
