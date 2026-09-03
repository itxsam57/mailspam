# Masterplan(Email Shield)

**Status:** CANONICAL CONTINUOUS PRODUCT + ENGINEERING BLUEPRINT  
**Project:** Email Shield  
**Repository:** `itxsam57/mailspam`  
**Canonical branch:** `main`  
**Established:** 2026-09-03  

> This document is the continuous backbone of Email Shield. It defines what the product is, what it must become, what it must never become, the security and privacy boundaries that cannot be weakened, the accepted feature set, the native/platform direction, the external acceptance boundaries, and the engineering process required to evolve it safely.
>
> It is intentionally not a snapshot of one commit. Engineers and agents must resolve the current `main`, open work, regression register, test matrix and latest exact-head gate from the repository before changing code.

---

## 0. Authority, precedence and change constitution

### 0.1 Purpose

Email Shield accumulated product truth across an original three-milestone specification, owner decisions, live-mailbox findings, a security redesign, feature-specific engineering contracts, regression locks, later account/Family/subscription decisions, a final consumer-completion milestone, and accepted production-path repairs. This Masterplan reconciles those sources into one durable high-level authority.

It exists to prevent five failure modes:

1. a future engineer reviving an obsolete requirement because an old document still exists;
2. a new feature silently weakening a security or privacy invariant;
3. green unit/CI code being mistaken for a working real consumer workflow;
4. native clients, provider adapters or new channels forking into separate weaker security engines;
5. project direction being changed by implementation convenience rather than an explicit owner decision.

### 0.2 Precedence when sources conflict

Use this order, from highest to lowest:

1. **A later explicit owner-approved product decision.** Product direction changes only by explicit owner decision, not inference.
2. **This `Masterplan(Email Shield)`.** It is the canonical high-level product/build authority after its accepted merge.
3. **Current locked security/regression contracts on accepted `main`** — especially `.engineering/REGRESSION_REGISTER.md`, `.engineering/TEST_MATRIX.md`, `.engineering/FINAL_CONSUMER_MILESTONE_INVARIANTS.md`, and feature-specific `.engineering/*.md` contracts. These are the executable proof layer and may strengthen the Masterplan.
4. **Accepted production implementation on current `main` plus its qualifying tests.** When prose is stale, current locked behavior is evidence of an accepted supersession.
5. **Current reconciliation/status documents** such as `docs/THREE_MILESTONE_FINAL_RECONCILIATION.md`, `.engineering/CANONICAL_ROADMAP_GAP_AUDIT.md`, `README_REBUILD_STATUS.md`, and final milestone ledgers.
6. **Supporting architecture/research documents.** They inform implementation but cannot silently override a later accepted rule.
7. **Historical plans, superseded branches, old PR descriptions, old screenshots and old milestone percentages.** They are provenance only.

If two current sources still genuinely conflict, **do not guess**. Preserve the safer existing production behavior, record the conflict, and require an explicit owner decision before changing semantics.

### 0.3 What this document is not

This file does not replace the Regression Register, Test Matrix, threat model, privacy policy, incident response plan or feature-specific security contracts. It tells engineers **what must remain true**; those lower-level artifacts tell them **how the repository proves it remains true**.

A change to a lower-level constant, score, timeout, provider limit or implementation technique does not require rewriting the Masterplan unless it changes product semantics, security/privacy posture, consumer behavior, accepted scope or an acceptance boundary.

### 0.4 Status vocabulary

- **LOCKED / IMPLEMENTED** — accepted production-path repository behavior with blocking regression evidence.
- **EXTERNAL ACCEPTANCE** — repository support exists, but the claim requires a real provider, public infrastructure, signing identity, merchant/store, operator or owner environment.
- **NATIVE / PLATFORM** — shared contracts exist or are required, but implementation/acceptance depends on Windows/macOS/Android/iOS native surfaces.
- **FUTURE APPROVED** — explicitly approved product direction that must be implemented when its dependency boundary is reached; it is not permission to weaken current behavior.
- **HISTORICAL / SUPERSEDED** — useful provenance but not current product authority.

No simulated fixture, mock provider, green unit test, local self-signed service or old successful workflow may be relabeled as an external/live PASS.

---

# Part I — Product constitution

## 1. North-star product

Email Shield is a **privacy-first personal and family scam-protection layer**, not merely an inbox scanner.

It protects people across connected email accounts and user-submitted suspicious content, explains why something is risky, helps the user take the correct action safely, shares only privacy-reduced threat intelligence where explicitly allowed, and evolves toward native desktop/mobile/browser scam protection without turning private communications into centralized surveillance.

A finished consumer should be able to answer these five questions without understanding the detection engine:

1. **Am I protected right now?**
2. **What did Email Shield stop, flag or change?**
3. **Why was it dangerous or why is it uncertain?**
4. **What should I do next?**
5. **Are the people I protect also safe?**

The product succeeds only when these answers are backed by production-path behavior, not demo UI.

## 2. Permanent product principles

Every current and future Email Shield surface must preserve:

- provider neutrality;
- local-first/private-by-default content processing;
- deterministic security evidence as the authoritative protection layer;
- one shared security meaning across providers and platforms;
- explicit evidence provenance;
- earned Safe verdicts rather than optimistic Safe defaults;
- fail-closed trust boundaries;
- privacy-reduced community, Family, telemetry and support schemas;
- native operating-system secret custody wherever persistent secrets are supported;
- account isolation and exact action ownership;
- bounded CPU, memory, network, storage and provider usage;
- consumer-readable explainability;
- explicit and reversible user actions where reversal is technically safe;
- truthful representation of unsupported or incomplete capabilities;
- root-cause engineering rather than symptom patches;
- exact-head cross-platform qualification before acceptance;
- real owner/provider/deployment acceptance wherever code cannot prove the real workflow.

When convenience and security conflict, **secure behavior wins and the UI explains the limitation**.

## 3. Privacy constitution

### 3.1 Local by default

Raw mailbox bodies, HTML, private conversations, contacts, relationship history, mailbox credentials, OAuth tokens, app passwords, device private keys, raw provider message IDs, raw unsubscribe targets and private browsing history must not become centralized product telemetry or community data.

The normal security pipeline processes mailbox content locally. A new feature may send data remotely only when:

1. the remote purpose is explicitly defined;
2. the minimum schema is documented;
3. private content is reduced or excluded wherever possible;
4. user consent is obtained when the feature is optional or content-bearing;
5. resource, authentication, abuse and retention boundaries are defined;
6. the remote service cannot silently become a generic telemetry escape hatch.

### 3.2 Remote data classes that are allowed when required

Remote services may receive narrowly scoped data for:

- account identity, trusted-device authentication and entitlement state;
- Family membership/invite state and privacy-reduced Family campaign intelligence;
- explicit user-submitted checks that require a separately approved remote capability;
- privacy-reduced community/global threat reports;
- signed threat intelligence acquisition;
- abuse prevention, rate limiting and service health;
- opt-in technical reliability telemetry under a closed allowlist;
- merchant/store receipt verification;
- separately consented future services with their own privacy review.

They must never receive mailbox content merely because centralization is easier to engineer.

### 3.3 Technical telemetry

Technical telemetry is **opt-in, privacy-safe and closed-schema**. It must not use generic autocapture/session replay and must not contain mailbox/account identity, subjects, bodies, sender addresses, raw URLs, provider message IDs, credentials/tokens, raw exceptions or Family private content.

### 3.4 Support diagnostics

The user may export a support bundle containing bounded technical facts such as app/core version, OS/runtime version, provider adapter class, generic error/status codes, permission/connection state, release/gate identity and aggregate workflow counts. It must exclude private content and secrets.

---

# Part II — Shared security architecture

## 4. One canonical protection engine

Every supported mailbox/channel follows:

**acquisition adapter → bounded canonical evidence → shared deterministic protection core → explanation + verdict → capability-checked action policy**

No provider, native client, browser bridge, Check Anything surface or mobile feature may create an independent weaker verdict engine.

Provider/native code may acquire evidence differently because platform APIs differ, but the meaning of equivalent evidence must converge before security decisions.

## 5. Supported email providers and parity

The canonical provider set is:

1. Gmail
2. iCloud Mail
3. Outlook / Microsoft 365 consumer mail through Microsoft Graph/public-client OAuth where available
4. Yahoo Mail
5. Generic IMAP

Requirements:

- one canonical message/envelope contract;
- one verdict model;
- one personal-policy model;
- one community-report contract;
- one action-capability model;
- provider-specific code only where acquisition/action APIs differ;
- no provider-specific compiled brand/domain allowlist as the main detector;
- unsupported provider capabilities are reported as unavailable, never assumed safe;
- fixture parity is required, but real-provider acceptance remains separate.

### 5.1 Gmail

Guided Gmail connection uses Authorization Code + PKCE S256 with a random `127.0.0.1` loopback callback, strong state/nonce/replay boundaries, verified stable Google identity, protected refresh-token custody and explicit provider validation. Connection/revocation failures remain truthful. Public Google OAuth publication/approval is an external launch gate.

### 5.2 Outlook

Guided Outlook uses a Microsoft **public desktop client** with Authorization Code + PKCE S256 and the accepted least-privilege mailbox scopes. Browser/token exchange must not depend on a client secret. Stable mailbox identity comes from Graph identity, not the email string or refresh token. Real-Outlook connect/scan/action/disconnect/reconnect acceptance is required before Outlook can be represented as fully owner-accepted for ordinary consumers.

### 5.3 iCloud, Yahoo and generic IMAP

Long-lived app-password credentials use native credential custody where available and opaque references in persistent session state. If native persistent secret storage is unavailable, Email Shield must not silently fall back to plaintext persistence.

IMAP remains UID/UIDVALIDITY aware, cancellation-safe, bounded and selective. It must not solve inspection gaps by downloading unlimited full raw messages.

## 6. Evidence completeness and Safe-by-proof

The August 2026 live-mailbox security redesign is permanent product law.

### 6.1 Safe is earned

A message may be called Safe only when the engine has enough coherent evidence to justify that conclusion. The absence of detected danger is not automatically proof of safety.

A message with materially incomplete required inspection must not silently become Safe. When the engine cannot inspect a supported security-relevant component within its safety limits, the outcome must preserve uncertainty or risk appropriately.

### 6.2 Positive authentication is not legitimacy

SPF/DKIM/DMARC success may establish identity/alignment evidence; it does **not** establish that the sender or business intent is legitimate. Authenticated malicious or compromised accounts remain dangerous.

Only authentication results from a trusted acquisition/provenance boundary may influence authoritative trust or failure evidence. Unproven `Authentication-Results` headers cannot manufacture either Safe evidence or threat evidence.

### 6.3 Evidence-family independence

High-confidence Safe decisions must not be manufactured by multiple weak signals that all originate from one underlying assumption. Evidence families should be independently meaningful — identity/authentication, relationship/history, content/intent, destination/link behavior, attachment behavior, provider placement and trusted intelligence.

### 6.4 Hard security floors

Hard threat evidence, explicit personal blocks, sufficiently trusted signed intelligence, confirmed account-local protections, malware indicators and other locked hard states cannot be erased by:

- sensitivity settings;
- sender familiarity;
- a successful authentication mechanism alone;
- an optimistic provider placement;
- a previous Mark Safe on another message;
- Family/community convenience;
- an AI explanation.

### 6.5 Provider folder placement

Inbox/Spam/Junk placement is evidence, not a verdict. Suspicious provider placement can raise caution and prevent weak-positive Safe classification, but it cannot by itself justify irreversible malicious classification.

## 7. Canonical verdict model

- **Safe** — sufficient coherent evidence supports normal treatment.
- **Review** — meaningful uncertainty or suspicious evidence requires attention.
- **High Risk** — strong evidence suggests a scam/threat and the user should avoid interacting until independently verified.
- **Confirmed Threat** — hard local policy, sufficiently trusted reviewed/signed intelligence or other locked confirmation criteria are satisfied.
- **Unknown / incomplete** — evidence required for a reliable conclusion is unavailable or materially incomplete.

The UI may use consumer-friendly wording, but it must not blur these meanings.

No fabricated numeric confidence should imply precision the engine does not possess. Confidence bands may be used only when their semantics are defined and conservative.

## 8. Canonical detection/evidence families

### 8.1 Identity and authentication

- RFC5322.From identity and display-name/domain consistency;
- trusted SPF/DKIM/DMARC alignment and explicit failures;
- Public Suffix List-backed registrable-domain decisions;
- Unicode/confusable/IDN/domain deception;
- Reply-To divergence and changes;
- sender-domain and destination-domain relationship;
- official/private-relay handling without creating unrelated trust;
- known-contact compromise/drift handling;
- untrusted authentication-header provenance rejection.

### 8.2 Relationship and thread context

- account-local encrypted privacy-reduced relationship history;
- HMAC/fingerprint identities rather than a plaintext contact-history database;
- repeated authenticated benign history as context only;
- first-contact semantics preserved honestly;
- authentication downgrade;
- stable Reply-To changes;
- explicit RFC thread-reference continuity and mid-thread route anomalies;
- repeated suspicious history.

Relationship history is **evidence, never an allowlist and never automatic trust**.

### 8.3 Message intent / social engineering

The engine must recognize generalized scam intent families including:

- credential/password/MFA/recovery-code theft;
- OAuth/device-code/account-takeover lures;
- business email compromise and executive/vendor impersonation;
- invoice/payment/bank-transfer changes;
- gift-card pressure;
- crypto/investment/task scams;
- refund/support/remote-access callback scams;
- romance/private-photo/adult solicitation lures;
- fake job/recruitment/task-work offers;
- delivery/toll/customs/payment demands;
- government/legal/tax/police impersonation;
- prize/lottery/advance-fee scams;
- account/security-alert hiding and spam-bomb patterns;
- malicious cloud-document/share invitations;
- subscription/renewal deception;
- fake shopping/storefront/refund patterns where locally observable evidence is sufficient;
- extortion/threat patterns;
- urgent secrecy/authority pressure;
- unsafe channel-switch/bypass-verification requests;
- image-only or polished AI-written phishing where structural evidence still exists;
- multilingual variants of the same underlying scam behavior.

Intent detection must be generalized enough to catch unseen campaigns and conservative enough not to classify ordinary legitimate messages merely because they contain common words.

### 8.4 HTML and interaction structure

Canonical parsing includes bounded plain text and HTML interaction evidence, including links, accepted base-relative navigation, forms/form actions and relevant automatic redirects. Script/style text remains inert. Parser/resource limits fail closed to incomplete coverage rather than silently ignoring risk.

### 8.5 Links and destinations

Static link evidence includes URL/domain structure, encoded destinations, deceptive display-versus-target behavior, redirect/lure indicators, suspicious transport/destination structure and signed/global intelligence matches.

Network destination analysis is a separate **explicit user action**, not automatic mailbox crawling.

### 8.6 QR / quishing

Supported PNG/JPEG QR inspection is local/offline and strictly bounded. Only safe-to-normalize HTTP(S) destinations enter the canonical link pipeline with QR provenance. Raw QR image bytes and arbitrary non-URL payloads do not become browser/history/community data.

### 8.7 Attachments and malware

The attachment layer includes, where applicable:

- bounded exact SHA-256 intelligence;
- declared type/filename/extension consistency;
- Unicode/bidi filename deception;
- executable/script/macro-capable risk policy;
- extension-versus-magic mismatch;
- bounded local static malware behavior;
- archive-container inspection with strict decompression and nesting limits;
- encrypted/password-protected archive risk indication;
- known-bad hash intelligence through trusted signed feeds;
- provider-capability-aware quarantine/removal only when safe and supported.

No attachment-inspection feature may create an unlimited full-message download fallback.

## 9. Threat-intelligence hierarchy

Protection authority is deliberately layered:

1. **Immediate personal/account-local intelligence** — explicit user decisions and locally reported campaigns protect that account first.
2. **Private Family Shield intelligence** — privacy-reduced signals protect a Family circle according to Family semantics.
3. **Global/community intelligence** — privacy-reduced independent reporting, anti-brigading logic, human review/reputation controls and signed publication protect unrelated users.

One user or one family must never manufacture global confirmed authority alone.

### 9.1 Global Shield requirements

- privacy-reduced report schema only;
- independent reporter deduplication;
- bounded rate/abuse controls;
- candidate/warning/confirmed stages;
- warning and confirmed states based on independent evidence, not raw report count alone;
- current security constants/weights remain controlled by the Regression Register and security review rather than informal UI changes;
- human review remains part of the confirmed/reputation boundary where currently locked;
- reporter reputation derives only from retained reviewed evidence and cannot itself create confirmation;
- signed Ed25519 feeds;
- freshness, resource limits, key overlap and anti-rollback protection;
- same-generation equivocation rejection;
- verified offline cache only while signature/freshness/rollback rules pass;
- invalid/untrusted/unavailable feed means intelligence unavailable, never clean;
- fixed retention/expiry so stale campaigns and reputation do not become permanent truth.

Current locked baseline thresholds include independent corroboration rather than single-reporter authority; changes to those exact thresholds require explicit reviewed security work and matching regressions.

### 9.2 Community privacy schema

Community reports may carry only the minimum privacy-reduced evidence required by the accepted schema, such as campaign fingerprints, eligible sender/reply/destination organizational indicators, bounded attachment hashes, evidence codes, score/verdict and pseudonymous reporter proof.

They must exclude mailbox identity, subject, body, contacts, credentials, provider message IDs, raw URL paths/query values, attachment names/content and unrelated local history.

---

# Part III — Consumer actions and workflows

## 10. Message actions: exact semantics

Security actions are separate capabilities. The UI may group them visually, but one action may not falsely claim another action occurred.

### 10.1 Report Scam to Email Shield

Current canonical behavior is the later REG-089 model:

1. persist the account-local campaign protection first;
2. request reversible provider Trash for the current selected message;
3. if provider Trash fails, personal protection remains committed and failure is shown honestly;
4. future matching locally reported campaign mail is eligible for durable account-local automatic Trash;
5. blocking the exact sender/domain remains a separate explicit choice unless another explicit personal rule already authorizes it;
6. Family/community evidence is privacy reduced;
7. one report never lowers or bypasses Global Shield independent-report/time-spread/review thresholds.

Any older document saying Report Scam must never request current-message Trash is superseded.

### 10.2 Block Sender / Block Domain

- selected-account scoped;
- persists personal rule before/with governed action transaction;
- current selected message may be moved to Trash only through provider-confirmed action semantics;
- future matches may use durable account-local automatic Trash authority;
- reversible through protected policy management;
- never silently becomes a global block.

### 10.3 Move to Spam/Junk

- acts on exactly the selected opaque message capability;
- requires provider confirmation;
- does not create Email Shield community-report success;
- does not imply sender/domain block;
- works through provider-neutral capability semantics.

### 10.4 Trash

- exact-message action;
- provider-confirmed and idempotent/replay protected;
- Undo/restore only when provider capability and retention support safe reversal.

### 10.5 Mark this message Safe

- exact-message scope only;
- cannot override High Risk/Confirmed hard evidence, blocks, verified signed threats or incomplete-inspection floors;
- cannot become a permanent sender allowlist.

### 10.6 Trust sender

- exact-address/account-local scope;
- bounded trust context only;
- hard threat evidence still wins;
- reversible.

### 10.7 Unsubscribe

Automatic RFC 8058 one-click POST is a security-sensitive network action. It requires the currently locked authenticated header/DKIM provenance and destination conditions, explicit user confirmation and hardened public HTTPS transport. Ambiguous/untrusted/missing authorization falls back to the manual in-app unsubscribe path rather than guessing.

`mailto:` fallback remains in-app rather than unexpectedly handing the user to an unsafe/ambiguous OS picker when Email Shield owns the action flow.

### 10.8 Analyze Links

- explicit user action only;
- token/capability-bound to selected message or explicit Scam Check input;
- uses hardened destination analysis;
- never sends mailbox credentials/cookies;
- does not automatically crawl every URL during mailbox scans.

## 11. Scan modes

### 11.1 Quick Scan

Fast, bounded, responsive protection over newest/relevant mail scope. Provider/API quotas and live IMAP limits stay bounded. Quick Scan must not silently expand into a full mailbox crawl.

### 11.2 Full Mailbox Audit

Broader audit across the provider's intended normal mailbox scope, with provider-aware folder semantics, pagination, quota-safe pacing, resumability and progress. Default scope must not silently include destructive/private system folders merely to inflate coverage.

### 11.3 Spam/Junk Scan

Explicit inspection of provider Spam/Junk placement using the same security core. Being in Spam/Junk is evidence, not automatic confirmation.

### 11.4 Cancellation and responsiveness

- scans run in killable Worker isolation;
- cooperative cancellation first, forced termination when necessary;
- Stop returns control without freezing the desktop service;
- new scan can start after stopped scan when ownership rules allow;
- provider sockets/operations use bounded deadlines and cancellation;
- no huge provider page/community refresh withholds all progress indefinitely.

### 11.5 Resume, refresh and restart

- scan continuation/history encrypted, account scoped and privacy reduced;
- provider cursors/checkpoints stay server side;
- browser refresh does not cancel running Worker;
- refreshed page reattaches to existing server-owned scan rather than starting duplicate;
- detached scans stop minting browser-only action tokens;
- stale `running` state after process restart becomes interrupted and can resume only through correct selected account;
- stale browser sessions fail visibly and require reload/reconnect;
- restored single-mailbox startup may select the sole unambiguous mailbox, but never guesses between multiple accounts or overwrites newer tab-local selection.

## 12. Continuous protection

Continuous protection is an extension of the same engine, not a separate detector.

### 12.1 Scheduled background protection

- account-scoped encrypted schedule state;
- bounded schedule intervals defined by current runtime contracts;
- one globally bounded background Worker budget;
- manual scans have priority;
- background runs bounded and read-only unless an explicitly approved protection policy authorizes action;
- failure backoff and deadlines;
- protected pause/resume/status;
- disconnect removes account schedule ownership;
- no raw results or secrets in scheduler persistence.

### 12.2 Near-real-time inbound protection

Provider-capability order:

- Gmail change/push notification adapter where production capabilities permit;
- Microsoft Graph change notifications where production capabilities permit;
- IMAP IDLE where reliable;
- bounded polling fallback where push/IDLE is unavailable.

All signals normalize into one replay-safe canonical event contract with deduplication, restart recovery, bounded backlog and manual-scan priority. Scheduled protection remains a fallback safety net.

### 12.3 Automatic actions

Automation settings may control notification/quarantine/spam behavior, but hard-destructive actions require the locked confidence/authority model. Sensitivity or convenience must not turn soft heuristics into automatic deletion authority.

---

# Part IV — Personal policy and adaptive protection

## 13. Personal Policy Management Centre

Personal policy remains selected-account scoped, encrypted and protected by the local API security boundary.

It manages accepted policy classes including personal blocks, trusted/safe exceptions, unsubscribe history and locally reported campaign memory.

Requirements:

- searchable/filterable management;
- single and bulk revoke where safe;
- explicit category clear/reset;
- strict versioned policy-only export;
- strict validated merge/replace import;
- no account/session/vault/credential/token secret in export;
- atomic persistence/rollback on failure;
- stale action-token invalidation after policy changes;
- browser safe-text rendering and no localStorage/sessionStorage secret persistence.

## 14. Relationship learning safety

- account-local encrypted history;
- persistent identities HMAC/fingerprint based rather than plaintext addresses;
- duplicate messages do not inflate history;
- prior benign history is context but never automatic trust;
- explicit Safe/Scam feedback can adjust bounded personal context;
- behavioral confidence may decay;
- sender-pattern drift/account takeover remain detectable;
- family members do not silently share private learning;
- reset/export controls preserve user agency;
- saturation/limit behavior prefers stale history over corrupted/inflated trust.

---

# Part V — Email Shield account, entitlement and Family Shield

## 15. Product identities are separate

Never conflate:

- **Email Shield account** — stable product account identity and user-facing username/account credentials model;
- **device** — app-generated cryptographic device identity;
- **entitlement** — plan state verified independently of mailbox/provider state;
- **Family Shield circle** — private membership/protection scope;
- **mailbox account** — provider identity used for mailbox operations/personal policy.

No hardware identifier is an Email Shield account identity.

## 16. Account security model

Core requirements:

- device private identity stored through native secret custody where available;
- stable public device ID derived from cryptographic identity, not hardware fingerprint;
- recovery uses high-entropy recovery proof with protected verification material;
- successful recovery rotates prior recovery authority;
- trusted-device revocation without accidentally destroying final recovery path;
- sign out everywhere/lost-device recovery;
- remote account/device authentication via signed challenge/passkey-quality proof, not trusting username + device ID text;
- mailbox identity/provider credential state separated from product account identity;
- explicit account deletion/export/clear-local-data without uploading mailbox contents.

## 17. Plan and purchase model

Canonical plan architecture:

- **Free** — useful local/manual protection and limited mailbox capability;
- **Individual** — continuous/multi-mailbox/advanced consumer protection according to packaging;
- **Family** — Individual-class protection plus Family Shield, trusted assistance and seat/device management.

Current seat architecture uses one account seat for Free/Individual and a bounded Family plan with default six seats unless service policy explicitly changes it.

Entitlement states include active, grace, expired and revoked semantics. Production authority comes from Apple, Google or web merchant verification adapters, not browser/UI state.

Purchase/entitlement lifecycle requirements:

- signed store/web evidence is verified by authoritative backend/service logic;
- duplicate subscription events are idempotent;
- cancellation, grace, expiry and revocation are represented honestly;
- Restore Purchase has explicit terminal states such as verified restore, nothing-to-restore, unavailable bridge and verification rejection;
- a returned store record that cannot be verified grants no paid access;
- stale/racing restore results cannot overwrite a newer request;
- native/store verifier secrets never ship in browser/client code;
- production UI cannot directly toggle paid entitlement.

Final commercial prices are a business decision and are **not hardcoded into security-engine semantics**.

Development entitlement switching is acceptance tooling only and must never become a production entitlement bypass.

### 17.1 Superseded original rule

The original product concept intentionally had no Email Shield account/subscription system. That rule was later explicitly replaced by the accepted account/device/Free-Individual-Family architecture. Future engineers must not remove that architecture because an old document says “no account” or “no subscription.”

## 18. Family Shield / Shield Circle

### 18.1 Membership

- one owner per circle;
- members bounded by entitlement seat limit;
- expiring one-time invite proofs;
- immediate authorization invalidation on member/device/invite revocation;
- delete circle / leave circle / seat transfer lifecycle;
- adult/member autonomy and consent preserved where required;
- no member can browse another member's mailbox/private history by default.

### 18.2 Family threat sharing

Default Family sharing contains privacy-reduced threat/campaign intelligence only. Sharing a specific suspicious item with a trusted person requires explicit consent and a narrowly scoped packet.

One member's personal report may protect that family immediately according to Family rules but cannot manufacture Global Shield confirmation.

Family warning/confirmed semantics remain distinct from public community/global consensus. Strict Family Protection may use a stronger private-family policy but cannot leak raw mailbox content or lower Global Shield authority.

### 18.3 Family safety categories

Family alerts/support cover high-risk classes such as banking/payment, crypto/investment, gift cards, government/legal, delivery/payment, romance, job/task, remote-access/refund/support and account-takeover patterns.

### 18.4 Failure isolation

Local personal protection commits first. Family/community service failure must not undo local Report Scam/Block decisions.

---

# Part VI — Consumer protection surfaces beyond scans

## 19. Scam Check / Check Anything

One local-first consumer analysis surface accepts suspicious material outside a connected mailbox.

Approved inputs:

- pasted message/email text;
- URL;
- copied sender/domain;
- `.eml` email file;
- screenshot/image;
- QR-code image;
- future native shared text/content;
- future explicit camera/clipboard/share-sheet inputs under platform permission rules.

Inputs normalize into the same bounded evidence/security semantics used by mailbox protection.

Output includes:

- verdict;
- conservative confidence band where useful;
- scam category;
- strongest supporting signals;
- strongest contradictory/safety signals;
- evidence limitations;
- safe next action;
- explicit uncertainty when evidence is insufficient.

Scam Check remains usable locally before a mailbox is connected when input does not require mailbox identity.

## 20. Explainability and safe-action guidance

Every significant verdict is consumer-readable:

- “Why this was flagged”;
- sender/authentication/domain/link/attachment/relationship/Family/community provenance;
- observed evidence versus unavailable/inferred evidence;
- “What should I do?”;
- independent official-channel verification instead of suspicious message contacts;
- warnings against sharing passwords, MFA codes, recovery codes, seed phrases or payment credentials;
- no implication that Safe mathematically guarantees harmlessness;
- no Family private-content/community reporter identity exposure.

## 21. Protection sensitivity

Profiles:

- **High Protection**
- **Balanced** — default
- **Low Noise**

Profiles may change treatment of soft/ambiguous evidence and notifications. They may **not** suppress hard authentication contradictions, explicit personal blocks, locked malware evidence, trusted confirmed intelligence or any other hard-threat invariant.

Per-account overrides may exist. Family defaults cannot erase required member autonomy or hard-threat floors.

## 22. Campaign Radar

Privacy-safe emerging-scam radar may use:

- aggregate privacy-reduced campaign fingerprints;
- independent reporter counts/weights;
- novelty/rate-change patterns;
- optional coarse user-selected region;
- signed campaign advisories;
- sanitized templates describing scammer requests.

No precise location or reconstructed private message is required.

## 23. Inbox Health and safe cleanup

Approved capabilities:

- subscription/newsletter inventory;
- RFC 8058-safe unsubscribe preferred;
- catch-and-trash after unsubscribe only when explicitly enabled and safely identified;
- pause/mute/read-later local rules;
- bounded bulk cleanup by selected sender/category/age with confirmation;
- optional sender/domain screening for unseen senders, not universal default quarantine;
- relationship context separate from unconditional allowlisting;
- activity history;
- Undo/recovery where provider support permits;
- keep-newest cleanup only for explicit low-risk categories;
- provider metadata-based mailbox volume/storage summaries where available without content upload.

## 24. Mailbox Health / compromise indicators

Where official provider capabilities reliably expose them, Email Shield may check:

- suspicious/new forwarding rules;
- suspicious inbox/filter rules;
- unexpected delegates/send-as identities;
- deterministic trusted-provider security alerts;
- suspicious auto-delete/redirect behavior;
- connected-app/session indicators only where official APIs safely expose them.

Email-content heuristics alone never claim the mailbox account itself is compromised. Unsupported checks are shown as unavailable, never safe.

## 25. Digital Account Footprint

Digital Account Footprint is a **local discovery aid**, not a centralized identity graph or a claim of complete coverage.

It may infer the user's likely online-account footprint from locally processed, suitably authenticated welcome/security/receipt/account messages and provider metadata that the existing mailbox permission already exposes.

Requirements:

- local by default;
- no upload of the account inventory;
- no claim that absence means the user has no account with a service;
- no password extraction/storage;
- privacy-safe category/service summaries;
- explicit distinction between evidence found in mail and verified account ownership;
- integrates with recovery/exposure guidance without becoming a data-broker profile.

## 26. Shopping Safety

Shopping Safety is an explicit consumer tool for unfamiliar storefronts/purchase requests.

Inputs are only what the user deliberately provides, such as:

- storefront URL;
- optional seller name;
- optional advertised-price text;
- optional payment instructions;
- optional storefront/seller text.

It may reuse hardened destination analysis and social-engineering/payment evidence. It must **not** inspect browser history, orders, cookies or saved payment data.

Output may distinguish high risk, caution, unknown/no-strong-signal and limitations. “No strong signal” must never be presented as proof that an unfamiliar seller is legitimate.

## 27. Browser Protection and link defense

The shared foundation includes:

- local URL verdict API;
- hardened destination analysis;
- phishing/typosquat/redirect-chain/destination reasoning;
- signed/global intelligence composition;
- download URL/filename/type risk handoff;
- real-time warn/block contract for future browser/native bridge;
- minimal URL/security context only;
- no passive cloud browsing-history telemetry by default;
- explicit privacy-reduced site report action if enabled.

The consumer “check before opening” path and future store-distributed browser extension must consume this engine contract rather than invent their own detector.

### 27.1 Hardened network boundary

Explicit destination acquisition retains current SSRF/rebinding protections: per-hop DNS validation, direct socket pinning to validated public addresses while preserving hostname/TLS identity, redirect revalidation, strict timeout/byte/redirect/content handling, no mailbox cookies/credentials and fail-closed unsupported/incomplete results.

## 28. Media Authenticity

Media Authenticity is a **capability-gated explicit tool**, not an unconditional “deepfake detector” claim.

Requirements:

- the user explicitly selects one image/audio/video;
- bounded input sizes by media type;
- a detector must advertise availability/capability before the UI enables analysis;
- unavailable detector → **UNAVAILABLE**, never authentic;
- inconclusive result → **INCONCLUSIVE**, never authentic;
- no supported manipulation indicator → truthfully means only that the configured detector returned no supported indicator; it is **not proof of authenticity**;
- likely-manipulated output may include a conservative confidence band and reason;
- selected media is never silently harvested from the device/browser;
- any future cloud detector requires an explicit privacy/security/consent boundary and cannot become core-protection authority.

## 29. Mobile scam-channel contracts

Shared core contracts support future native clients for:

- SMS/text analysis;
- Android notification text/link analysis;
- iOS SMS filtering within platform constraints;
- share-sheet/shared-content analysis;
- clipboard analysis only after explicit user action;
- calendar-invite URL/scam analysis with permission;
- QR from camera/image;
- generic notification payloads without private message body by default.

Permissions are minimized and feature-scoped. Native acquisition may differ; canonical evidence/verdict semantics do not.

## 30. Remote-access / payment-risk intervention

Email Shield may warn on combinations such as:

- suspicious messages asking user to install remote-support software;
- remote-access software active while strong financial-scam evidence is present, where native platforms expose this narrowly/safely;
- gift-card/crypto/bank-transfer urgency plus impersonation evidence;
- suspicious callback numbers with guidance to independently obtain official contact information.

Email Shield is not endpoint EDR or a banking system. It does not upload broad process inventory or claim to block transactions it cannot observe.

## 31. Identity exposure / credential-risk features

Approved privacy-preserving foundation:

- explicit opt-in breach/exposure checks;
- k-anonymity/prefix or equivalently privacy-preserving lookup where a vetted provider permits it;
- no plaintext password upload;
- email-address exposure checks only after explicit consent;
- Family summary without unnecessary breach detail disclosure;
- recovery guidance to independently verified official services.

Credit monitoring, insurance and regulated financial surveillance remain outside the core unless a future regulated partner is separately approved.

## 32. AI / ML policy

The early “no AI/ML” rule is superseded by a narrower permanent rule:

- deterministic security evidence remains authoritative;
- AI/ML may contribute bounded evidence where failure modes are controlled;
- AI may provide optional explanations/presentation;
- AI must never silently override hard deterministic threat states;
- cloud inference requires explicit consent, redaction/minimum-data architecture and separate privacy/security review;
- inability to reach AI never disables core local protection.

The product remains useful and secure without paid third-party inference.

---

# Part VII — Activity, UI, accessibility and consumer trust

## 33. Unified Protection Activity

One consumer-facing activity model covers manual scans, continuous protection, Family/global matches and user actions.

It may record privacy-safe local events such as:

- protected/flagged/reviewed/confirmed outcomes;
- blocked/reported/trash/spam/unsubscribe actions;
- cleanup actions;
- recovery/Undo outcomes;
- connection/permission health changes;
- protection-profile changes.

The user can understand **what changed and why**. Provider-capability-gated Undo never promises recovery after retention/deletion makes it impossible.

## 34. Notifications

- generic/privacy-safe content by default;
- optional richer local-only previews;
- no body/subject leakage through remote notification routing by default;
- notification actions scoped to correct account/message/current session;
- Family notifications do not expose another member's private content.

## 35. Consumer navigation and Home

Primary consumer navigation is outcome-focused, not developer architecture.

The accepted current desktop navigation model is centered on:

- **Home**
- **Check & Scan**
- **Health**
- **Family**
- **Activity**
- **Account**
- **Settings**

Internal Community/operations/developer diagnostics remain hidden from ordinary consumer navigation unless a separately authorized developer/operations surface is intentionally opened.

Canonical first-run journey:

1. create/sign in to Email Shield account, with local Scam Check usable before mailbox connection and local-only capability retained where feasible;
2. review requested permissions and why needed;
3. connect mailbox account(s);
4. run first protection scan;
5. select High/Balanced/Low Noise sensitivity;
6. enable/configure scheduled/real-time protection;
7. optionally create/join Family Shield;
8. arrive at simple protection-status Home.

Home answers:

- Am I protected?
- What happened recently?
- Is anything waiting for me?
- Are my Family members protected?
- Is any permission, connection, subscription or protection service broken?

### 35.1 Multi-account UI ownership

Every browser workflow displaying/mutating account-scoped state binds async results/actions to selected account generation. Switching accounts clears/rehydrates correct workspace; stale responses cannot overwrite newer account view.

## 36. Accessibility and localization

Blocking architecture supports:

- keyboard-only operation;
- visible focus;
- semantic landmarks/programmatic labels;
- screen-reader-compatible status/tables;
- 200%/400% zoom and narrow layouts;
- forced colors/high contrast;
- reduced motion;
- no security meaning encoded only by color;
- strict localization catalog with English fallback;
- locale-safe date/number formatting;
- local/system fonts without unnecessary tracking dependencies;
- contextual scam-safety education;
- respectful non-shaming language for scam victims.

Professional translations and owner assistive-technology acceptance remain real content/manual gates rather than fake automated PASS claims.

---

# Part VIII — Local service, secrets and persistence

## 37. Desktop local API security

Permanent requirements:

- loopback-only binding;
- Host and forwarded/proxy-header rejection;
- process-local HttpOnly session;
- CSRF proof for protected reads;
- exact same-origin proof and expiring single-use mutation nonce for mutations;
- opaque capability/action replay protection;
- restrictive CSP/framing/opener/resource/referrer/capability headers;
- browser storage does not hold readable local session secrets;
- credential/token/error redaction;
- request/resource/rate bounds;
- stale session failure visible and fail closed.

Native wrappers may replace browser transport later, but may not weaken equivalent authority/replay/isolation properties.

## 38. Native secret custody

Desktop persistent secret handling uses one opaque-reference abstraction across:

- Windows Credential Manager;
- macOS Keychain;
- Linux Secret Service.

Long-lived provider credentials, OAuth refresh tokens and local encryption keys inherit this boundary.

Requirements:

- no secrets in unsafe command-line arguments/logs;
- native write/read/delete verified;
- missing native service never triggers plaintext fallback;
- encryption keys scoped to managed data root;
- legacy key migration only after authenticated decryption/read-back proof;
- unreadable encrypted state fails closed rather than silently resetting security data.

## 39. Encrypted local persistence

Security-sensitive local stores include personal policy, local report memory/outbox, scan state/history, relationship history, background schedules, account/Family state and community aggregate state when server mode is used.

Permanent rules:

- authenticated encryption;
- descriptor-bound/no-follow resource-bounded reads where applicable;
- separate plaintext/envelope limits;
- atomic replace semantics;
- failed write preserves previous valid state;
- private key files strict ownership/mode protections where native-vault custody is not the contract;
- corruption/missing-key behavior explicit/fail closed;
- recovery tooling archives confirmed unreadable ciphertext rather than deleting evidence blindly.

---

# Part IX — Community/account infrastructure and operations

## 40. Community service architecture

Desktop client does not automatically become a public community server. Public ingestion/feed behavior is an explicitly configured server mode/service.

Production readiness requires:

- HTTPS/TLS and proper DNS;
- gateway/edge authentication/rate/volumetric controls;
- reporter enrollment/reputation controls;
- durable encrypted aggregate storage;
- bounded append-only ingestion/journal + snapshot compaction;
- crash-tail recovery;
- fixed retention;
- signed feed publishing;
- signing-key overlap/rotation;
- backup/restore drills;
- generic public error surfaces;
- fixed-cardinality privacy-safe metrics;
- monitoring/alerts;
- environment/tenant separation;
- separate account/community storage/signing secrets;
- no production secret defaults;
- incident kill switches for community feed, link analysis and account sync that do **not** disable local scanning.

Repository readiness is not proof these production operations have been deployed.

## 41. Scale and cost law

- avoid unnecessary paid API dependencies for core protection;
- bound all network/cloud work;
- cache/coalesce privacy-safely where valid;
- low-memory Worker/background behavior;
- provider-quota-aware acquisition;
- explicit concurrency/queue bounds;
- bounded storage/retention;
- 10,000-client/reporting capacity qualification for community paths where defined;
- cost/capacity worksheets import runtime-owned ceilings;
- planning outputs are planning, not SLAs;
- expensive optional remote capabilities cannot become required for core local protection.

## 42. Operations and incident response

Operational metrics/diagnostics are fixed-cardinality/privacy-safe. Public error responses never expose stack traces, storage paths, crypto details or attacker-controlled echoed values.

Incident response supports containment of:

- compromised community signing keys;
- feed corruption/equivocation;
- storage corruption;
- OAuth/provider credential incidents;
- account service compromise;
- abusive reporting/gateway traffic;
- release signing/update incidents;
- telemetry/privacy regressions.

Local scanning should remain available whenever safely possible even if remote community/account/link services are disabled during containment.

---

# Part X — Release, native and cross-platform architecture

## 43. Portable shared core

- exact versioned schema;
- strict bounded runtime validation;
- decision/evidence response only;
- no Node/host/filesystem/network/API/adapter/OAuth/vault/Worker/shell dependency in transitive core graph;
- deterministic platform-neutral helpers;
- committed cross-provider/adversarial vectors;
- desktop workflows route through same core contract.

Native clients may add acquisition, secure storage, OS scheduling, notifications, permissions and UI, but **may not fork or reinterpret accepted threat semantics**.

## 44. Release integrity

Portable/release foundations require:

- reproducible host-targeted package inventory;
- exact approved runtime and production dependency closure;
- normalized files/modes/mtimes where format permits;
- complete SHA-256 manifest/release identity;
- reject secret/dev/extra/missing/symlink contamination;
- verify every byte before/after staging;
- signed update envelope with pinned overlap trust;
- platform/architecture/version/release binding;
- strictly newer forward update;
- atomic activation;
- full verification before repair/rollback;
- one-step signed rollback only to recorded verified predecessor;
- uninstall preserves user data by default;
- purge requires explicitly marked safe managed data directory.

Ephemeral CI signatures prove implementation, not production signing custody.

## 45. Native application phase

Native Windows/macOS/Android/iOS wrappers come **after** shared consumer/security semantics are accepted enough that platform work will not hide desktop/provider defects.

Native wrappers may add:

- secure-storage bridges;
- native notifications;
- background schedulers/entitlements;
- OAuth callback/protocol handling;
- share sheet / SMS / notification / camera / calendar bridges;
- browser/web protection bridge;
- store billing adapters;
- installer/package formats;
- platform UI shells.

They may not:

- invent a second detector;
- downgrade Safe/Review/High Risk/Confirmed semantics;
- bypass local privacy rules;
- weaken Family/global authority boundaries;
- treat platform permission failure as Safe;
- claim continuous protection where OS policy does not allow it.

## 46. Store/distribution acceptance

External/native launch gates include, as applicable:

- Authenticode or equivalent Windows signing;
- Apple Developer ID and notarization;
- App Store / Play Store signing and review;
- native background entitlements;
- production OAuth redirect/application registration;
- production merchant/store verification;
- production release-key custody and rotation;
- installed update/rollback/uninstall acceptance on real supported OS versions.

These are never replaced by portable-package CI.

---

# Part XI — Regression, competition and security evolution

## 47. Regression Vault

Every discovered real defect becomes a permanent regression when technically reproducible.

Sanitized owner-approved real samples enter only through accepted provenance/sanitization/review. Privacy and expected outcomes are preserved across all five provider adapters.

Scenario families include at minimum:

- benign controls for every threat class;
- full-context scams with benign-looking links;
- QR/quishing;
- hidden/cloaked redirects;
- support/refund callbacks;
- known-contact takeover;
- BEC;
- romance/gift-card/crypto/investment/job/task scams;
- malicious calendar invites;
- fake shopping/download/extension lures;
- remote-access/payment social engineering;
- spam-bomb/security-alert hiding;
- polished/AI-written phishing;
- image-only phishing;
- multilingual scam language;
- provider-specific acquisition edge cases while preserving provider-neutral verdict meaning.

## 48. Competitive feature rule

Email Shield may independently implement useful **publicly observable product behavior** from competitors — real-time warnings, safe browsing, Check Anything, explainability, Family protection, campaign alerts, cleanup, account exposure checks and similar — when it improves the approved product.

It never copies competitor source code, private APIs, trade secrets, proprietary models, private corpora, branding or protected assets.

Competitive research may expand protection; it may not override Email Shield's privacy/security constitution.

---

# Part XII — Milestone lineage and current continuous roadmap

## 49. Historical milestone foundation

### Milestone 1 — Complete testable cross-adapter protection core

**Formal state: CLOSED.**

Foundation retained:

- five-provider canonical adapter architecture;
- shared verdict engine;
- Quick/Full/Spam scans;
- responsive cancellation/Worker isolation;
- bounded MIME/partial-content safety;
- exact provider action capability/confirmation;
- personal policies;
- local API security;
- privacy-reduced reporting/signed-feed foundation;
- live iCloud hard testing;
- regression/test/governance process.

Later strengthening does not reopen M1; regressions are defects.

### Milestone 2 — Verified community intelligence and production hardening

**Repository state: CODE-COMPLETE for canonical repository-buildable rows. Formal external acceptance remains open.**

Major implemented foundations:

- guided Gmail/Outlook OAuth architecture;
- cross-platform native vault;
- encrypted personal policy/scan/relationship/background state;
- policy management centre;
- resumable scans/history;
- relationship context;
- QR decoding;
- hardened Analyze Links transport/coordinator/cache;
- thread-continuity analysis;
- attachment hash/type integrity;
- trusted authentication provenance/alignment + PSL domain boundary;
- RFC 8058 one-click integrity;
- bounded community feed/aggregate/storage/recovery/rotation;
- scalable journal/retention and 10,000-reporter proof;
- signed-feed anti-rollback;
- privacy-safe metrics/diagnostics;
- dependency/security closure;
- portable release foundation.

### Milestone 3 — Release-ready continuous cross-platform product

**Repository/shared-engine state: engineering implementation complete for accepted pre-native workstreams; owner/native/external acceptance remains separate.**

Major foundations:

- scheduled and near-real-time continuous protection architecture;
- portable shared core;
- signed release/update/rollback lifecycle;
- multi-account isolation;
- Check Anything;
- explainability and sensitivity profiles;
- Family Guardian/campaign radar;
- Inbox/Mailbox Health and Digital Account Footprint;
- Shopping Safety, Browser Protection and truthful Media Authenticity capability surface;
- browser/mobile/intervention contracts;
- account/privacy/subscription lifecycle;
- activity/Undo/recovery;
- accessibility/localization/safety;
- privacy-safe support/operations;
- regression/provider compatibility/capacity/release gates.

## 50. Final Consumer Completion layer

The later approved Final Consumer Completion milestone **strengthened and completed** the original three-milestone product direction. It does not delete the three milestones; it reconciles the finished consumer promise across workstreams A-W and creates the handoff boundary to native applications.

Its permanent outcome is an understandable personal/family scam-protection product rather than a developer-facing scanner.

Future engineers must not use “exactly three milestones” from the original brief to remove accepted Final Consumer Completion features. The three milestones remain lineage; this Masterplan is the continuing structure after them.

## 51. Current work boundary as of establishment

At establishment:

- Milestone 1 formally closed.
- Milestone 2 repository-buildable rows implemented; real provider/deployment acceptance remained open.
- Milestone 3/final consumer repository engineering reached owner/live/native acceptance-and-repair boundary.
- later owner/live findings through current `main` continued to produce root-cause fixes; those are regressions, not new scope.
- Android/iOS mailbox application shells remained deliberately after stable shared-engine/live-provider boundary.

**Do not freeze this section to a commit SHA.** Resolve current `main`, open issues/PRs and exact-head/post-merge gates before deciding what is unfinished.

## 52. External acceptance gates that cannot be faked

Unless later real evidence explicitly closes them, the registered boundaries are:

1. **GAP-001 — Google publication:** production Google OAuth publication/consent/verification for intended public app;
2. **GAP-002 — Outlook live:** controlled real Outlook connect/scan/action/disconnect/reconnect owner acceptance;
3. **GAP-004 — Community deployment:** public Community/Global Shield DNS/TLS, persistent storage, monitoring, backup/restore and signing-key rotation ceremony;
4. **GAP-005 — Analyze Links live:** controlled public destination/redirect/DNS validation infrastructure;
5. **GAP-008 — Gateway abuse:** production reporter enrollment/reputation/rate/volumetric/DDoS defenses;
6. owner-visible destructive/recovery/multi-account/Family/accessibility acceptance marked manual;
7. native Windows/macOS packaging/signing/background-task acceptance;
8. Android/iOS native shell, permission/background/store acceptance;
9. real Apple/Google/web merchant verification and production entitlement events;
10. professional translation/content review for release locales;
11. production telemetry/monitoring owner acceptance if optional service enabled.

Later real closure must update status/reconciliation evidence and, if the product boundary materially changes, this Masterplan through the same review process.

---

# Part XIII — Engineering execution law

## 53. Recover state before doing work

Every new engineer/agent/session first inspects:

1. current `main` HEAD from Git;
2. open PRs/issues relevant to Email Shield;
3. `.engineering/CONTINUATION.json` as hint, not substitute for Git;
4. `README_REBUILD_STATUS.md`;
5. `docs/THREE_MILESTONE_FINAL_RECONCILIATION.md`;
6. `.engineering/CANONICAL_ROADMAP_GAP_AUDIT.md`;
7. `.engineering/REGRESSION_REGISTER.md`;
8. `.engineering/TEST_MATRIX.md`;
9. this Masterplan and feature-specific security contract;
10. latest qualifying CI evidence for exact current/PR head.

Never resume from old PR/SHA merely because previous chat mentioned it.

## 54. Root-cause rule

A green test is not the goal. A working secure consumer workflow is the goal.

When defect appears:

1. preserve/reproduce failure;
2. trace full ownership chain — consumer click/state → protected API/capability → workflow/coordinator → provider/local service → persistence → returned result → browser/native reconciliation;
3. identify earliest incorrect assumption/boundary;
4. add failing regression at correct layer when possible;
5. fix root cause, not screenshot symptom;
6. do not weaken assertions, timeouts, expected results, privacy boundaries or security floors merely to get green CI;
7. remove temporary/debug/dead code introduced during diagnosis;
8. rerun focused tests and unchanged complete gate;
9. repeat real owner/live step that failed when applicable.

A patch that hides symptom while preserving wrong producer/consumer contract is not accepted.

## 55. Test-before-credit rule

Code existing in repository does not mean feature works.

Engineering credit requires:

- production-path implementation;
- producer and consumer wired;
- focused regression coverage;
- privacy/security invariants tested;
- full Engineering Gate on exact immutable candidate head;
- browser/runtime/package path where applicable.

Live/external credit additionally requires its real environment.

## 56. Exact-head pull-request law

Every implementation/governance repair is qualified on literal immutable PR head SHA, not GitHub synthetic merge ref while pretending it is branch head.

Required sequence:

1. branch from current accepted `main`;
2. focused TDD/root-cause change;
3. full applicable Engineering Gate on exact PR head;
4. Windows + macOS + Ubuntu jobs and combined summary all green;
5. merge only exact verified head, using expected-head guard where supported;
6. run/confirm independent post-merge gate on resulting `main` before calling change accepted;
7. older green runs do not transfer to newer SHA.

Gate Summary is fail-closed: failed/cancelled required platform cannot be masked.

## 57. Manual/live acceptance law

Manual testing is used only where real visibility/provider/platform behavior cannot be fully proven in CI. It should be a **single clear owner handoff** where practical, not endless piecemeal guessing.

Owner should not repeat already accepted live checks unless relevant behavior changed, a regression invalidates evidence, platform/provider changed materially, or owner explicitly asks.

Fixture mode is engineering tooling only and remains explicitly development-authorized/unavailable from ordinary production consumer startup.

## 58. Security/privacy review law

Every new feature answers:

- What private data does it acquire?
- Where is it normalized?
- Does any leave device?
- What is persisted, for how long and under what key?
- What can browser/native UI see?
- What capability authorizes mutation?
- What happens when evidence is incomplete?
- What happens when remote/provider service unavailable?
- Can one account/member/reporter affect another without explicit authority?
- What are CPU/memory/network/storage bounds?
- How are abuse/replay/race/stale-state handled?
- What regression prevents later weakening?

If these cannot be answered, feature is not merge-ready.

## 59. No-stall / no-scope-drift law

External acceptance waiting time is not permission to invent unrelated features or redesign product. When repository-buildable work for current boundary is exhausted, stop at real external gate unless:

- live evidence reveals reproducible code defect;
- owner explicitly expands product;
- security vulnerability requires remediation;
- dependency/platform change invalidates locked behavior.

Native work must not be escape route around unresolved desktop/provider security defects.

---

# Part XIV — Explicit supersession register

## 60. Decisions future engineers must not accidentally revive

### S-01 — “No Email Shield account / no subscription”

**SUPERSEDED.** Replaced by accepted cryptographic account/device model and Free/Individual/Family entitlement architecture.

### S-02 — “No AI/ML under any circumstances”

**SUPERSEDED IN PART.** Permanent rule is deterministic authority: AI/ML may contribute bounded evidence/explanation but cannot override hard deterministic states or make cloud inference mandatory.

### S-03 — “Exactly three milestones means no later product-completion layer”

**SUPERSEDED.** Three milestones remain historical lineage. Later owner-approved Final Consumer Completion A-W is accepted scope; native wrapping follows stable shared-engine boundary.

### S-04 — “Report Scam and Trash must always be separate”

**SUPERSEDED by REG-089.** Report Scam commits local campaign protection first, then requests reversible Trash for current selected message; future account-local campaign/block matches retain durable automatic Trash authority. Global/Family publication authority remains separate.

### S-05 — “Known sender = Safe”

**REJECTED.** Relationship history is context only. Known contacts can be compromised; hard threat evidence wins.

### S-06 — “Authentication pass = legitimate sender/business”

**REJECTED.** Authentication establishes bounded identity/alignment evidence only and requires trusted provenance.

### S-07 — “No detected threat = Safe”

**REJECTED by security redesign.** Safe is earned. Incomplete inspection/missing intelligence cannot silently become Safe.

### S-08 — “Provider Spam/Junk alone proves maliciousness”

**REJECTED.** Placement is risk/context evidence, not sole confirmation authority.

### S-09 — “One personal/community report can globally confirm threat”

**REJECTED.** Global confirmation remains independent-report/review/signing governed.

### S-10 — “Green code or fixtures prove real provider/deployment acceptance”

**REJECTED.** Real provider/public/native/store gates require real environments.

### S-11 — “Portable package = native consumer app”

**REJECTED.** Portable/release foundations prove shared packaging; native installer/store/background/permission acceptance remains separate.

### S-12 — “Each provider/platform may implement its own detector”

**REJECTED.** All acquisition surfaces converge on shared portable protection semantics.

### S-13 — “Solve IMAP inspection by unlimited whole-message/attachment downloads”

**REJECTED.** Selective bounded MIME/attachment acquisition and completeness semantics are permanent.

### S-14 — “Unsupported capability can be shown safe/healthy”

**REJECTED.** Unsupported/unavailable is explicit and cannot be converted to Safe.

### S-15 — “Developer fixture entitlement/providers may ship as ordinary consumer authority”

**REJECTED.** Development acceptance tooling is explicitly gated and production-disabled.

### S-16 — “Old UI/navigation screenshots are product authority”

**REJECTED.** Current consumer outcome/navigation contracts and accepted implementation control; historical screenshots are evidence only.

### S-17 — “Media detector unavailable/inconclusive means authentic”

**REJECTED.** Media Authenticity is capability-truthful: unavailable/inconclusive stays unavailable/inconclusive; no indicator is not proof of authenticity.

### S-18 — “Shopping check can silently inspect browser/payment history”

**REJECTED.** Shopping Safety evaluates only explicit user inputs and approved destination evidence.

---

# Part XV — Canonical source registry

## 61. Primary source backbone

### Product / roadmap / reconciliation

- `docs/FINAL_CONSUMER_COMPLETION_MILESTONE.md`
- `docs/FINAL_MILESTONE_PRODUCT_OUTCOME.md`
- `docs/FINAL_MILESTONE_CONSUMER_PROMISE.md`
- `docs/FINAL_MILESTONE_SECURITY_PROMISE.md`
- `docs/FINAL_MILESTONE_SCOPE_LOCK.md`
- `docs/THREE_MILESTONE_FINAL_RECONCILIATION.md`
- `.engineering/CANONICAL_ROADMAP_GAP_AUDIT.md`
- `README_REBUILD_STATUS.md`
- `docs/MILESTONE_1_CLOSURE.md`
- `docs/MILESTONE_2_LIVE_ACCEPTANCE.md`

### Executable governance

- `.engineering/REGRESSION_REGISTER.md`
- `.engineering/TEST_MATRIX.md`
- `.engineering/FINAL_CONSUMER_MILESTONE_INVARIANTS.md`
- `.engineering/CONTINUATION.json` — continuation hint only; resolve current state from Git
- `.github/workflows/verify.yml`
- `package.json` gate commands

### Privacy / security / incident

- `PRIVACY.md`
- `SECURITY.md`
- `THREAT_MODEL.md`
- `INCIDENT_RESPONSE.md`
- `.engineering/LOCAL_PERSISTENCE_FILE_INTEGRITY.md`
- `.engineering/CREDENTIAL_VAULT.md`
- `.engineering/AUTHENTICATION_RESULTS_PROVENANCE.md`
- `.engineering/AUTHENTICATION_ALIGNMENT_INTEGRITY.md`
- `.engineering/ANALYZE_LINKS_NETWORK_BOUNDARY.md`
- `.engineering/LINK_DESTINATION_P0_CLOSURE.md`
- `.engineering/ATTACHMENT_HASH_INTELLIGENCE.md`
- `.engineering/ATTACHMENT_TYPE_INTEGRITY.md`
- `.engineering/HTML_INTERACTION_NORMALIZATION.md`
- other current feature-specific `.engineering/*.md` contracts referenced by Regression Register.

### Account / Family / continuous / cross-platform

- `.engineering/ACCOUNT_ENTITLEMENT_FAMILY_ARCHITECTURE.md`
- `.engineering/BACKGROUND_PROTECTION.md`
- `.engineering/CROSS_PLATFORM_CORE_PLAN.md`
- `docs/FINAL_MILESTONE_NATIVE_BOUNDARY.md`
- final workstream/acceptance documents under `docs/` and `.engineering/`.

### Current consumer production surfaces that must remain represented

- `web/consumer-product.js`
- `web/scam-check.js`
- `web/shopping-safety.js`
- `web/media-authenticity.js`
- `web/billing-plan-ui.js`
- `web/family-shield.js`
- `web/family-guardian-preferences.js`
- `web/protection-learning.js`
- `web/health-cleanup-controller.js`
- `web/review-actions.js`
- `web/analyze-links-actions.js`
- current server/engine APIs backing those surfaces.

### Production community / release / operations

- `.engineering/COMMUNITY_DEPLOYMENT.md`
- `.engineering/COMMUNITY_RECOVERY_ROTATION.md`
- `.engineering/COMMUNITY_SCALABLE_INGESTION.md`
- `.engineering/COMMUNITY_OPERATIONAL_METRICS.md`
- `.engineering/COMMUNITY_READINESS_INTEGRITY.md`
- `.engineering/COMMUNITY_FEED_ROLLBACK_INTEGRITY.md`
- `docs/DEPLOYMENT_CAPACITY_COST.md`
- release/package contracts referenced by current Regression Register/Test Matrix.

### Historical source lineage

The recovered owner-approved August 2026 three-milestone engineering specification, earlier unified milestone plan, live iCloud false-Safe evidence and resulting security redesign remain historical provenance. Their surviving requirements are integrated here. Superseded requirements are explicitly recorded in Part XIV rather than silently deleted from history.

---

# Part XVI — Definition of the finished Email Shield

## 62. Owner/product acceptance lens

Following this Masterplan to completion must produce a product where:

- normal consumer can install/open it and understand protection without developer knowledge;
- Gmail, iCloud, Outlook, Yahoo and generic IMAP use equivalent security meaning;
- engine catches technical phishing and social-engineering scams including polished/QR/image/known-contact variants;
- dangerous mail is not called Safe merely because authentication passed or detector lacked evidence;
- user clearly sees why something was flagged and what to do next;
- actions have exact understandable consequences;
- personal rules protect immediately without poisoning unrelated users;
- Family Shield protects loved ones without exposing inboxes;
- Global Shield gains value from independent privacy-reduced intelligence with abuse/review/signing controls;
- Check Anything protects suspicious material outside mailboxes;
- Shopping Safety, Browser Protection, Digital Account Footprint and Media Authenticity behave within their truthful privacy/capability boundaries;
- continuous protection, Inbox/Mailbox Health and mobile contracts extend product beyond manual scanner;
- secrets/private content remain local by default;
- optional remote services are narrow/bounded/privacy reviewed;
- low-spec devices/provider quotas remain respected;
- multi-account/session/race/restart behavior is reliable in real use;
- native clients reuse one accepted core instead of diverging;
- external/provider/store/deployment claims are made only after real acceptance;
- regressions found by owner become permanent protection rather than recurring bugs.

## 63. Engineering acceptance lens

The project is not finished because every planned function exists. It is finished when:

1. every approved repository-buildable feature has production-path implementation;
2. full regression/corpus/provider/privacy/security suite is green on exact candidate;
3. Windows, macOS and Ubuntu required gates/summary pass;
4. portable/release artifacts verify;
5. low-resource/capacity/dependency policies pass;
6. owner-visible workflows work in real consumer UI;
7. destructive/recovery actions behave correctly;
8. real Gmail/Outlook/IMAP-provider acceptance required for release passes;
9. public community/account/link infrastructure passes real deployment/abuse/recovery/key-rotation acceptance;
10. native/store/signing/background/permission acceptance passes on intended platforms;
11. privacy/security/public docs match actual behavior;
12. no known blocker is relabeled “future” merely to declare completion.

## 64. Final invariant

**The core idea never changes; it gets stronger.**

Email Shield continuously improves scam detection, privacy, explainability, Family protection, reliability and cross-platform reach without weakening accepted security meaning.

When a new capability conflicts with that principle, change the capability — not the principle.
