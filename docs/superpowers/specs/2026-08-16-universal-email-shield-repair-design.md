# Universal Email Shield Repair Design

## Purpose

This design defines the final provider-neutral repair architecture for the currently owner-tested Email Shield build. The goal is to close every confirmed code/workflow defect without weakening existing security, privacy, provider correctness, fail-closed behavior, or already-working consumer flows.

The iCloud and Spam/Junk scans are evidence that exposed weaknesses in the current detector. They are not authorization to build iCloud-specific scoring rules. Detection quality is an Email Shield property. Provider adapters may extract provider-specific evidence, but the common engine owns scam reasoning, confidence, scoring, uncertainty, verdicts, and actions.

This design is the architecture authority for Linear program EMA-33 and the related universal detection defects EMA-31 and EMA-32.

## Non-negotiable invariants

1. Gmail, iCloud, Yahoo, generic IMAP, and Outlook may normalize provider facts only. They must not own provider-specific risk thresholds, Safe exceptions, scam keywords, brand rules, or final verdict logic.
2. Equivalent normalized evidence must produce the same score/verdict regardless of the provider adapter that produced it.
3. Missing or untrusted evidence is uncertainty. It must not manufacture Safe or manufacture threat evidence.
4. Incomplete inspection can never become Safe merely because a sender is known, trusted, historically clean, or user-approved.
5. Hard contradictions always override relationship/history confidence.
6. Authentication-Results, ARC, relay lineage, and forwarding metadata may be trusted only when their provenance to the actual mailbox/provider trust boundary is proven.
7. Provider Spam/Junk placement is contextual corroboration, never malicious truth.
8. No repair may be implemented by lowering High Risk thresholds, blanket allowlists, test-only bypasses, production entitlement bypasses, or weakening SSRF/privacy controls.
9. Every behavior change follows RED regression -> root-cause trace -> minimal production repair -> focused GREEN -> full regression -> exact cross-platform gate.
10. Existing working behavior must be regression-locked before shared-core changes land.

## Architecture overview

The repaired architecture has four provider-neutral stages:

`Provider Adapter -> Canonical Evidence Normalizer -> Structural Detection Core -> Verdict/Action Policy`

### Provider Adapter

Responsibilities:

- fetch bounded provider data;
- identify folder/placement semantics;
- provide raw provider authentication/relay/forwarding evidence;
- provide provider-native identifiers needed for later actions;
- report evidence provenance and completeness;
- never score risk or choose a verdict.

### Canonical Evidence Normalizer

Responsibilities:

- convert provider-specific data into one canonical envelope/evidence contract;
- preserve evidence provenance separately from evidence value;
- separate outer transport/relay identity from resolved original sender identity;
- normalize registrable domains consistently;
- normalize Reply-To, display identity, destination domains, folder placement, authentication state, relationship state, and content inspection coverage;
- reject logically impossible evidence before it can reach scoring.

### Structural Detection Core

Responsibilities:

- extract reusable scam structure from content and identity evidence;
- reason over relationships between claims, transactions, requested actions, identities, destinations, and historical context;
- emit independent evidence families rather than keyword-driven score jumps;
- preserve explainability for every fired finding;
- use the same primitives for connected mailbox scans and consumer safety tools where the input supports them.

### Verdict/Action Policy

Responsibilities:

- combine validated evidence families using one provider-neutral policy;
- preserve Safe/Review/High Risk/Confirmed Threat/Unknown semantics;
- fail closed when coverage/provenance is insufficient;
- prevent user trust/history from suppressing hard threat contradictions;
- map verdicts to product actions without provider-specific scoring forks.

## Universal provenance and identity confidence

### Problem

The current iCloud evidence shows two simultaneous failures:

- legitimate mail is often trapped in Unknown/Review because trusted provenance is discarded or unresolved;
- suspicious mail can occupy the same Unknown bucket, so simply relaxing the Safe gate would weaken protection.

This requires better evidence resolution, not a lower threshold.

### Provenance & Relationship Confidence Graph

The canonical model must distinguish:

- provider trust boundary;
- outer transport sender/relay;
- validated forwarding/relay lineage;
- resolved original sender identity where provable;
- SPF/DKIM/DMARC/ARC results plus provenance;
- display identity;
- Reply-To identity;
- destination identity;
- local relationship history;
- user trust state;
- inspection completeness.

The graph can increase confidence only when evidence is positively proven. It cannot infer trust from appearance alone.

Apple Private Relay and other forwarder transformations must never become blanket allowlists. A relay-shaped local part or `privaterelay.appleid.com` domain is not proof. Trust requires validated lineage/metadata plus consistency with the rest of the evidence graph.

Relationship history remains context, not trust. Repeated historically clean authenticated behavior may help satisfy an identity prerequisite only when there is no new hard contradiction. A compromised known sender must still escalate if the new message introduces auth failure, Reply-To divergence, credential capture, payment coercion, malicious destinations, dangerous attachments, or other hard evidence.

## Universal structural scam reasoning

### Problem

Current Spam/Junk evidence shows real scam campaigns changing from High Risk to Review when one phrase-level trigger, such as callback wording, disappears. A smart attacker can paraphrase around that.

### Claim-Transaction-Action Consistency Graph

The detector must extract structural slots independently from exact wording:

1. claimed institution/brand/service identity;
2. claimed event, such as invoice, payment, refund, subscription, login, account restriction, inheritance, job, or support incident;
3. money/asset/payment instrument, such as card, bank transfer, crypto, gift card, invoice amount, refund, or cash-equivalent code;
4. requested action, such as call, reply, click, pay, install software, send OTP/code, disclose a credential, move money, scan QR, or contact a supplied support channel;
5. urgency, consequence, secrecy, pressure, or bypass-normal-process language;
6. resolved sender identity and authentication state;
7. Reply-To identity;
8. displayed versus actual destination identity;
9. provider folder placement;
10. local relationship/history context;
11. attachment/QR/destination security evidence;
12. inspection completeness.

Risk comes from contradictory topology across these slots, not from a single keyword.

Examples:

- claimed PayPal transaction + Bitcoin purchase + unrelated sender origin + suspicious history + Spam placement remains suspicious even if `call us` disappears;
- gift card purchase + request to send codes/photos + urgency/secrecy is structurally dangerous whether delivered by email, pasted text, or Shopping Safety;
- OTP request + security-department impersonation + supplied callback/channel is dangerous even if wording changes;
- remote-access software + bank impersonation + account-protection pressure compounds structurally;
- legitimate authenticated brand notifications with consistent origin/destination and no coercive contradictions remain protected from false positives.

### Evidence integrity

Every evidence object must be internally valid before scoring. Examples:

- a registrable domain cannot mismatch itself;
- a relay/intermediary domain cannot be treated as the claimed-brand origin when validated lineage proves a different original identity;
- duplicated observations from the same underlying fact cannot count as independent evidence families;
- missing auth/context cannot be converted into auth failure;
- Spam placement cannot satisfy a hard-threat requirement by itself.

Invalid evidence is discarded and diagnosed, not scored.

## Shared consumer safety primitives

The product currently exposes multiple safety surfaces. They must not become independent weak mini-detectors.

### Connected mailbox scanning

Uses the full canonical envelope, provider provenance, relationship context, structural content evidence, links/QR/attachments, intelligence, and policy state.

### Check Anything / .eml

Must route through the same structural detector. Pasted text naturally lacks provider provenance; that absence remains explicit uncertainty rather than using a weaker phrase-only detector. `.eml` parsing must produce the same canonical content/header evidence shape as connected mailbox mail where equivalent data is present.

### Payment / callback / remote-access check

Reuses shared action, coercion, impersonation, payment, OTP, gift-card, remote-access, and secrecy primitives. It may return a workflow-specific recommendation, but it cannot own a separate scam vocabulary that contradicts mailbox scanning.

### Shopping Safety

Reuses shared payment/action/coercion/price-anomaly/gift-card/crypto/irreversibility primitives plus explicit user-supplied storefront information. It must not invent merchant reputation. Unknown external reputation remains Unknown while structural fraud evidence can still produce High Risk.

## Link and destination integrity

EMA-7 and EMA-10 are repaired after structural detection because destination evidence feeds the universal graph.

Requirements:

- percent-encoded absolute URLs are normalized only when the complete decoding is unambiguous and safe;
- malformed or ambiguous values remain uninspectable, never silently rewritten into another destination;
- valid public HTTPS destinations must not become Unknown because of avoidable transport/classification defects;
- loopback, private, link-local, and prohibited network targets are rejected before any outbound connection;
- redirects are revalidated at every hop;
- DNS/connection safety remains pinned/fail-closed;
- mailbox cookies/provider credentials are never used by Analyze Links;
- inability to inspect remains Unknown/Review rather than Safe.

## Background protection and release-mode integrity

EMA-18 and EMA-23 are release-critical because hidden scheduler state and exposed development entitlement controls undermine consumer truthfulness.

Background protection must have one authoritative persisted state consumed by both UI and scheduler. Selecting a mailbox must not implicitly enable an undocumented ~2-minute loop. Minimum/maximum interval contracts must be enforced by the scheduler itself, not only by UI validation. Disconnect must remove or deactivate the corresponding schedule.

Normal consumer mode must not expose development entitlement switching/preview controls. Server-side production entitlement validation remains authoritative and must continue rejecting development switching outside explicit engineering mode.

## Action and lifecycle correctness

Message actions must use capability ownership scoped to the actual action, not a global one-action-per-message lock. Analyze Links, Unsubscribe, Mark Safe, Report Scam, Move to Spam/Junk, and related actions may have distinct preconditions and idempotency rules.

Provider mailbox state is the final truth for destructive/mutating actions. Health cleanup must resolve the exact target set and verify the provider-side outcome before reporting success. Disconnect must clean active profile-mailbox relationships so Family/profile metadata cannot target a removed mailbox.

## Diagnostic truth

The flight recorder and Support Bundle are repaired only after the main workflows stabilize so diagnostics describe the repaired architecture rather than stale ownership.

Diagnostics must correlate:

`consumer action -> workflow -> protected API -> service/core/provider/storage checkpoints -> terminal backend result -> terminal visible UI result`

The privacy boundary remains strict: no raw mail content, sender/recipient/mailbox identity, subjects, raw URLs, provider-native message IDs, credentials/tokens, Family private data, device keys, typed secrets, or raw exception text/stacks.

Support metrics must reconcile with the same authoritative scheduler/scan/action state used by the product so diagnostics cannot claim zero provider scans while Activity records repeated automatic scans.

## Consumer composition

After correctness/security repair, consumer UI defects are closed without hiding unresolved backend behavior.

Community must become a consumer threat/campaign surface; provider transport counters and engineering operations move to diagnostics/developer-only surfaces.

Health must canonicalize duplicate identities while preserving semantically distinct unsubscribe/security records, and security-alert cards must be distinguishable by service/category/time/count where evidence supports it.

Activity gets a consumer detail view backed by already-recorded privacy-safe event data.

Notification settings must correspond to a real notification owner/status/delivery path or be explicitly deferred rather than leaving an orphan control.

Home onboarding must use capability-specific prerequisites rather than one shared mailbox guard. Review permissions must work; first-scan guidance must distinguish local Scam Check from mailbox scanning; sensitivity must explain its mailbox prerequisite or persist a pre-connection choice; Family review/skip and Home confirmation must not be blocked by an unrelated mailbox requirement; continuous-protection onboarding must reach real state/control.

Restore-purchase terminal status must be prominent and accessible. Media Authenticity must remain unavailable/hidden until a vetted detector exists; no fabricated authenticity verdict is permitted.

## Execution order

### Wave 0: regression shield

Before modifying shared core behavior, capture RED reproductions for owner-observed failures and negative-control regressions for existing good behavior.

Required corpus includes:

- legitimate Apple, Instagram, NayaPay, RedotPay, Foodpanda, Glovo, Alibaba and other relay/forwarder examples from the current owner scans;
- suspicious unknown-origin examples from the same scans;
- exact PayPal/Bitcoin campaign variants that oscillate between Review and High Risk;
- same campaign paraphrased without callback wording;
- gift-card/code-photo, OTP/security-department, crypto-time-pressure, remote-access/bank, payment-review, and malicious `.eml` cases from EMA-9/19/21;
- hard-ham legitimate invoices, account alerts, marketing, provider Spam false positives, and authenticated payment receipts;
- forged Authentication-Results and fake Private Relay-shaped identities;
- trusted/known sender acquiring a new hard contradiction;
- same-domain claim that must never produce mismatch;
- cross-provider parity fixtures where equivalent canonical evidence must yield identical core results.

### Wave 1: universal detection integrity

Close EMA-31 and EMA-32 in the canonical normalizer/core first, then route EMA-9, EMA-19, and EMA-21 through the shared primitives.

### Wave 2: link/destination integrity

Close EMA-7 and EMA-10 while preserving SSRF/DNS pinning/fail-closed behavior.

### Wave 3: protection lifecycle and release mode

Close EMA-18 and EMA-23.

### Wave 4: provider/message action correctness

Close EMA-8, EMA-6, EMA-16, and EMA-25.

### Wave 5: diagnostic truth

Rebase/adapt EMA-5 diagnostic recorder to the repaired workflow ownership, then close EMA-20.

### Wave 6: Health and consumer composition

Close EMA-17, EMA-15, EMA-11, EMA-12, EMA-13, EMA-26, EMA-27, EMA-28, EMA-29, EMA-30, EMA-24, and EMA-22.

EMA-14 remains external entitlement acceptance rather than a defect to bypass. Outlook live acceptance remains deliberately deferred until this repair program is green.

## Testing and acceptance

Every implementation unit must have a reviewer-rejectable boundary and its own TDD cycle.

Required gates:

1. targeted RED test fails for the owner-reproduced defect;
2. production repair makes that exact test GREEN;
3. hard-ham/legitimate controls remain GREEN;
4. cross-provider parity proves provider adapters do not change decision logic;
5. incomplete inspection cannot become Safe;
6. forged auth/relay metadata cannot gain trust;
7. hard contradictions override relationship/user trust;
8. SSRF/private-address blocks happen before outbound connection;
9. production entitlement cannot be switched by development UI/API paths;
10. full Windows/macOS/Linux engineering gate passes on the frozen repair head;
11. only that exact verified SHA may merge;
12. merged `main` independently passes the same gate;
13. one consolidated owner live reacceptance covers only workflows changed by repairs.

## Definition of done

The universal repair program is complete when every confirmed code/workflow defect in EMA-33 is root-fixed and regression-locked, equivalent normalized evidence receives equivalent Email Shield decisions across providers, already-working security/privacy behavior is preserved, and the only remaining work is deliberate external acceptance such as legitimate Family entitlement and deferred Outlook/Microsoft live acceptance.