# Universal Detection Integrity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Repair EMA-31, EMA-32, EMA-9, EMA-19 and EMA-21 by making scam detection and identity/coverage reasoning provider-neutral, structurally robust to paraphrase, and shared across mailbox scans and consumer safety tools without weakening fail-closed behavior.

**Architecture:** Keep the existing `CanonicalEnvelope -> scanMessage -> layerResults -> computeVerdict` pipeline as the single authoritative mailbox/Scam Check decision path. Add one pure structural-content extractor and one structural-consistency layer; refactor existing intent/consumer tools to consume those primitives instead of maintaining independent phrase switches. Repair IMAP content completeness at the acquisition boundary and repair relay/claim uncertainty at the identity layer; do not weaken Authentication-Results provenance rules or `HIGH_RISK_THRESHOLD = 6`.

**Tech Stack:** TypeScript, Node.js, Vitest 4, existing Portable Core, Gmail API/IMAP adapters, deterministic local text normalization, `tldts` domain relation helpers.

## Global Constraints

- Base architecture authority: `docs/superpowers/specs/2026-08-16-universal-email-shield-repair-design.md`.
- Linear execution authority: EMA-33. This plan directly targets EMA-31, EMA-32, EMA-9, EMA-19 and EMA-21.
- Provider adapters may acquire/normalize facts only. No adapter-specific score, verdict, Safe exception, brand list, scam vocabulary or threshold.
- Preserve `.engineering/AUTHENTICATION_RESULTS_PROVENANCE.md`: untrusted MIME Authentication-Results cannot grant trust **or** create authentication-failure evidence.
- Do not set `authentication.providerTrust = "trusted"` for live Gmail/iCloud/Yahoo/IMAP/Outlook based only on mailbox login, guessed authserv-id, provider branding or header presence.
- Keep `HIGH_RISK_THRESHOLD = 6` and `REVIEW_THRESHOLD = 2`; this repair must improve evidence quality, not lower thresholds.
- Full or safely proven content completeness may allow an ordinary Safe verdict without authentication; partial/bounded content must remain fail-closed unless the existing trusted-identity prerequisite is actually satisfied.
- A known relay with unproven origin must create identity uncertainty, not a false mismatch and not positive trust.
- Relationship history remains context, not an allowlist. Existing authenticated-history requirements remain intact in this plan.
- Same underlying fact must not be emitted twice under two new structural codes solely to cross the High Risk threshold.
- Consumer tools may present workflow-specific recommendations, but shared scam facts come from the same extractor used by mailbox scanning.
- No raw owner mailbox contents are committed to the public repository. Owner failures are reproduced with synthetic equivalents preserving the same structural topology.
- Every production change begins only after its targeted RED test fails for the expected reason.

---

## File map

### New files

- `server/src/engine/structuralScamEvidence.ts` — pure extraction of normalized scam facts from subject/body/link text; no scores/verdicts/provider branching.
- `server/src/engine/layers/structuralConsistency.ts` — combines extracted scam facts with canonical identity/folder/link context and emits validated provider-neutral evidence.
- `tests/unit/universalDetectionOwnerRegressions.test.ts` — synthetic reproductions of owner-observed false negatives/false positives.
- `tests/unit/universalDetectionProviderParity.test.ts` — proves provider adapters cannot alter decisions once normalized evidence is equivalent.
- `tests/unit/structuralScamEvidence.test.ts` — extractor contract and paraphrase/adversarial tests.

### Existing files modified by this plan

- `server/src/engine/pipeline.ts` — add structural consistency exactly once in the shared layer list.
- `server/src/engine/layers/messageIntent.ts` — retain useful legacy evidence but reuse structural facts and remove phrase-level behavior that duplicates the new structural layer.
- `server/src/engine/layers/identityImpersonation.ts` — reject impossible same-domain mismatch; handle unproven relays as uncertainty instead of false brand mismatch.
- `server/src/engine/identitySignals.ts` — expose identity-resolution helpers without weakening `authenticationResultsTrusted`.
- `server/src/engine/verdict.ts` — no threshold change; only add evidence-integrity guard if required to reject malformed/duplicate new structural evidence.
- `server/src/adapters/imap/mimeParts.ts` — expose declared-size/completeness information needed for safe complete text acquisition.
- `server/src/adapters/imap/imapAdapter.ts` — fetch complete readable MIME alternatives when they fit the approved resource budget; preserve partial status when they do not.
- `server/src/util/mimeNormalize.ts` — keep common completeness semantics and untrusted raw Authentication-Results default.
- `server/src/core/portableCore.ts` / `portableCoreStrict.ts` — only if a canonical-contract field actually changes; this plan is designed to avoid a schema change unless RED evidence proves one is necessary.
- `server/src/consumer/scamCheck.ts` — preserve the existing shared `scanMessage` route and surface new evidence categories correctly.
- `server/src/consumer/scamCheckInputs.ts` — preserve `.eml` forced-untrusted provenance while proving structural parity.
- `server/src/consumer/intervention.ts` — replace separate gift-card/OTP/crypto action detection with shared structural facts.
- `server/src/consumer/shoppingSafety.ts` — replace duplicated payment/pressure detection with shared structural facts while preserving no-invented-reputation behavior.
- `tests/unit/generalizedIdentityArchitecture.test.ts`
- `tests/unit/authenticationResultsProvenance.test.ts`
- `tests/unit/consumerScamCheck.test.ts`
- `tests/unit/scamCheckInputs.test.ts`
- `tests/unit/shoppingSafetyIntegration.test.ts`
- `tests/integration/corpusScan.test.ts`
- `.engineering/REGRESSION_REGISTER.md`
- `.engineering/TEST_MATRIX.md`

---

### Task 1: Freeze the owner failures and hard-ham controls as RED regressions

**Files:**
- Create: `tests/unit/universalDetectionOwnerRegressions.test.ts`
- Modify only if a shared builder is clearly reusable: `tests/unit/generalizedIdentityArchitecture.test.ts`

**Interfaces:**
- Consumes: current `scanMessage`, `evaluateConsumerScamCheck`, `evaluateSubmittedEml`, `assessScamIntervention`, `analyzeShoppingSafety`.
- Produces: an executable acceptance corpus that must stay green for every later task.

- [ ] **Step 1: Add a local canonical-envelope builder that cannot accidentally grant authentication**

In `tests/unit/universalDetectionOwnerRegressions.test.ts`, create:

```ts
function envelope(overrides: Partial<CanonicalEnvelope> = {}): CanonicalEnvelope {
  return {
    provider: "imap",
    accountProof: "owner-regression-proof",
    messageId: "owner-regression-message",
    providerNativeId: "owner-regression-native",
    folder: "inbox",
    providerFolderName: "INBOX",
    from: { displayName: null, address: "notice@sender.example", domain: "sender.example" },
    replyTo: null,
    subject: "",
    date: new Date(0).toISOString(),
    authentication: { providerTrust: "unknown", spf: "unknown", dkim: "unknown", dmarc: "unknown", arc: "unknown" },
    textPreview: "",
    htmlSignals: null,
    links: [],
    attachments: [],
    listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
    threadContext: { isFirstContact: true, threadContinuityBroken: false, replyToChangedMidThread: false },
    parseStatus: "complete",
    parseNotes: [],
    diagnostics: { fetchedAt: new Date(0).toISOString(), sizeBytes: 512, encoding: "plain", contentCoverage: "complete" },
    ...overrides,
  };
}
```

Use `.example` identities only. Do not paste real owner mailbox addresses, message bodies, provider IDs or private scan exports into git.

- [ ] **Step 2: Add RED paraphrase-stability tests for EMA-32**

Create two synthetic messages representing the same fraudulent topology:

```ts
const variants = [
  "PayPal payment received. Bitcoin order processing. Contact support if this was not you.",
  "PayPal payment confirmation. A Bitcoin purchase is now in progress. Review the transaction through support.",
];
```

Use sender `billing@unrelated-school.example`, display name `PayPal Billing`, and Spam/Junk only in one variant. Assert both remain `high_risk` and the second cannot fall to `review` merely because no phone/callback phrase exists.

- [ ] **Step 3: Add RED false-negative tests for EMA-9/19/21**

Add synthetic controls matching the owner failures:

```ts
"Your manager needs $500 in Apple gift cards today. Send clear photos of the codes. Do not call; keep this between us."
"Security department here. Read back the one-time verification code so we can stop the account lock."
"Send 800 USDT to the wallet within 30 minutes to release the payment review. This transfer cannot be reversed."
"Bank fraud team: install AnyDesk so we can secure the account and process the refund."
```

Required assertions:
- `evaluateConsumerScamCheck(...).verdict` is `high_risk` for the first three.
- `assessScamIntervention(...).signals` contains a `critical` signal for gift-card code exfiltration, OTP/account-secret exfiltration, crypto time pressure, and bank + remote-access.
- `analyzeShoppingSafety(...)` returns `high_risk` for gift-card-code and crypto-pressure purchase scenarios even when destination reputation is Unknown.

- [ ] **Step 4: Add RED impossible-evidence and hard-ham controls**

Add tests that:
- `from.domain = "free-ethereum.example"` plus an explicit `free-ethereum.example` claim can never emit `EXPLICIT_DOMAIN_CLAIM_MISMATCH`.
- a normal authenticated same-domain payment receipt is not High Risk.
- a normal authenticated account-security notification is not High Risk merely because it says “verify”, “security”, or “account”.
- Spam/Junk placement alone never creates High Risk.
- a forged `Authentication-Results: dmarc=pass` with `providerTrust: "unknown"` does not authenticate or suppress scam evidence.
- a trusted/known-history sender with a new gift-card/OTP/payment hard contradiction still escalates.

- [ ] **Step 5: Add a RED `.eml` parity test**

Build a synthetic RFC822 buffer containing the gift-card/code-photo scam and a forged `Authentication-Results` pass. Assert `evaluateSubmittedEml()` keeps transport provenance untrusted **and** reaches the same scam verdict family as pasted text.

- [ ] **Step 6: Run only the new regression file and verify RED for the expected missing behaviors**

Run:

```bash
npx vitest run tests/unit/universalDetectionOwnerRegressions.test.ts
```

Expected: existing benign/provenance assertions pass; the owner false-negative/paraphrase tests fail because current phrase-triggered logic does not produce enough structural evidence. Record the failing test names in the PR/Linear comment before production code changes.

- [ ] **Step 7: Commit the RED corpus only**

```bash
git add tests/unit/universalDetectionOwnerRegressions.test.ts
git commit -m "test: lock universal detection owner regressions"
```

---

### Task 2: Build one pure structural scam-fact extractor

**Files:**
- Create: `server/src/engine/structuralScamEvidence.ts`
- Create: `tests/unit/structuralScamEvidence.test.ts`
- Reuse: `server/src/engine/securityText.ts`

**Interfaces:**
- Produces:

```ts
export type TransactionEvent = "invoice" | "payment" | "purchase" | "refund" | "subscription" | "login" | "account_restriction" | "inheritance" | "job" | "prize" | "support_incident";
export type PaymentInstrument = "bank_transfer" | "card" | "crypto" | "gift_card" | "cash_app" | "unknown_money";
export type RequestedAction = "call" | "reply" | "open_link" | "scan_qr" | "pay" | "install_remote_access" | "send_otp" | "send_recovery_secret" | "send_gift_card_code" | "move_money";
export type PressureSignal = "urgent" | "deadline" | "account_loss" | "secrecy" | "no_independent_contact" | "irreversible";

export interface StructuralScamFacts {
  events: TransactionEvent[];
  paymentInstruments: PaymentInstrument[];
  requestedActions: RequestedAction[];
  pressure: PressureSignal[];
  organizationClaims: string[];
}

export function extractStructuralScamFacts(input: {
  subject?: string | null;
  text?: string | null;
  htmlText?: string | null;
  displayName?: string | null;
  links?: readonly Pick<LinkInfo, "visibleText" | "rawUrl" | "normalizedUrl" | "source">[];
}): StructuralScamFacts;
```

- [ ] **Step 1: Write extractor tests before the module exists**

Tests must prove concept extraction survives wording changes:
- `buy Apple gift cards` and `purchase Apple vouchers` both produce `gift_card` + `pay`/`send_gift_card_code` when code/photo transmission is requested;
- `send a picture of the codes` and `reply with the card numbers` both map to `send_gift_card_code`;
- `verification code`, `one-time code`, `OTP`, and `passcode` in a request-to-share context map to `send_otp`;
- crypto + `within 30 minutes` maps to `crypto` + `deadline`; irreversible wording maps to `irreversible`;
- AnyDesk/TeamViewer/Quick Assist map to `install_remote_access` only when installation/control is requested;
- a plain legitimate mention (“We support gift cards in our store”; “Your OTP was used to sign in”) does **not** create an exfiltration/request action.

- [ ] **Step 2: Verify RED**

```bash
npx vitest run tests/unit/structuralScamEvidence.test.ts
```

Expected: module/import missing or assertions fail because the extractor does not exist.

- [ ] **Step 3: Implement the extractor as parsing only**

Use `normalizeSecurityText()` and small concept lexicons/grammars to extract facts. Do **not** return scores or verdicts. Keep organization-claim extraction generic:
- repeated organization-like display-name/subject identity;
- leading organization phrase before a transactional noun in the subject (for example `PayPal Payment ...` becomes claim token `paypal` without adding a PayPal allow/deny mapping);
- explicit domain claims remain handled by identity/domain logic, not a brand database.

Ensure extracted arrays are unique and deterministically ordered.

- [ ] **Step 4: Verify GREEN and benign negatives**

```bash
npx vitest run tests/unit/structuralScamEvidence.test.ts
```

Expected: PASS, including all negative controls.

- [ ] **Step 5: Commit**

```bash
git add server/src/engine/structuralScamEvidence.ts tests/unit/structuralScamEvidence.test.ts
git commit -m "feat: extract provider-neutral structural scam facts"
```

---

### Task 3: Repair identity-claim integrity before adding new risk scores

**Files:**
- Modify: `server/src/engine/layers/identityImpersonation.ts`
- Modify: `server/src/engine/identitySignals.ts`
- Modify: `tests/unit/generalizedIdentityArchitecture.test.ts`
- Modify: `tests/unit/authenticationResultsProvenance.test.ts`

**Interfaces:**
- Consumes: `extractStructuralScamFacts()` only for generic organization claims; existing `sameOrganizationalDomain`, `organizationalDomain`, `isKnownSenderRelay`, `verifiedRelayOriginDomains`.
- Produces: logically valid identity evidence; no new positive trust source.

- [ ] **Step 1: Add RED tests for the exact identity defects**

Add tests that:
1. same organizational domain explicit claim never emits `EXPLICIT_DOMAIN_CLAIM_MISMATCH`, even when auth provenance is unknown;
2. an unrelated explicit domain still emits mismatch when the sender is non-relay;
3. a known relay with no proven origin does **not** emit `BRAND_DOMAIN_MISMATCH` merely because its outer relay domain differs from a claimed organization;
4. the same unproven relay does not gain `authenticationPassed()` or an authenticated identity;
5. an authenticated relay with proven encoded origin retains current verified-origin behavior;
6. forged relay-shaped local parts with untrusted authentication cannot create a verified origin.

Run:

```bash
npx vitest run tests/unit/generalizedIdentityArchitecture.test.ts tests/unit/authenticationResultsProvenance.test.ts
```

Verify the same-domain/unproven-relay cases fail for the expected current behavior before editing production code.

- [ ] **Step 2: Fix explicit-domain mismatch at the source**

Before emitting `EXPLICIT_DOMAIN_CLAIM_MISMATCH`, compare the claimed registrable domain against:
- the visible sender registrable domain;
- any authenticated sender identity domain;
- any **verified** relay origin domain.

If the claimed domain equals the visible sender registrable domain, it is logically impossible to call it a mismatch even when authentication is unknown. This removes invalid evidence but grants no trust.

- [ ] **Step 3: Make unproven relays uncertain instead of contradictory**

When `isKnownSenderRelay(senderDomain)` is true and `verifiedRelayOriginDomains(envelope)` is empty, do not compare organization claim words against the outer relay label. Return the layer with an `incompleteReason` such as:

```ts
"The sender is a relay/forwarder and Email Shield could not prove the original organizational identity."
```

Do not set `blocksSafeVerdict` from this identity-layer uncertainty alone; ordinary fully inspected mail can still be Safe, while partial/bounded content remains governed by the existing safe gate.

- [ ] **Step 4: Preserve the authentication provenance contract**

Do not change `authenticationResultsTrusted()` or make `relayAliasDomainCandidates()` authoritative. Verify all forged-header and forged-relay tests remain green.

- [ ] **Step 5: Run focused tests**

```bash
npx vitest run tests/unit/generalizedIdentityArchitecture.test.ts tests/unit/authenticationResultsProvenance.test.ts
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add server/src/engine/layers/identityImpersonation.ts server/src/engine/identitySignals.ts tests/unit/generalizedIdentityArchitecture.test.ts tests/unit/authenticationResultsProvenance.test.ts
git commit -m "fix: reject impossible and relay-uncertain identity evidence"
```

---

### Task 4: Add structural consistency as one shared detection layer

**Files:**
- Create: `server/src/engine/layers/structuralConsistency.ts`
- Modify: `server/src/engine/pipeline.ts`
- Modify: `server/src/engine/layers/messageIntent.ts`
- Modify: `tests/unit/universalDetectionOwnerRegressions.test.ts`
- Modify: `tests/unit/identityIntentBehavioralCertification.test.ts`
- Modify: `tests/unit/adaptiveVerdictSafety.test.ts`

**Interfaces:**
- Produces:

```ts
export function structuralConsistencyLayer(envelope: CanonicalEnvelope): LayerResult;
```

The layer consumes `extractStructuralScamFacts()` and emits a **small number of compound structural evidence codes**. Required initial codes:

```text
IMPERSONATED_TRANSACTION_ORIGIN
GIFT_CARD_CODE_EXFILTRATION
ACCOUNT_SECRET_EXFILTRATION
IRREVERSIBLE_PAYMENT_PRESSURE
REMOTE_ACCESS_FINANCIAL_PRESSURE
SECRECY_PAYMENT_DIVERSION
```

- [ ] **Step 1: Extend RED assertions to evidence families, not only verdicts**

For each owner scenario, assert which structural code must exist. This prevents a future unrelated score from making the test green accidentally.

- [ ] **Step 2: Verify RED**

```bash
npx vitest run tests/unit/universalDetectionOwnerRegressions.test.ts
```

Expected: new evidence-code assertions fail because the structural layer does not exist.

- [ ] **Step 3: Implement compound evidence rules**

Rules must require topology, not one word:

- `GIFT_CARD_CODE_EXFILTRATION`: gift-card instrument **and** requested transmission of codes/card numbers/photos. Base contribution 4. Add no second code from the same two facts.
- `ACCOUNT_SECRET_EXFILTRATION`: OTP/recovery/password/seed secret **and** request to disclose/send/read it to the message/caller. Contribution 4.
- `IRREVERSIBLE_PAYMENT_PRESSURE`: crypto/bank-transfer/gift-card/cash-equivalent payment **and** deadline/urgency/irreversibility. Contribution 4.
- `REMOTE_ACCESS_FINANCIAL_PRESSURE`: remote-access installation/control request **and** bank/refund/payment/account-security context. Contribution 4.
- `SECRECY_PAYMENT_DIVERSION`: value transfer **and** secrecy/no-independent-contact instruction. Contribution 3.
- `IMPERSONATED_TRANSACTION_ORIGIN`: a generic organization claim tied to a payment/purchase/refund/account event **and** sender/Reply-To origin contradiction. Contribution 3 or 4 based on whether an independent Reply-To/destination contradiction also exists. Do not emit it when the organization claim aligns with the sender/verified identity.

The High Risk threshold remains 6. High Risk is reached through genuinely independent combinations such as identity contradiction + payment pressure, or secret exfiltration + secrecy/urgency.

- [ ] **Step 4: Remove duplicate phrase-trigger scoring from `messageIntentLayer` where the new layer owns the same fact**

Keep legacy intent rules that represent distinct evidence and multilingual coverage. Do not leave both `CALLBACK_SCAM_INTENT` and a new structural code counting the same invoice+callback fact twice. Callback/phone remains an additional requested action, not the switch that decides whether the underlying transaction is suspicious.

- [ ] **Step 5: Insert the layer exactly once in `scanMessage()`**

Place `structuralConsistencyLayer(envelope)` after identity/transport context is available and before destination/attachment/personal/global results are aggregated. There must be no provider condition around the call.

- [ ] **Step 6: Run focused owner + legacy safety suites**

```bash
npx vitest run tests/unit/universalDetectionOwnerRegressions.test.ts tests/unit/identityIntentBehavioralCertification.test.ts tests/unit/adaptiveVerdictSafety.test.ts tests/unit/verdict.test.ts
```

Expected: owner paraphrase cases GREEN, benign controls GREEN, thresholds unchanged.

- [ ] **Step 7: Commit**

```bash
git add server/src/engine/layers/structuralConsistency.ts server/src/engine/pipeline.ts server/src/engine/layers/messageIntent.ts tests/unit/universalDetectionOwnerRegressions.test.ts tests/unit/identityIntentBehavioralCertification.test.ts tests/unit/adaptiveVerdictSafety.test.ts
git commit -m "feat: score structural scam contradictions in shared core"
```

---

### Task 5: Reduce false Unknown safely by repairing IMAP content completeness, not by relaxing Safe

**Files:**
- Modify: `server/src/adapters/imap/mimeParts.ts`
- Modify: `server/src/adapters/imap/imapAdapter.ts`
- Modify: existing IMAP MIME/body tests (use the existing test file that currently exercises `fetchBoundedReadableBodies`; if multiple exist, modify the one importing that function rather than creating a duplicate harness)
- Modify: `tests/unit/universalDetectionOwnerRegressions.test.ts`

**Interfaces:**
- Keep current `BoundedReadableBodies` return shape but make `truncated` accurately mean at least one selected readable alternative was not completely obtained.
- Introduce one exported acquisition constant in `mimeParts.ts` or the existing IMAP resource-limit module:

```ts
export const MAX_COMPLETE_READABLE_PART_BYTES = 256 * 1024;
```

This is a resource cap, not a risk threshold.

- [ ] **Step 1: Write RED acquisition tests**

Construct body-structure selections where:
- a 60 KiB text/plain part is currently truncated by the old 48 KiB encoded fetch despite fitting the new complete budget;
- a 180 KiB HTML part fits the complete budget;
- a 400 KiB HTML part exceeds the budget and must remain truncated/partial;
- a provider response shorter than the declared MIME part remains incomplete;
- no full-message fallback occurs.

Assert that under-budget parts can be proven complete and over-budget/short parts cannot.

- [ ] **Step 2: Verify RED**

Run the exact IMAP unit file plus:

```bash
npx vitest run tests/unit/universalDetectionOwnerRegressions.test.ts
```

Expected: under-budget completeness assertions fail under the current 48 KiB/24 KiB acquisition behavior.

- [ ] **Step 3: Implement declared-size-aware complete part fetching**

For each selected readable MIME alternative:
- if the declared encoded part size is known and `<= MAX_COMPLETE_READABLE_PART_BYTES`, request the complete part with a one-byte completeness sentinel where the IMAP API allows it;
- reject/mark incomplete when the returned bytes are shorter than a declared complete part;
- decode within the same bounded local resource budget;
- if the declared size is unknown or above the budget, retain bounded acquisition and `truncated = true`;
- never fetch the whole RFC822 message as fallback;
- keep QR/attachment bounds unchanged.

- [ ] **Step 4: Preserve universal completeness semantics**

`imapAdapter.ts` may set `parseStatus = "complete"` / `contentCoverage = "complete"` only when every selected security-relevant readable alternative was completely obtained and HTML/link extraction itself was not incomplete. Otherwise keep `partial` with `bounded_sufficient` or `insufficient` exactly as today.

Do **not** change `boundedContentAllowsSafe()` to allow unauthenticated partial content.

- [ ] **Step 5: Run IMAP + portable-core safety suites**

```bash
npm run test:unit -- --runInBand
npm run check:core
```

If Vitest rejects `--runInBand`, run `npm run test:unit` unchanged; do not alter production/test semantics to accommodate a runner flag.

Required: IMAP body tests, portable-core validation, QR/attachment limits, and owner regression tests GREEN.

- [ ] **Step 6: Commit**

```bash
git add server/src/adapters/imap/mimeParts.ts server/src/adapters/imap/imapAdapter.ts tests/unit
git commit -m "fix: prove complete IMAP readable content within safety budget"
```

---

### Task 6: Prove universal provider-decision parity

**Files:**
- Create: `tests/unit/universalDetectionProviderParity.test.ts`
- Modify: `tests/unit/portableCoreVectors.test.ts` only if a conformance vector is the existing canonical location for the same invariant.

**Interfaces:**
- Consumes `scanMessage()` / `scanMessageThroughPortableCore()` with canonical envelopes that differ only in provider/folder-native metadata.
- Produces a permanent architecture guard.

- [ ] **Step 1: Write parity tests**

Create equivalent canonical scam and benign envelopes for `gmail`, `icloud`, `yahoo`, `imap`, and `outlook`. Hold all decision-relevant normalized facts equal. Assert:

```ts
expect(result.scored.verdict).toBe(reference.scored.verdict);
expect(result.scored.score).toBe(reference.scored.score);
expect(result.scored.evidence.map(e => e.code).sort()).toEqual(referenceCodes);
```

Add a second test proving that provider-specific **facts** are allowed to differ: Spam/Junk folder placement or trusted-vs-untrusted auth provenance changes evidence because the normalized input changed, but there is no branch on `envelope.provider` in the decision layers.

- [ ] **Step 2: Add source-architecture assertions**

Read the shared detector files and assert they do not contain provider-specific decision branches such as:

```text
envelope.provider === "icloud"
envelope.provider === "gmail"
envelope.provider === "yahoo"
envelope.provider === "outlook"
```

Provider-specific acquisition code remains allowed in adapters.

- [ ] **Step 3: Verify GREEN**

```bash
npx vitest run tests/unit/universalDetectionProviderParity.test.ts tests/unit/universalDetectionOwnerRegressions.test.ts
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add tests/unit/universalDetectionProviderParity.test.ts tests/unit/portableCoreVectors.test.ts
git commit -m "test: lock provider-neutral detection parity"
```

---

### Task 7: Lock Check Anything and `.eml` to the repaired shared core

**Files:**
- Modify: `server/src/consumer/scamCheck.ts`
- Modify only if needed for parity: `server/src/consumer/scamCheckInputs.ts`
- Modify: `tests/unit/consumerScamCheck.test.ts`
- Modify: `tests/unit/scamCheckInputs.test.ts`
- Modify: `tests/unit/universalDetectionOwnerRegressions.test.ts`

**Interfaces:**
- Preserve `evaluateConsumerScamEnvelope(envelope, deps, limitations)` as the sole canonical-envelope evaluator.
- Preserve `.eml` `providerTrust: "unknown"` override.

- [ ] **Step 1: Add RED/guard tests proving there is no second scorer**

Test the same synthetic gift-card/OTP/crypto scam as:
- pasted message;
- canonical connected-mailbox envelope;
- `.eml` artifact.

Assert the same structural evidence codes are present whenever equivalent text is available. Verdict may remain more conservative for `.eml` because provenance is intentionally untrusted, but it must not become **less risky** because the input route bypassed structural detection.

- [ ] **Step 2: Update explanation category mapping for new structural codes**

Extend `CATEGORY_BY_CODE` in `scamCheck.ts` so structural codes map to existing consumer categories. Do not add scoring in the explanation layer.

- [ ] **Step 3: Keep submitted transport untrusted**

Do not change `forceSubmittedTransportUntrusted()`; add a regression asserting a forged pass inside `.eml` remains non-authoritative.

- [ ] **Step 4: Run consumer Scam Check suites**

```bash
npx vitest run tests/unit/consumerScamCheck.test.ts tests/unit/scamCheckInputs.test.ts tests/unit/universalDetectionOwnerRegressions.test.ts
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add server/src/consumer/scamCheck.ts server/src/consumer/scamCheckInputs.ts tests/unit/consumerScamCheck.test.ts tests/unit/scamCheckInputs.test.ts tests/unit/universalDetectionOwnerRegressions.test.ts
git commit -m "fix: keep Scam Check and eml on universal detector"
```

---

### Task 8: Reuse structural facts in Payment/Callback/Remote-Access intervention

**Files:**
- Modify: `server/src/consumer/intervention.ts`
- Modify/add to the existing intervention unit test file importing `assessScamIntervention`
- Modify: `tests/unit/universalDetectionOwnerRegressions.test.ts`

**Interfaces:**
- `assessScamIntervention(text: string): ScamInterventionAssessment` remains public.
- Internally consumes `extractStructuralScamFacts({ text })`.

- [ ] **Step 1: Verify the Task 1 intervention cases are still RED before production edits**

Run:

```bash
npx vitest run tests/unit/universalDetectionOwnerRegressions.test.ts
```

Confirm gift-card code exfiltration, OTP exfiltration and crypto time pressure fail for the current intervention logic.

- [ ] **Step 2: Replace independent payment/action phrase switches with structural facts**

Map facts to intervention signals:
- `send_gift_card_code` -> critical `GIFT_CARD_CODE_EXFILTRATION`;
- `send_otp` / `send_recovery_secret` -> critical `ACCOUNT_ACCESS_SECRET_REQUEST`;
- `install_remote_access` + financial/account context -> critical `REMOTE_ACCESS_REQUEST`;
- irreversible payment instrument + deadline/urgent pressure -> critical `URGENT_IRREVERSIBLE_PAYMENT_REQUEST`.

Phone extraction may remain local to intervention because displaying detected callback numbers is a workflow-specific feature; whether a callback is suspicious must depend on structural context.

- [ ] **Step 3: Preserve benign callback control**

Normal project callback text with no money, account secret, remote control or coercion must remain without a critical signal.

- [ ] **Step 4: Run focused tests**

```bash
npx vitest run tests/unit/universalDetectionOwnerRegressions.test.ts
```

Plus the existing intervention-specific test file found by import/reference before editing. All must PASS.

- [ ] **Step 5: Commit**

```bash
git add server/src/consumer/intervention.ts tests/unit
git commit -m "fix: reuse structural scam facts for intervention"
```

---

### Task 9: Reuse structural facts in Shopping Safety without inventing reputation

**Files:**
- Modify: `server/src/consumer/shoppingSafety.ts`
- Modify: `tests/unit/shoppingSafetyIntegration.test.ts`
- Modify: `tests/unit/universalDetectionOwnerRegressions.test.ts`

**Interfaces:**
- Preserve `analyzeShoppingSafety(input, dependencies): ShoppingSafetyResultV1`.
- Reuse `extractStructuralScamFacts()` and `assessScamIntervention()`; destination reputation behavior remains unchanged.

- [ ] **Step 1: Add/confirm RED cases**

Required cases:
- Apple gift cards + send code photos + urgency -> `high_risk` even when destination verdict is Unknown;
- USDT/crypto + 30-minute irreversible payment -> `high_risk`;
- extreme bargain + wire/crypto-only + secrecy/no-manufacturer-contact -> at least `high_risk` with explanations covering more than payment method alone;
- normal card purchase control -> no fabricated merchant reputation and no `high_risk` from ordinary commerce language.

- [ ] **Step 2: Replace duplicated payment/urgency regexes with structural facts**

Shopping-specific signals may describe buyer-protection implications, but the underlying payment/action/coercion facts come from the shared extractor. Keep explicit user-supplied storefront text only; do not inspect browser history/orders/cookies.

- [ ] **Step 3: Keep destination Unknown truthful**

A structural scam can be High Risk even when merchant reputation/destination evidence is unavailable. Conversely, absence of structural risk plus Unknown destination must remain `unknown`, not Safe/legitimate.

- [ ] **Step 4: Run focused tests**

```bash
npx vitest run tests/unit/shoppingSafetyIntegration.test.ts tests/unit/universalDetectionOwnerRegressions.test.ts
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add server/src/consumer/shoppingSafety.ts tests/unit/shoppingSafetyIntegration.test.ts tests/unit/universalDetectionOwnerRegressions.test.ts
git commit -m "fix: reuse universal scam structure in shopping safety"
```

---

### Task 10: Run the detection closure gate and record architecture contracts

**Files:**
- Modify: `.engineering/REGRESSION_REGISTER.md`
- Modify: `.engineering/TEST_MATRIX.md`
- Modify only if required by existing governance: `.engineering/CANONICAL_ROADMAP_GAP_AUDIT.md`
- No production behavior changes in this task.

**Interfaces:**
- Produces the permanent gate evidence for Wave 0/1 and the exact SHA eligible for merge/review.

- [ ] **Step 1: Run all affected unit and integration suites**

```bash
npm run typecheck
npm run test:unit
npm run test:integration
npm run check:core
npm run check:core-vectors
npm run check:provider-compatibility
npm run check:regression-vault
```

Every command must pass without changing expected results to hide failures.

- [ ] **Step 2: Run the complete Engineering Gate locally where supported**

```bash
npm run gate
```

Do not interpret a platform-specific local skip as cross-platform acceptance.

- [ ] **Step 3: Update governance records**

Record:
- owner regression cases are synthetic/privacy-safe;
- same-domain impossible evidence is blocked;
- unproven relays are uncertainty, not trust or mismatch;
- structural evidence is provider-neutral;
- Check Anything/.eml/intervention/shopping reuse common primitives;
- IMAP complete-content acquisition is bounded and does not relax partial Safe rules;
- cross-provider parity is executable.

- [ ] **Step 4: Commit governance only**

```bash
git add .engineering/REGRESSION_REGISTER.md .engineering/TEST_MATRIX.md .engineering/CANONICAL_ROADMAP_GAP_AUDIT.md
git commit -m "docs: lock universal detection repair contracts"
```

- [ ] **Step 5: Freeze the repair head and run GitHub Windows/macOS/Linux Engineering Gate**

Push the implementation branch, open/update its PR, and wait for the exact head SHA. Require Windows, macOS, Ubuntu/Linux and fail-closed summary all green on that exact SHA.

- [ ] **Step 6: Review before merge**

Inspect the final diff specifically for:
- provider-specific decision branches outside adapters;
- new brand allow/deny lists;
- threshold changes;
- `providerTrust = "trusted"` introduced without a proven acquisition contract;
- duplicated structural evidence counting the same underlying fact twice;
- removed/relaxed SSRF, privacy, attachment, QR or Portable Core limits;
- real owner mailbox data accidentally committed.

Any finding returns to the relevant RED/root-cause task.

- [ ] **Step 7: Update Linear only from verified evidence**

Comment on EMA-31/32/9/19/21 with the exact frozen SHA, focused regression results and gate run. Mark an issue Done only if its acceptance criteria are actually satisfied; do not close EMA-33 while later waves remain.

## Wave 0/1 completion criteria

Wave 0/1 is accepted only when:

1. observed PayPal/Bitcoin topology stays stable under callback wording removal/paraphrase;
2. gift-card code, OTP secret, crypto time-pressure and bank remote-access controls escalate correctly;
3. legitimate invoices/security notifications/marketing controls do not regress;
4. same-domain mismatch evidence is impossible;
5. unproven relay identity cannot gain trust or create a false outer-domain brand mismatch;
6. more ordinary IMAP mail becomes fully inspected by complete-under-budget acquisition rather than by relaxing Safe rules;
7. oversized/incomplete IMAP mail remains Partial/Unknown as appropriate;
8. forged Authentication-Results cannot grant trust or produce auth-failure evidence;
9. connected-mailbox, pasted-text and `.eml` paths share structural evidence where equivalent content exists;
10. intervention and Shopping Safety reuse the same structural primitives;
11. equivalent normalized evidence produces equivalent core verdicts across Gmail/iCloud/Yahoo/generic IMAP/Outlook provider labels;
12. thresholds, privacy boundaries and security resource limits remain unchanged unless a separately RED-proven security requirement explicitly demands a reviewed change;
13. exact frozen Windows/macOS/Linux Engineering Gate passes before any merge claim.