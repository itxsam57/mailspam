# Universal Detection Integrity Implementation Plan v2

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. REQUIRED for every production change: superpowers:systematic-debugging + superpowers:test-driven-development.

**Goal:** Close EMA-31, EMA-32, EMA-9, EMA-19 and EMA-21 with one provider-neutral detector and better bounded content acquisition, without lowering thresholds or trusting unproven provider metadata.

**Architecture:** Preserve `CanonicalEnvelope -> scanMessage -> LayerResult[] -> computeVerdict` as the authoritative decision path. Add a pure structural-fact extractor and a single structural-consistency layer; feed the same facts into Scam Check, intervention and Shopping Safety. Provider adapters only acquire/normalize evidence.

**Tech Stack:** TypeScript, Node.js, Vitest, Portable Core, Gmail API, IMAP-family adapters.

## Global Constraints
- Base: `af48ed7d2b70b9233aba9595d08aa337cc6b7fbf`.
- Do not change `HIGH_RISK_THRESHOLD = 6` or `REVIEW_THRESHOLD = 2`.
- Do not set live provider auth trust from mailbox login or raw Authentication-Results.
- Do not add provider-specific scoring/verdict branches.
- Partial/incomplete inspection never becomes Safe.
- Relationship history never overrides hard contradictions.
- Do not commit real owner mailbox content; reproduce with synthetic equivalents.
- RED must fail for the intended behavior before production edits.

---

### Task 1: Owner regression shield

**Files:**
- Create: `tests/unit/universalDetectionOwnerRegressions.test.ts`

**Consumes:** `scanMessage`, `evaluateConsumerScamCheck`, `evaluateSubmittedEml`, `assessScamIntervention`, `analyzeShoppingSafety`.

- [ ] Add synthetic RED cases for: PayPal+Bitcoin+unrelated origin with and without callback wording; $500 Apple gift cards + send code photos + secrecy; OTP/security-department exfiltration; 800 USDT + 30-minute irreversible pressure; bank + AnyDesk; malicious `.eml` with forged Authentication-Results.
- [ ] Add hard-ham controls: authenticated same-domain payment receipt; normal authenticated security alert; Spam placement alone; same-domain claim; forged raw Authentication-Results; known sender acquiring a new hard contradiction.
- [ ] Run `npx vitest run tests/unit/universalDetectionOwnerRegressions.test.ts` and record the expected failing assertions.
- [ ] Commit only this test file: `git add tests/unit/universalDetectionOwnerRegressions.test.ts && git commit -m "test: lock universal detection owner regressions"`.

### Task 2: Pure structural scam facts

**Files:**
- Create: `server/src/engine/structuralScamEvidence.ts`
- Create: `tests/unit/structuralScamEvidence.test.ts`

**Produces:**
```ts
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

- [ ] RED tests prove paraphrase equivalence for gift-card code exfiltration, OTP disclosure, crypto deadlines/irreversibility, remote-access requests, and benign mentions that must not become requests.
- [ ] Run `npx vitest run tests/unit/structuralScamEvidence.test.ts` and verify RED.
- [ ] Implement parsing only: normalized concepts, unique deterministic facts, no scores/verdicts/provider branches.
- [ ] Run the same test GREEN.
- [ ] Commit exact files.

### Task 3: Identity evidence integrity

**Files:**
- Modify: `server/src/engine/layers/identityImpersonation.ts`
- Modify: `server/src/engine/identitySignals.ts`
- Modify: `tests/unit/generalizedIdentityArchitecture.test.ts`
- Modify: `tests/unit/authenticationResultsProvenance.test.ts`

- [ ] RED: same registrable domain can never emit `EXPLICIT_DOMAIN_CLAIM_MISMATCH`; unproven known relay creates uncertainty rather than outer-domain brand mismatch; forged relay shape/header cannot gain trust; unrelated non-relay claim still mismatches.
- [ ] Run `npx vitest run tests/unit/generalizedIdentityArchitecture.test.ts tests/unit/authenticationResultsProvenance.test.ts` and verify the new assertions RED.
- [ ] Fix mismatch source comparison against visible sender, authenticated identity and verified relay origin. For known relay with no verified origin, return an incomplete identity explanation instead of brand mismatch; do not grant auth trust.
- [ ] Run focused tests GREEN and commit exact files.

### Task 4: One structural consistency layer

**Files:**
- Create: `server/src/engine/layers/structuralConsistency.ts`
- Modify: `server/src/engine/pipeline.ts`
- Modify: `server/src/engine/layers/messageIntent.ts`
- Modify: `tests/unit/universalDetectionOwnerRegressions.test.ts`
- Modify: `tests/unit/identityIntentBehavioralCertification.test.ts`
- Modify: `tests/unit/adaptiveVerdictSafety.test.ts`

**Produces:** `structuralConsistencyLayer(envelope: CanonicalEnvelope): LayerResult`.

Initial compound evidence codes: `IMPERSONATED_TRANSACTION_ORIGIN`, `GIFT_CARD_CODE_EXFILTRATION`, `ACCOUNT_SECRET_EXFILTRATION`, `IRREVERSIBLE_PAYMENT_PRESSURE`, `REMOTE_ACCESS_FINANCIAL_PRESSURE`, `SECRECY_PAYMENT_DIVERSION`.

- [ ] Add RED assertions for exact evidence codes, not only verdicts.
- [ ] Run owner regression test and verify RED.
- [ ] Implement compound topology rules. A single phrase cannot create High Risk; independent evidence families must combine. Do not double-count the same underlying facts in `messageIntentLayer`.
- [ ] Insert the new layer exactly once in `scanMessage()` with no provider condition.
- [ ] Run `npx vitest run tests/unit/universalDetectionOwnerRegressions.test.ts tests/unit/identityIntentBehavioralCertification.test.ts tests/unit/adaptiveVerdictSafety.test.ts tests/unit/verdict.test.ts` GREEN.
- [ ] Commit exact files.

### Task 5: IMAP completeness without relaxing Safe

**Files:**
- Create: `server/src/adapters/imap/readableBodyFetch.ts`
- Modify: `server/src/adapters/imap/imapAdapter.ts`
- Modify: `server/src/adapters/imap/mimeParts.ts`
- Create: `tests/unit/imapReadableBodyCompleteness.test.ts`

**Produces:** `fetchBoundedReadableBodies(...)` owned by `readableBodyFetch.ts`, with `MAX_COMPLETE_READABLE_PART_BYTES = 256 * 1024` as a resource cap.

- [ ] RED tests: 60 KiB plain and 180 KiB HTML parts are completely obtainable; 400 KiB remains partial; short provider responses remain incomplete; no full-message fallback.
- [ ] Run `npx vitest run tests/unit/imapReadableBodyCompleteness.test.ts` and verify RED.
- [ ] Extract the existing readable-part fetch logic into the new focused module without behavior change, rerun baseline, then implement declared-size-aware complete-under-budget fetching with a completeness sentinel where supported.
- [ ] `imapAdapter.ts` may report complete coverage only when every selected security-relevant readable part and HTML/link extraction is complete. Do not change the Safe gate.
- [ ] Run `npx vitest run tests/unit/imapReadableBodyCompleteness.test.ts tests/unit/universalDetectionOwnerRegressions.test.ts` plus `npm run check:core` GREEN.
- [ ] Commit exact files.

### Task 6: Provider-neutral decision parity

**Files:**
- Create: `tests/unit/universalDetectionProviderParity.test.ts`

- [ ] Build equivalent canonical benign/scam envelopes labeled Gmail/iCloud/Yahoo/IMAP/Outlook with all decision-relevant normalized facts identical.
- [ ] Assert identical score, verdict and evidence-code set.
- [ ] Add source-architecture assertions that shared detector files contain no `envelope.provider ===` decision branches for provider names.
- [ ] Add one control showing normalized folder/auth facts may change output when the **facts** change.
- [ ] Run `npx vitest run tests/unit/universalDetectionProviderParity.test.ts tests/unit/universalDetectionOwnerRegressions.test.ts` GREEN.
- [ ] Commit the exact new test file.

### Task 7: Shared consumer surfaces

**Files:**
- Modify: `server/src/consumer/scamCheck.ts`
- Modify: `server/src/consumer/scamCheckInputs.ts`
- Modify: `server/src/consumer/intervention.ts`
- Modify: `server/src/consumer/shoppingSafety.ts`
- Create: `tests/unit/scamIntervention.test.ts`
- Modify: `tests/unit/consumerScamCheck.test.ts`
- Modify: `tests/unit/scamCheckInputs.test.ts`
- Modify: `tests/unit/shoppingSafetyIntegration.test.ts`
- Modify: `tests/unit/universalDetectionOwnerRegressions.test.ts`

- [ ] RED: equivalent pasted text / canonical mail / `.eml` carry the same structural evidence when content is equivalent; `.eml` forged auth remains untrusted. Intervention must flag gift-card codes, OTP, crypto deadline, bank+remote access. Shopping Safety must detect those structures while preserving Unknown destination reputation.
- [ ] Run all five test files and verify expected RED assertions.
- [ ] Map new core evidence codes to existing Scam Check categories only; no scoring in presentation.
- [ ] Make intervention consume `extractStructuralScamFacts`; phone extraction may remain workflow-specific.
- [ ] Make Shopping Safety consume shared facts/intervention; do not invent merchant reputation.
- [ ] Run the same tests GREEN and commit exact files.

### Task 8: Wave 0/1 closure gate

**Files:**
- Modify: `.engineering/REGRESSION_REGISTER.md`
- Modify: `.engineering/TEST_MATRIX.md`

- [ ] Run `npm run typecheck`, `npm run test:unit`, `npm run test:integration`, `npm run check:core`, `npm run check:core-vectors`, `npm run check:provider-compatibility`, `npm run check:regression-vault`.
- [ ] Run `npm run gate` locally where supported. Do not convert a platform skip into a pass.
- [ ] Document exact invariants in the two governance files; commit only those two files.
- [ ] Push/freeze the exact Wave 0/1 head and require Windows/macOS/Linux Engineering Gate + fail-closed summary all green.
- [ ] Review final diff for threshold changes, provider-specific decision branches, broad allowlists, unproven `providerTrust = "trusted"`, duplicated evidence, weakened security/resource limits, or real mailbox data. Any finding returns to the relevant RED task.
- [ ] Update EMA-31/32/9/19/21 only from exact verified evidence; EMA-33 stays open.

## Acceptance
Wave 0/1 closes only when paraphrased scams remain stable, dangerous owner cases escalate, hard-ham stays controlled, same-domain mismatch is impossible, unproven relay remains uncertainty, complete-under-budget IMAP mail gains coverage without weakening partial-mail Safe rules, forged auth cannot gain trust, consumer surfaces reuse shared facts, provider parity is executable, and the exact three-OS gate passes.