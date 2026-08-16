# Email Shield — Universal Detection Repair Wave 0/1 Closure

Date: 2026-08-16
Program owner: EMA-33
Repair PR: #103
Behavioral repair SHA: `89a5e63c2d613d4c28fce81087d60297c52c6f5f`
Behavioral Engineering Gate: run `31959673546` (#1165)

## Status

The automated/code portion of P0 Universal Detection Integrity is closed on the repair branch. Final owner live mailbox reacceptance remains external/manual and is deliberately not represented as automated evidence.

This closure record supplements the historical Regression Register and Test Matrix without deleting or rewriting their prior evidence. The next canonical registry IDs for this wave are REG-090, A-72 and MAN-021.

## Locked architecture contract — REG-090

Email Shield detection remains provider-neutral and privacy-safe:

- Gmail, iCloud, Yahoo, Outlook and generic IMAP adapters may extract and normalize evidence/provenance, but do not own risk thresholds, Safe exceptions, scam keywords, brand rules or final verdict logic.
- Synthetic owner regressions lock paraphrase-stable claim/transaction/action contradictions and high-risk payment/account-secret/remote-access scam structure without mailbox-specific brand maps.
- An explicit same-organizational-domain claim cannot become an identity contradiction merely because external-origin heuristics are absent.
- Missing, unknown or unproven relay/Auth-Results provenance is non-authorizing and incomplete; it cannot manufacture authentication, mismatch, relationship confidence or Safe evidence.
- Connected-mailbox scans, Check Anything text, submitted `.eml`, Intervention and Shopping Safety reuse shared structural scam facts where their input permits it.
- Shopping Safety translates shared payment/action/pressure facts into buyer-facing explanations without inventing merchant age, reputation, registration, inventory, delivery history or price fairness.
- IMAP readable body acquisition may prove bounded middle-sized selected MIME parts complete within the reviewed complete-part budget; oversized or unknown-length parts remain Partial/Unknown and never trigger whole-message fallback.
- Equivalent normalized evidence must produce equivalent detection decisions across Gmail, iCloud, Yahoo, Outlook and generic IMAP.
- Existing fail-closed privacy/resource boundaries, community payload reduction and provider permission scope remain unchanged.

Automated protection includes:

- `tests/unit/universalDetectionOwnerRegressions.test.ts`
- `tests/unit/structuralScamEvidence.test.ts`
- `tests/unit/structuralScamEvidenceTopology.test.ts`
- `tests/unit/structuralConsistencyOwnership.test.ts`
- `tests/unit/generalizedIdentityArchitecture.test.ts`
- `tests/unit/authenticationResultsProvenance.test.ts`
- `tests/unit/consumerScamCheck.test.ts`
- `tests/unit/scamCheckInputs.test.ts`
- `tests/unit/interventionStructuralConvergence.test.ts`
- `tests/unit/shoppingSafetyIntegration.test.ts`
- `tests/unit/imapReadableBodyCompleteness.test.ts`
- `tests/unit/universalDetectionProviderParity.test.ts`
- `tests/integration/corpusScan.test.ts`
- the compiled developer suite, browser/server smokes and full three-platform Engineering Gate.

## Automated closure matrix — A-72

The universal detection closure gate is blocking and must preserve all of the following together:

1. Owner-derived synthetic regressions catch payment diversion, gift-card code exfiltration, OTP/recovery-secret theft, crypto pressure and financial remote-access structure under paraphrase.
2. Impossible same-domain identity evidence is rejected while real hard contradictions still dominate relationship/history confidence.
3. Untrusted Authentication-Results/relay provenance remains incomplete and cannot become positive or negative authentication fact.
4. Check Anything and submitted `.eml` reach the same structural detector primitives used by connected mailbox scans where equivalent evidence exists.
5. Intervention and Shopping Safety consume the shared structural facts instead of maintaining competing gift-card/OTP/crypto/payment/pressure scoring logic.
6. Bounded IMAP middle-sized readable MIME parts may be completely acquired by selected-part fetch; oversized/unknown parts remain bounded/partial with no whole-message fallback.
7. Equivalent normalized evidence across all five providers produces equivalent score/verdict behavior.
8. Normal newsletters, security notices and ordinary card-purchase controls do not become High Risk merely because the shared detector became stronger.
9. The 56-fixture corpus runs through all five provider adapters.
10. Strict typecheck, production build, browser checks, compiled server smoke and the Windows/macOS/Ubuntu Engineering Gate remain green.

## Fresh behavioral verification

Exact behavioral SHA: `89a5e63c2d613d4c28fce81087d60297c52c6f5f`

Engineering Gate run `31959673546` (#1165):

- Windows: success.
- macOS: success.
- Ubuntu: success, including the Linux Secret Service gate path.
- Gate Result Summary: success.
- Unit tests: 192 files passed, 1 skipped; 1,122 tests passed, 1 skipped.
- Shopping Safety integration: 6/6 passed.
- Universal owner regressions: 18/18 passed.
- Structural scam evidence: 24/24 passed.
- Intervention structural convergence: 7/7 passed.
- IMAP readable body completeness: 5/5 passed.
- Universal provider parity: 4/4 passed.
- Integration corpus: 280 scans = 56 fixtures × 5 providers.
- Malicious: 140/140 caught as non-Safe.
- Legitimate: 140/140 correctly Safe.
- `check:core-vectors`: five-provider/adversarial portable-core vectors passed.
- `check:provider-compatibility`: five versioned provider contracts passed.
- Browser source/wiring/privacy checks passed.
- Executable Chromium boot, Google consumer entrypoint, scan-results and unsubscribe smokes passed.
- Compiled desktop server/API, community, account/Family Shield, background-protection and release/package smokes passed.
- Locked dependency install reported 0 npm vulnerabilities on the reviewed macOS run.

## TDD evidence for the final Shopping Safety defect

RED SHA: `8e052a95975862a91d6e2c3bdb489030a7266e85`
Engineering Gate run: `31959486246` (#1164)

The test-only commit produced exactly two intended failures:

- a gift-card-code exfiltration scenario reached High Risk but had no Shopping Safety signal explaining why;
- a compound bank-transfer/crypto + urgency + verification-avoidance scenario lacked verification-avoidance explanation.

The ordinary card-purchase control remained non-High-Risk and the full five-provider corpus remained 140/140 malicious caught and 140/140 legitimate Safe.

GREEN SHA: `89a5e63c2d613d4c28fce81087d60297c52c6f5f`

Shopping Safety now consumes `extractStructuralScamFacts(...)` for payment instruments, gift-card-code transfer, urgency/deadlines, secrecy and independent-verification avoidance, then emits shopping-specific consumer explanations. It does not lower verdict thresholds or introduce a provider/brand-specific scorer.

## Diff/security review

The Wave 0/1 diff was reviewed against the EMA-33 non-negotiables and Task 10 closure checklist:

- no provider-specific final-decision branch was introduced into the shared detector;
- no mailbox-specific rule block was introduced;
- no new brand allow/deny map was introduced;
- no verdict threshold was lowered;
- no test-only or production-entitlement bypass was introduced;
- no `providerTrust: "trusted"` shortcut was added to live provider acquisition;
- no duplicate score-max/bypass wrapper was introduced;
- structural facts suppress equivalent legacy scoring where necessary to avoid double inflation;
- no raw mailbox body/HTML was added to community reporting;
- no provider permission was expanded;
- IMAP resource expansion is explicit, selected-part-only and regression-bounded; no full-message fallback was added;
- no provider-specific detector copy was added;
- owner cases in source are synthetic/privacy-safe; no real mailbox content was committed.

## Manual owner reacceptance — MAN-021

After the repair SHA is merged and an independent exact-main gate is green, perform one consolidated owner live reacceptance rather than repeatedly retesting already-passed areas:

1. iCloud Spam/Junk: targeted `LiveMusicNow` message.
2. Yahoo Spam/Junk: targeted `LiveMusicNow` message.
3. Same iCloud account: Full Scan.
4. Same Yahoo account: Full Scan.
5. Optional iCloud Inbox controls such as the previously used `John S` / `SpamMyself` examples if still available.

Expected behavior:

- the targeted structural scam is Review or stronger with an explicit non-Safe/coverage explanation;
- previously targeted High Risk phishing remains High Risk;
- ordinary newsletter/security/marketing mail is not promoted to High Risk without evidence;
- no mailbox/provider-specific decision difference appears for equivalent normalized evidence.

CI has no live mailbox credentials and therefore cannot claim MAN-021 passed.

## Scope reconciliation

This record closes the code/automation portion of EMA-33 P0 Universal Detection Integrity only. The broader EMA-33 repair program continues with P0 Link/Destination Integrity and P0 Protection Lifecycle/Security, followed by the listed P1/P2 workflow/consumer repairs. Final production/external acceptance remains governed by EMA-33 and the existing known-gap register.