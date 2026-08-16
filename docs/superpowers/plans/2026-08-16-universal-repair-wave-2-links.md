# Link and Destination Integrity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development or superpowers:executing-plans; use systematic-debugging + TDD for every behavior change.

**Goal:** Close EMA-7 and EMA-10 without weakening DNS pinning, redirect validation, SSRF protection or fail-closed verdicts.

**Architecture:** Normalize actionable URLs once before destination analysis, then make the hardened transport return explicit evidence states. Network policy must reject prohibited addresses before connect and on every redirect.

**Tech Stack:** TypeScript, Node HTTPS/DNS, Vitest.

## Constraints
- Preserve mailbox-cookie/provider-credential isolation.
- No “Unknown -> Safe” shortcut.
- Percent-decoding must be bounded and unambiguous.
- Private/loopback/link-local targets must be rejected before outbound connection.

### Task 1: RED owner link corpus
**Files:** Create `tests/unit/universalLinkOwnerRegressions.test.ts`.
- [ ] RED: encoded absolute `https%3A%2F%2Fexample.com%2F...` normalizes to the same destination as its plain form.
- [ ] RED: malformed double/partial encoding remains uninspectable.
- [ ] RED: public HTTPS destination with a valid bounded response is classified from evidence rather than transport error.
- [ ] RED: 127.0.0.1, RFC1918, link-local, IPv6 loopback/private targets never call the connector.
- [ ] Run `npx vitest run tests/unit/universalLinkOwnerRegressions.test.ts` and record RED.
- [ ] Commit only the RED file.

### Task 2: Canonical URL normalization
**Files:** Modify `server/src/workflows/analyzeLinks.ts`; modify `server/src/util/htmlInteraction.ts`; create `tests/unit/analyzeLinksNormalization.test.ts`.
- [ ] Write RED equivalence/ambiguity tests.
- [ ] Add one bounded decode step only when the full token decodes to a syntactically valid absolute HTTP(S) URL; never recursively decode attacker-controlled layers.
- [ ] Preserve original value for explanation while `normalizedUrl` owns the actionable destination.
- [ ] Run both test files GREEN; commit exact files.

### Task 3: Pre-connect SSRF and redirect proof
**Files:** Modify `server/src/util/hardenedFetch.ts`; create `tests/unit/hardenedFetchPreconnectGuard.test.ts`.
- [ ] RED with injected resolver/connector proves prohibited resolved addresses are rejected before connector invocation.
- [ ] RED proves every redirect is re-resolved/revalidated and a public->private redirect is stopped before the second connect.
- [ ] Implement one validated-resolution object passed into the pinned connector; ordinary `fetch()` may not re-resolve independently.
- [ ] Preserve byte/time/content-type caps.
- [ ] Run `npx vitest run tests/unit/hardenedFetchPreconnectGuard.test.ts` GREEN; commit exact files.

### Task 4: Destination evidence classification
**Files:** Modify `server/src/workflows/analyzeLinks.ts`; modify `server/src/consumer/browserProtection.ts`; modify `server/src/api/linkAnalysisActions.ts`; create `tests/unit/destinationEvidenceClassification.test.ts`.
- [ ] RED: public successful inspection yields ALLOW/benign only from actual evidence; transport-insufficient stays Unknown; prohibited private target returns explicit blocked/private semantics.
- [ ] Fix state mapping so network-policy rejection is not presented as generic suspicious content and ordinary valid transport evidence is not discarded.
- [ ] Run `npx vitest run tests/unit/universalLinkOwnerRegressions.test.ts tests/unit/analyzeLinksNormalization.test.ts tests/unit/hardenedFetchPreconnectGuard.test.ts tests/unit/destinationEvidenceClassification.test.ts` GREEN.
- [ ] Commit exact files.

### Task 5: Closure gate
**Files:** Modify `.engineering/REGRESSION_REGISTER.md`; modify `.engineering/TEST_MATRIX.md`.
- [ ] Run `npm run typecheck`, `npm run test:unit`, `npm run test:integration`, `npm run gate`.
- [ ] Freeze exact head and require Windows/macOS/Linux + summary green.
- [ ] Record EMA-7/10 evidence only after exact gate; no raw owner URLs beyond public controls in git.