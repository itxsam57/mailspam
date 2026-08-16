# Link / Destination Integrity P0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Repair EMA-7 and EMA-10 so explicit link checks share one bounded URL normalizer and one DNS-pinned destination-analysis owner, without weakening SSRF protection or adding network visits to automatic mailbox scans.

**Architecture:** `server/src/util/htmlInteraction.ts` remains the single normalization boundary for attacker-controlled link text. It may decode one genuinely whole-percent-encoded absolute HTTP(S) URL, but must never recursively decode, authorize credentials, or turn non-web schemes into executable destinations. `DestinationAnalysisCoordinator` in `server/src/workflows/analyzeLinks.ts` remains the only network-analysis owner; Check Anything URL mode will compose that coordinator explicitly instead of creating another fetch path. Automatic Quick/Full/Spam scans remain network-free.

**Tech Stack:** TypeScript, Vitest, Express, Node URL parser, existing `DestinationAnalysisCoordinator`, existing DNS-pinned `hardenedFetch`, GitHub three-platform Engineering Gate.

## Global Constraints

- RED test commit before each behavior change; verify the failure is the intended defect.
- No provider-specific URL decoding or destination scoring.
- No brand allow/deny list and no verdict-threshold reduction.
- Do not relax DNS pinning, private/loopback/link-local/metadata blocking, redirect validation, timeout, content-type, byte or concurrency limits.
- Destination network access remains an explicit user action only; no automatic mailbox-scan browsing.
- Preserve raw/displayed destination evidence separately from the canonical URL used for network analysis.
- A failed, malformed, blocked, unavailable or uninspected destination is never promoted to benign/Safe.
- No internet-dependent unit or integration test; inject deterministic destination fetch/analyzer doubles.
- No owner mailbox content or credentials in fixtures, logs, commits or CI artifacts.

---

### Task 1: EMA-7 one-pass whole-percent-encoded HTTP(S) canonicalization

**Files:**
- Create: `tests/unit/linkDestinationNormalization.test.ts`
- Modify: `server/src/util/htmlInteraction.ts`

**Interfaces:**
- Consumes: attacker-controlled `href`, form action, meta-refresh and plain-text destination strings already handled by `analyzeHtmlInteractions(...)`.
- Produces: exported `canonicalizeWebDestination(raw: string, baseHref: string | null): string`, used by all structural interaction extraction in this file.
- Contract: only a candidate beginning with a percent-encoded `http://` or `https://` scheme and representing a whole encoded absolute URL may be decoded once. A second encoded layer must remain non-executable.

- [ ] **Step 1: Write RED normalization regressions**

Create `tests/unit/linkDestinationNormalization.test.ts` with focused synthetic cases:

```ts
import { describe, expect, it } from "vitest";
import { analyzeHtmlInteractions, canonicalizeWebDestination } from "../../server/src/util/htmlInteraction.js";

describe("link destination canonicalization", () => {
  it("decodes one whole-percent-encoded absolute HTTPS destination while preserving raw evidence", () => {
    const raw = "https%3A%2F%2Fshop.example%2Faccount%3Fmode%3Dreview";
    const result = analyzeHtmlInteractions(`<a href="${raw}">Review account</a>`, null);
    expect(result.links).toHaveLength(1);
    expect(result.links[0]?.rawUrl).toBe(raw);
    expect(result.links[0]?.normalizedUrl).toBe("https://shop.example/account?mode=review");
  });

  it("does not recursively decode a double-encoded destination", () => {
    const raw = "https%253A%252F%252Fshop.example%252Faccount";
    expect(canonicalizeWebDestination(raw, null)).toBe(raw);
  });

  it.each([
    "javascript%3Aalert%281%29",
    "data%3Atext%2Fhtml%2Ctest",
    "file%3A%2F%2F%2Fetc%2Fpasswd",
  ])("does not turn encoded non-web scheme %s into an executable URL", (raw) => {
    expect(canonicalizeWebDestination(raw, null)).toBe(raw);
  });

  it("rejects encoded HTTP credentials instead of canonicalizing them", () => {
    const raw = "https%3A%2F%2Fuser%3Asecret%40shop.example%2F";
    expect(canonicalizeWebDestination(raw, null)).toBe(raw);
  });

  it("canonicalizes encoded loopback only as an HTTP target so downstream SSRF blocking still owns the denial", () => {
    expect(canonicalizeWebDestination("http%3A%2F%2F127.0.0.1%2Fadmin", null)).toBe("http://127.0.0.1/admin");
  });

  it("leaves malformed percent escapes as malformed bounded evidence", () => {
    const raw = "https%3A%2F%2Fshop.example%2";
    expect(canonicalizeWebDestination(raw, null)).toBe(raw);
  });
});
```

- [ ] **Step 2: Verify RED**

Run:

```bash
npm run test:unit -w server -- tests/unit/linkDestinationNormalization.test.ts
```

Expected: compile/test failure because `canonicalizeWebDestination` is not exported and/or the encoded HTTPS case remains unnormalized. Existing tests must not be edited to hide the failure.

- [ ] **Step 3: Implement one-pass canonicalization at the shared owner**

In `server/src/util/htmlInteraction.ts`, replace the private `normalizedDestination` owner with an exported `canonicalizeWebDestination` and a narrow helper. The helper must only consider whole-percent-encoded absolute HTTP(S) candidates whose scheme separator and leading slashes are encoded; it must use one `decodeURIComponent` call, require the result to parse as HTTP(S), reject `username`/`password`, and never call itself recursively. Normal already-valid URLs and relative URLs retain current behavior.

Implementation shape:

```ts
function decodeWholeEncodedAbsoluteWebUrl(candidate: string): string {
  if (!/^https?%3a%2f%2f/i.test(candidate)) return candidate;
  try {
    const decoded = decodeURIComponent(candidate);
    const parsed = new URL(decoded);
    if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password) return candidate;
    return parsed.toString();
  } catch {
    return candidate;
  }
}

export function canonicalizeWebDestination(raw: string, baseHref: string | null): string {
  const entityDecoded = decodeHtmlEntities(raw);
  const candidate = urlCandidate(decodeWholeEncodedAbsoluteWebUrl(entityDecoded));
  if (!candidate) return "";
  try {
    return baseHref ? new URL(candidate, baseHref).toString() : new URL(candidate).toString();
  } catch {
    return candidate;
  }
}
```

Before committing, review whether decoding a mixed partially-encoded URL could alter query semantics; if the source candidate contains literal URL delimiters inconsistent with a whole encoded absolute URL, tighten the recognizer rather than decoding more input.

- [ ] **Step 4: Verify GREEN and existing interaction behavior**

Run:

```bash
npm run test:unit -w server -- tests/unit/linkDestinationNormalization.test.ts
npm run typecheck
npm run check:web
```

Expected: all pass. Existing entity/base/form/meta/plain-text interaction behavior remains unchanged.

- [ ] **Step 5: Commit**

```bash
git add tests/unit/linkDestinationNormalization.test.ts server/src/util/htmlInteraction.ts
git commit -m "fix: canonicalize encoded web destinations once"
```

---

### Task 2: EMA-7 downstream destination safety and parity

**Files:**
- Modify: `tests/unit/linkDestinationNormalization.test.ts`
- Create: `tests/unit/linkDestinationClassificationParity.test.ts`
- Modify only if RED proves necessary: `server/src/engine/layers/destinationClassification.ts`

**Interfaces:**
- Consumes: canonical URL emitted by `canonicalizeWebDestination(...)`.
- Produces: unchanged `DestinationResult` from `classifyDestination(...)`.
- Safety owner: `classifyDestination`/`hardenedFetch`, not the normalizer, retains private-network and credential blocking.

- [ ] **Step 1: Add RED/downstream assertions before any classifier change**

Test that an encoded public URL extracted by `analyzeHtmlInteractions` reaches `classifyDestination` as canonical HTTP(S), while encoded loopback becomes `blocked_unsafe_target`, encoded credentials remain malformed/error, and double-encoded/non-web destinations never invoke the supplied fetch double.

- [ ] **Step 2: Run the focused tests**

```bash
npm run test:unit -w server -- tests/unit/linkDestinationNormalization.test.ts tests/unit/linkDestinationClassificationParity.test.ts
```

Expected: pass if Task 1 correctly feeds the existing safety owner. If any case fails, inspect the exact normalization/classifier boundary before changing production code.

- [ ] **Step 3: Change classification only if a RED proves an ownership defect**

Do not loosen `isBlockedTarget`. Any required change must preserve HTTP(S)-only, no-userinfo, loopback/private/link-local/metadata blocking and fail-closed fetch errors.

- [ ] **Step 4: Commit the parity lock**

```bash
git add tests/unit/linkDestinationNormalization.test.ts tests/unit/linkDestinationClassificationParity.test.ts server/src/engine/layers/destinationClassification.ts
git commit -m "test: lock encoded destination safety parity"
```

---

### Task 3: EMA-10 make Check Anything URL mode use the shared explicit destination analyzer

**Files:**
- Modify: `server/src/workflows/analyzeLinks.ts`
- Modify: `server/src/api/scamCheckRoutes.ts`
- Modify: `server/src/api/consumerDesktopServer.ts`
- Create: `tests/unit/scamCheckUrlDestinationIntegration.test.ts`
- Modify only if consumer rendering requires it: `web/consumer-product.js`

**Interfaces:**
- `DestinationAnalysisCoordinator.analyze(...)` will accept a `Pick<CanonicalEnvelope, "links">` rather than requiring unrelated envelope fields; mailbox Analyze Links and Scam Check URL mode use the same coordinator.
- `ScamCheckRouteDependencies` gains optional `destinationAnalyzer?: DestinationAnalysisCoordinator`; production composition passes `localOptions.destinationAnalyzer`, falling back to the existing process coordinator.
- URL-mode response gains a bounded optional `destinationAnalysis` object containing the shared `AnalyzeLinksResult`; message, `.eml`, and image checks do not invoke destination network analysis.

- [ ] **Step 1: Write RED API integration tests**

Create an injected `DestinationAnalysisCoordinator` with deterministic `fetchImpl` and `networkEnabled: true`. Through the real protected Scam Check route assert:

```ts
expect(body.schemaVersion).toBe(1);
expect(body.destinationAnalysis?.results[0]?.classification).toBe("benign");
expect(body.destinationAnalysis?.results[0]?.url).toBe("https://example.com/");
```

Also assert:
- URL mode calls the destination fetch double exactly once.
- message mode does not call it.
- `.eml` and image routes do not call it.
- blocked/error destination results remain explicit and are never rewritten to benign/Safe.
- raw fetched body content is not copied into the API response.

- [ ] **Step 2: Verify RED**

```bash
npm run test:unit -w server -- tests/unit/scamCheckUrlDestinationIntegration.test.ts
```

Expected: URL response lacks `destinationAnalysis` and fetch count is zero under current code.

- [ ] **Step 3: Generalize the shared coordinator input without duplicating behavior**

Change the coordinator/analyze helper signature to `Pick<CanonicalEnvelope, "links">`; keep queueing, HMAC cache, DNS-pinned fetch, incident controls and classification unchanged.

- [ ] **Step 4: Compose the analyzer into Scam Check URL route only**

After `assertConsumerScamCheckRequest(req.body)`, evaluate the existing local scam result. For `kind === "url"`, canonicalize the submitted URL through the shared URL normalizer, construct one bounded `LinkInfo`, and invoke `analyzeLinks({ links: [link] }, analyzer)`. Return the existing Scam Check fields plus `destinationAnalysis`. Do not invoke the analyzer for message/EML/image inputs.

- [ ] **Step 5: Verify GREEN and route security**

```bash
npm run test:unit -w server -- tests/unit/scamCheckUrlDestinationIntegration.test.ts
npm run typecheck
npm run check:web
npm run smoke:browser
```

Expected: all pass; loopback/session/origin/rate-limit boundaries remain enforced.

- [ ] **Step 6: Commit**

```bash
git add server/src/workflows/analyzeLinks.ts server/src/api/scamCheckRoutes.ts server/src/api/consumerDesktopServer.ts tests/unit/scamCheckUrlDestinationIntegration.test.ts web/consumer-product.js
git commit -m "fix: inspect explicit Scam Check URLs through shared destination analysis"
```

---

### Task 4: EMA-10 isolate Analyze Links transport failures without internet-dependent CI

**Files:**
- Create: `tests/unit/analyzeLinksTransportIntegrity.test.ts`
- Modify only if RED proves necessary: `server/src/util/hardenedFetch.ts`
- Modify only if RED proves necessary: `server/src/workflows/analyzeLinks.ts`

**Interfaces:**
- Uses existing injectable resolver/socket/fetch boundaries in `hardenedFetch` and `DestinationAnalysisCoordinator`.
- Must distinguish expected fail-closed DNS/private/timeout/content-limit outcomes from a valid public HTTPS text response.

- [ ] **Step 1: Add controlled transport matrix**

Cover a deterministic public-IP resolution + pinned HTTPS text success, DNS failure, public-to-private rebinding attempt, redirect to private target, timeout/abort, unsupported content type and oversized body. No test may call the public internet.

- [ ] **Step 2: Run RED/diagnostic matrix**

```bash
npm run test:unit -w server -- tests/unit/analyzeLinksTransportIntegrity.test.ts
```

If all valid-public cases already pass, record that EMA-10's remaining cross-provider error rate is a live/environment acceptance gap rather than changing production network policy without evidence.

- [ ] **Step 3: If and only if a deterministic valid-public case fails, repair that exact transport boundary**

Preserve resolve/validate/socket-pin per redirect hop and all existing limits. Re-run the complete hardened-fetch test family after any change.

- [ ] **Step 4: Commit**

```bash
git add tests/unit/analyzeLinksTransportIntegrity.test.ts server/src/util/hardenedFetch.ts server/src/workflows/analyzeLinks.ts
git commit -m "test: lock Analyze Links transport integrity"
```

---

### Task 5: P0 Link/Destination closure and integration

**Files:**
- Modify: `.engineering/REGRESSION_REGISTER.md`
- Modify: `.engineering/TEST_MATRIX.md`
- Create: `.engineering/LINK_DESTINATION_P0_CLOSURE.md`
- Update Linear: EMA-7, EMA-10, EMA-33

**Interfaces:**
- Produces immutable automated closure evidence and a truthful manual live-destination acceptance boundary.

- [ ] **Step 1: Run focused closure matrix**

```bash
npm run test:unit -w server -- tests/unit/linkDestinationNormalization.test.ts tests/unit/linkDestinationClassificationParity.test.ts tests/unit/scamCheckUrlDestinationIntegration.test.ts tests/unit/analyzeLinksTransportIntegrity.test.ts
npm run typecheck
npm run build
npm run check:web
npm run check:core-vectors
npm run check:provider-compatibility
```

- [ ] **Step 2: Audit diff against security invariants**

Confirm no SSRF weakening, no direct `fetch()` outside the shared destination owner, no automatic mailbox destination visit, no raw page-body persistence/telemetry, no provider-specific decoder and no Safe promotion on incomplete analysis.

- [ ] **Step 3: Run full exact-head Engineering Gate**

```bash
npm run gate
```

GitHub Windows, macOS, Ubuntu/Linux Secret Service and Gate Result Summary must all pass on one immutable head SHA.

- [ ] **Step 4: Freeze governance and rerun the exact governance-inclusive SHA**

Record new regression/matrix IDs based on the current registry tail; never overwrite historical IDs.

- [ ] **Step 5: Merge only the verified exact SHA and require independent merged-main gate**

No next P0 lifecycle/security branch begins until the new `main` SHA passes the full independent gate.

- [ ] **Step 6: Keep real-network owner acceptance manual**

Use controlled real public destinations only after code integration. CI must not claim that Gmail/iCloud owner Analyze Links transport is live-accepted without the owner's environment.