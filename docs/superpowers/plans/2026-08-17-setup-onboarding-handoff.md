# Setup Onboarding Handoff Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every mailbox-dependent first-run step guide an unconnected consumer into the real provider connection surface with explicit prerequisite instructions, while keeping step completion authoritative and account-bound.

**Architecture:** `web/consumer-onboarding.js` remains the owner of first-run milestones and will emit one semantic `email-shield-provider-setup-requested` handoff whenever a mailbox-dependent action cannot proceed. `web/consumer-provider-onboarding.js` remains the owner of normal provider cards and will render/focus a small setup guidance callout from that event. No step is completed by navigation or by the handoff itself; `mailbox_connected` still comes only from an actually selected connected account observed by the existing account state.

**Tech Stack:** Browser JavaScript, existing Email Shield UI router/event boundary, Vitest source-contract tests, GitHub Engineering Gate.

## Global Constraints

- Base exactly on verified `main` `7077693b7f96d998ac651166f6f9791157a37432`.
- Do not alter detector scoring, thresholds, provider-neutral detection, community trust, Family authorization, or raw-mail privacy boundaries.
- Outlook remains hidden/postponed in the normal consumer provider journey.
- Do not mark any mailbox-dependent onboarding milestone complete from navigation alone.
- Do not persist prerequisite prompts, mailbox identity, credentials, or provider secrets.
- Use strict RED -> GREEN TDD and run the canonical Engineering Gate on exact commits.

---

### Task 1: Lock the missing prerequisite handoff with a failing onboarding contract

**Files:**
- Modify: `tests/unit/consumerOnboardingWeb.test.ts`
- Test: `tests/unit/consumerOnboardingWeb.test.ts`

**Interfaces:**
- Consumes: current first-run `handleAction`, `chooseSensitivity`, and provider-card ownership.
- Produces: regression requirements for `email-shield-provider-setup-requested`, explicit dependency copy, and provider-surface focus/scroll behavior.

- [ ] **Step 1: Write the failing test**

Add a test that reads both browser modules and requires:

```ts
it("hands mailbox prerequisites to the real provider setup surface without granting completion", () => {
  const onboarding = read("web/consumer-onboarding.js");
  const providers = read("web/consumer-provider-onboarding.js");

  expect(onboarding).toContain("email-shield-provider-setup-requested");
  expect(onboarding).toContain("Requires a connected, selected mailbox");
  expect(onboarding).toContain("requestMailboxSetup('connect')");
  expect(onboarding).toContain("requestMailboxSetup('sensitivity')");
  expect(onboarding).not.toContain("state.completed.add('mailbox_connected');\n      requestMailboxSetup");

  expect(providers).toContain("email-shield-provider-setup-requested");
  expect(providers).toContain("consumerProviderSetupGuidance");
  expect(providers).toContain("grid.scrollIntoView");
  expect(providers).toContain("firstAvailableProvider.focus");
});
```

- [ ] **Step 2: Run the branch Engineering Gate and verify RED**

Run the canonical GitHub Engineering Gate on the exact test-only commit. Expected: the new onboarding test fails because the semantic handoff/callout does not yet exist; unrelated tests remain green.

---

### Task 2: Implement one semantic prerequisite handoff at the ownership boundary

**Files:**
- Modify: `web/consumer-onboarding.js`
- Modify: `web/consumer-provider-onboarding.js`
- Test: `tests/unit/consumerOnboardingWeb.test.ts`

**Interfaces:**
- Consumes: `window.emailShieldNavigate`, the Settings route, `.consumer-provider-grid`, and normal consumer provider buttons.
- Produces: `CustomEvent('email-shield-provider-setup-requested', { detail: { reason } })`; an ephemeral guidance element `#consumerProviderSetupGuidance` owned by provider onboarding.

- [ ] **Step 1: Add the minimal first-run handoff**

In `consumer-onboarding.js`, add a helper that routes to Settings and emits only a bounded reason token:

```js
function requestMailboxSetup(reason) {
  route('settings');
  window.dispatchEvent(new CustomEvent('email-shield-provider-setup-requested', {
    detail: { reason },
  }));
}
```

Use it for the step-2 connect action and for sensitivity when no mailbox is bound. Keep `ensureBoundMailbox()` authoritative; do not add `mailbox_connected` or any other completion merely because navigation occurred. Update the affected step copy so the prerequisite is visible before the user clicks, including the exact phrase `Requires a connected, selected mailbox` for mailbox-dependent actions.

- [ ] **Step 2: Render/focus the real provider setup owner**

In `consumer-provider-onboarding.js`, create one reusable callout immediately before the provider grid:

```js
const setupGuidance = document.createElement('div');
setupGuidance.id = 'consumerProviderSetupGuidance';
setupGuidance.className = 'consumer-card';
setupGuidance.hidden = true;
grid.insertAdjacentElement('beforebegin', setupGuidance);
```

Listen for `email-shield-provider-setup-requested`. Map only known reason tokens (`connect`, `sensitivity`, and later-safe generic fallback) to concise instructions. On the event, reveal the callout, call `grid.scrollIntoView({ behavior: 'smooth', block: 'center' })`, and focus the first currently available provider button using a temporary programmatic focus target only if needed. Do not expose Outlook; use the already-filtered `providerButtons` map.

- [ ] **Step 3: Keep successful provider actions authoritative**

Do not complete onboarding in provider onboarding. Existing account connection/session rendering remains the source that causes `consumer-onboarding.js` to observe a selected mailbox and add `mailbox_connected` on refresh.

- [ ] **Step 4: Run the focused/unit checks and canonical Engineering Gate**

Expected: the new test passes; `check-ui-workflows.mjs` remains green; all existing unit/API/regression/browser/package checks remain green on Windows, macOS, and Ubuntu with real Linux Secret Service.

---

### Task 3: Self-review the consumer path and freeze exact-head evidence

**Files:**
- Modify only if evidence requires it: `docs/superpowers/plans/2026-08-17-setup-onboarding-handoff.md`

**Interfaces:**
- Consumes: exact branch diff and gate evidence.
- Produces: a merge-ready frozen branch, not an automatic merge.

- [ ] **Step 1: Review the exact diff**

Verify the branch changes only the plan, onboarding regression test, first-run controller, and provider-onboarding controller. Confirm no scoring, provider adapter, Family, community, credential, or Outlook live-acceptance code changed.

- [ ] **Step 2: Verify user-visible workflow semantics**

Confirm from code/tests that before a mailbox exists: prerequisite text is already visible; clicking Connect or a sensitivity choice opens Settings and surfaces the provider cards with contextual guidance; no setup milestone is credited. After a real mailbox appears/selects, the existing authoritative refresh can credit `mailbox_connected` and the requested step can then be completed normally.

- [ ] **Step 3: Freeze and verify exact head**

Run one final canonical Engineering Gate on the exact final branch head. Require Windows success, macOS success, Ubuntu success with real Linux Secret Service, and Gate Result Summary success before opening/readying the PR.

- [ ] **Step 4: Stop at integration choice**

Open or update a PR against `main` and report the frozen SHA. Do not merge without a new explicit user integration choice for that PR.
