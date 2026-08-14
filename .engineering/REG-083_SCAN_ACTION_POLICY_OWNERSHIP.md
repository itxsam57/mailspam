# REG-083 — Scan Action and Personal Policy Ownership

## Scope

This regression lock protects the consumer Scan page, Stop/Resume lifecycle, message actions, Personal Policy Management, scan history presentation, and unsubscribe truthfulness from overlapping browser/server ownership.

## Required invariants

1. **One scan lifecycle owner**
   - `web/scan-monitor.js` is the sole browser owner of scan start, live SSE progress, explicit Stop, and message Block/Trash mutation dispatch.
   - `web/index.html` may provide pure rendering/account bootstrap helpers but must not own a second `EventSource`, scan start function, Stop listener, or message policy mutation controller.

2. **Retained scan presentation must retain usable bounded actions**
   - Stop/Resume may retain the current scan presentation.
   - Resume housekeeping must not invalidate still-visible opaque review or unsubscribe actions merely because the worker is restarted from a protected checkpoint.
   - Actions remain account-scoped and bounded by the normal action TTL and single-operation conflict protections.
   - Account teardown must discard the account's outstanding action capabilities.

3. **Message policy mutations are server-authorized**
   - Block sender/domain, Trash, Spam/Junk, Safe, Trust, and Report Scam use opaque server-issued review tokens.
   - Browser-rendered sender/domain text is presentation only and must never become the authority for a policy mutation.
   - The server derives the sender/domain/provider message identity from the registered action context.

4. **Personal Policy is the canonical durable rule surface**
   - Successful durable Block/Trust/Safe/community-policy mutations must be visible after Personal Policy refresh.
   - `web/policy-management.js` owns one immutable `emailShieldRefreshPersonalPolicy` refresh function. Other browser modules may await that function after a confirmed durable mutation; they must not synthesize Refresh-button clicks or create competing policy loaders.
   - Stale asynchronous policy reads must not repaint after a newer mutation or account selection.
   - Message cards must not manufacture `Unblock` actions that do not have a corresponding hardened server mutation contract.
   - Revocation of durable personal rules belongs to Personal Policy Management.

5. **Action-bearing warning-card DOM stays stable during live progress**
   - Incoming scan progress may prepend newly rendered warning cards but must not reserialize/replace already-mounted warning-card nodes.
   - An in-flight Block, Trash, Spam/Junk, Safe, Trust, Report Scam, or unsubscribe action must continue to own the same live button/status node until that action resolves.
   - Full workspace restoration may rebuild the bounded card list because restoration is an explicit presentation boundary, not concurrent live progress.

6. **Block side effects remain truthful**
   - Block saves the account-scoped durable rule first and attempts the current-message provider Trash move through the same protected action context.
   - A provider Trash failure must not falsely roll back an already-persisted protection rule.
   - UI copy must describe both the durable rule and the current-message move attempt.

7. **One Resume control**
   - The Scan controls contain one authoritative Resume button next to Stop.
   - Scan history is read-only and must not add per-record Resume/Stop controls that compete with the active scan controller.

8. **Long result projections are optional presentation only**
   - Scanned emails, Safe-message review, Technical scan details, and previous Scan history are user-controlled disclosures and default closed.
   - None of these projections may create a second scan stream or mutate scan lifecycle state.
   - Suspicious warning cards may remain visible because they are the primary warning surface.

9. **Manual unsubscribe is not confirmed unsubscribe**
   - Opening an external unsubscribe webpage or mail request may be recorded in Activity as a manual handoff.
   - Manual handoff must not increment the encrypted Confirmed unsubscribes policy because Email Shield cannot verify external completion.
   - Verified RFC 8058 one-click completion may be persisted as a Confirmed unsubscribe and must await the Personal Policy owned refresh boundary.
   - Manual controls and status text must explicitly say completion is not confirmed.

## Automated proof

The blocking engineering gate must cover:

- unit tests proving opaque review/unsubscribe actions remain valid through Stop/Resume housekeeping within their bounded TTL;
- API tests proving a pre-Stop review token can still execute a durable Block after Resume housekeeping;
- architecture tests proving there is no legacy inline scan controller, no fake message-card Unblock owner, one Resume control, token-only browser Block requests, stable live warning-card DOM, one owned Personal Policy refresh boundary, stale-read suppression, and closed-by-default long disclosures;
- executable Chromium fixture scan proving scanned messages render, safe RFC 8058 unsubscribe remains actionable, unsafe HTTP unsubscribe remains non-actionable, a real browser Block action persists to Personal Policy, its live card control remains synchronized during ongoing scan progress, and the policy count refreshes.

A change that breaks any invariant above is a regression even if scan counters, Activity, or another duplicate UI surface still appears to work.
