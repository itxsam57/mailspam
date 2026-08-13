# Email Shield — Final Pre-Native Manual / Live Test Handoff

This source-controlled template is used by `npm run gate` to create `artifacts/engineering/MANUAL_TEST_HANDOFF.md`.

## Handoff rule

The owner continues only after the generated verification report says **PASSED** for the exact immutable release-candidate SHA. Build, strict typecheck, unit/API/regression tests, five-provider corpus, Worker runtime, cryptographic validation, privacy/session/replay checks, browser-source checks, compiled smokes, package lifecycle, capacity and dependency audits belong to automation and must not be manually re-created as a substitute for the gate.

For every owner check record only PASS/FAIL, the check ID, browser/OS when relevant and the exact visible failure. Never include credentials, app passwords, OAuth codes/tokens, mailbox bodies, local-session values, private provider message IDs, private URL query strings, recovery codes or signing private keys.

The Milestone 2 external-provider plan remains `docs/MILESTONE_2_LIVE_ACCEPTANCE.md`. This handoff adds the complete final-consumer/pre-native owner acceptance required by Workstream W.

## A — Startup, layout and session integrity

- **MAN-F01 Initial render** — open `http://127.0.0.1:4173`; confirm one stable render without blank/frozen state, overlap, browser security warning or permanent loading.
- **MAN-F02 Responsive layout** — desktop, narrow/mobile width, 200% zoom and 400% zoom keep primary text, cards, status, forms and actions reachable without hidden security meaning.
- **MAN-F03 Keyboard/focus** — navigate primary routes, setup, forms and destructive confirmations with keyboard only; focus remains visible and logical.
- **MAN-F04 Reduced/high-contrast behavior** — forced/high-contrast and reduced-motion modes keep verdicts/actions understandable without color or animation alone.
- **MAN-F05 Protected session** — normal reads/actions produce no visible CSRF/nonce/unauthorized-session errors.
- **MAN-F06 Process restart** — leave the tab open, restart `npm run dev`, try one harmless stale-tab mutation and verify an explicit reload/session-expired requirement rather than silent execution; reload and continue.
- **MAN-F07 Action replay** — after a successful controlled mutation, rapid reuse is rejected, disabled or requires fresh state instead of executing twice.

## B — Canonical eight-step first run

Use a fresh test data directory so prior onboarding state cannot hide the setup flow.

- **MAN-F08 Account step** — before creating/signing in, confirm local **Check Anything / Scam Check** remains usable. Create or sign in to an Email Shield account and verify Step 1 completes only after signed-in state is visible.
- **MAN-F09 Mailbox step** — connect/select a mailbox and verify Step 2 completes only when a mailbox actually exists.
- **MAN-F10 Permission review** — open the permission explanation; verify it distinguishes OAuth/provider credentials, OS credential-vault custody, local inspection, explicit actions and data that is not uploaded. Acknowledge it and verify Step 3 persists.
- **MAN-F11 First scan** — run a completed protection scan. Step 4 must remain incomplete before a completed scan record exists and complete afterward.
- **MAN-F12 Sensitivity** — select High Protection, Balanced or Low Noise from onboarding. Step 5 must complete only after the save succeeds. Switch profiles once more and confirm hard-threat wording never promises a bypass.
- **MAN-F13 Continuous protection** — open Background Protection and enable it. Merely opening the panel must **not** complete Step 6; enabled state must. Pause it and verify the step no longer presents as continuously protected, then enable it again for the rest of acceptance.
- **MAN-F14 Family decision** — open Family Shield or choose **Not now**. Verify Family is explicitly optional and Step 7 records the decision without pretending a family exists.
- **MAN-F15 Home completion** — before Steps 1–7 are complete, **Check Home** must refuse completion. After all seven are complete, finish Step 8 and verify the onboarding checklist retires without a second legacy popup.

## C — Account, privacy, plan and destructive lifecycle

Use controlled test accounts only.

- **MAN-F16 Recovery-code visibility** — create/recover a test account and verify a newly issued recovery code is shown only in the intended one-time flow; do not paste the code into test notes.
- **MAN-F17 Device list/revoke** — registered devices render clearly; revoke a non-current controlled device and verify it becomes unusable without affecting the current device.
- **MAN-F18 Recovery rotation** — perform controlled account recovery and confirm the old recovery path is no longer treated as current.
- **MAN-F19 Sign out / sign back in** — sign out and sign back in on the trusted device; mailbox content must not appear inside the profile/account metadata.
- **MAN-F20 Privacy-safe export** — export account metadata and inspect it for absence of mailbox bodies, subjects, provider tokens, raw URLs and device private keys.
- **MAN-F21 Local-data clear separation** — where offered, clear local activity/learning independently from remote account deletion; verify the UI distinguishes the two operations.
- **MAN-F22 Account deletion** — on a disposable test account only, exercise the explicit destructive confirmation and verify the account cannot silently remain signed in afterward.
- **MAN-F23 Plan UI** — Free/Individual/Family states render consistently. Development entitlement controls must appear only when the explicit local development environment switch is enabled and must be labeled as non-payment simulation.

## D — Family Shield / Family Guardian

- **MAN-F24 Create/join/leave** — create a controlled Shield Circle, create an invite, join with a second controlled account/device, leave/remove as appropriate and verify seat/member state refreshes correctly.
- **MAN-F25 Ownership transfer** — transfer ownership between controlled members and verify old-owner-only controls move to the new owner.
- **MAN-F26 Revocation immediacy** — revoke/remove a member/device/invite and verify its Family authorization stops immediately.
- **MAN-F27 Privacy boundary** — Family summary/radar must not reveal another member’s subject, body, mailbox address, sender address, provider message ID or private history.
- **MAN-F28 Trusted assistance** — use a controlled suspicious item and the trusted-person flow; verify sharing requires explicit user intent and the UI does not imply passive family mailbox access.
- **MAN-F29 Family threat semantics** — a Family warning/confirmed signal may protect the Family but must not claim that one member independently created global community consensus.

## E — Check Anything, explanations and safety tools

- **MAN-F30 Message check** — paste a controlled suspicious text and a legitimate control; verify verdict, strongest signals, limitations and safe next actions are readable and do not fabricate unavailable evidence.
- **MAN-F31 URL check** — check a controlled URL; verify advice uses independently obtained official channels and does not auto-open the suspicious destination.
- **MAN-F32 EML check** — analyze a controlled `.eml`; malformed/partial input must not become Safe merely because inspection failed.
- **MAN-F33 Image/QR check** — analyze controlled PNG/JPEG/QR inputs. When local OCR/media coverage is unavailable, the result must say so rather than show a false green Safe state.
- **MAN-F34 Browser destination tool** — use **Check before opening** on controlled destinations; block/warn/allow wording must be explainable and no passive browsing-history collection should be implied.
- **MAN-F35 Payment/callback/remote-access tool** — paste controlled bank-transfer, crypto/gift-card, callback and remote-support scam requests plus legitimate controls; verify the guidance tells the user to verify through independently sourced channels.
- **MAN-F36 Exposure tool** — without explicit confirmation no lookup occurs. With a controlled address and configured service, verify the UI explains that only privacy-preserving lookup material is sent and that a clean result is not proof of no historic exposure.
- **MAN-F37 Support bundle** — export it and inspect for app/runtime/provider-status/aggregate diagnostic data only. It must not contain credentials, tokens, subjects, sender addresses, raw URLs, Family private data, mailbox bodies or device private keys.

## F — Health, activity, cleanup and Undo

- **MAN-F38 Inbox & Mailbox Health** — run the health check. Unsupported provider-security capabilities must show **unavailable**, not Safe. Subscription/cleanup and Digital Account Footprint sections remain local and understandable.
- **MAN-F39 Cleanup confirmation** — use only controlled fixture data. Bulk cleanup must require the explicit destructive confirmation and affect only the selected sender/domain/account scope.
- **MAN-F40 Undo validity** — when provider/fixture semantics support restoration, Undo is offered only inside its valid window and only once. When unsupported or expired, the UI must not promise recovery.
- **MAN-F41 Activity privacy** — protection activity explains what changed and why without raw mailbox content. Clear Activity requires its explicit confirmation and affects only local activity state.
- **MAN-F42 Policy centre** — search/filter, single/bulk revoke, category clear/reset and policy counts remain synchronized to the selected account.
- **MAN-F43 Policy export/import** — exported policy data contains policy state only; merge/replace remains selected-account scoped.

## G — Scanning, realtime/background protection and provider actions

- **MAN-F44 Five-provider fixtures** — connect Gmail, Outlook, iCloud, Yahoo and Generic IMAP in Fixture mode; each completes Quick Scan visibly.
- **MAN-F45 Scan presentation** — run Quick, Full Mailbox and Spam/Junk fixture scans; progress/counters/cards do not duplicate or remain stale.
- **MAN-F46 Stop/resume** — stop a Full scan during progress, start another scan, refresh during a resumable scan, then resume an eligible scan. Completed scans must not remain falsely resumable.
- **MAN-F47 Account isolation** — connect at least two fixture accounts; results, policies, schedules, actions, learning and activity must never cross-link.
- **MAN-F48 Background isolation** — enable different intervals for two fixture accounts, verify selected-account status isolation, manual-scan priority, immediate Pause and disconnect cleanup.
- **MAN-F49 Action separation** — Report Scam, Move to Spam/Junk, Mark Safe, Trust sender, Trash where offered and unsubscribe remain distinct controls.
- **MAN-F50 Report Scam privacy** — confirmation describes account-local protection, privacy-reduced sharing, independent community thresholds and optional exact-sender block; it must not claim body/subject/mailbox/credential/provider-ID/raw private URL upload.
- **MAN-F51 Immediate campaign memory** — report a controlled fixture campaign without moving it, rescan and verify local Confirmed Threat protection while the provider folder remains unchanged.
- **MAN-F52 Provider movement** — Move to Spam/Junk changes exactly the intended controlled message and does not imply shared reporting.
- **MAN-F53 QR/HTML/attachment presentation** — malformed/oversized/unsupported inspection cases do not freeze the UI or falsely appear Safe.
- **MAN-F54 Unsubscribe presentation** — manual web/mailto remains available where appropriate; RFC 8058 one-click is not offered merely from a One-Click declaration without required trusted DKIM proof.

## H — Campaign radar, operations and final state

- **MAN-F55 Campaign radar fail-closed** — verified advisories are understandable; when signed intelligence is unavailable/unverified the radar becomes unavailable rather than stale-green.
- **MAN-F56 Privacy-safe operations** — aggregate operations/health status is readable with keyboard, screen reader, 200%/400% zoom, narrow layout and forced colors, and contains no mailbox/message identity or content.
- **MAN-F57 Broken-connection visibility** — deliberately use a controlled disconnected/expired fixture or provider state and verify Home/consumer surfaces make the problem discoverable rather than claiming full protection.
- **MAN-F58 Final refresh** — refresh once; no permanent blank page, uncaught visible error, broken layout, stale-session loop or duplicate onboarding overlay remains.

## Live provider checks

Follow the detailed IDs in `docs/MILESTONE_2_LIVE_ACCEPTANCE.md`.

- **iCloud / Yahoo / Generic IMAP:** provider-approved app passwords, bounded Quick scan, controlled exact provider action and reconnect when accounts are available.
- **Gmail:** guided loopback OAuth, Quick scan, controlled exact provider action, Disconnect/revocation, reconnect and stable account-policy identity. Production OAuth publication remains GAP-001 until accepted.
- **Outlook:** Microsoft public desktop/mobile registration with `http://localhost`, no guided-flow client secret, scopes `offline_access`, `User.Read`, `Mail.ReadWrite`, loopback PKCE connect, Quick scan, controlled exact provider action, Disconnect, reconnect and stable Graph-account policy identity. This is the owner acceptance required by GAP-002.

## Live network/deployment checks

These cannot be proven by desktop CI and remain launch/external acceptance rather than missing repository code:

- controlled public Analyze Links destination/redirect/DNS acceptance — GAP-005;
- production community DNS/TLS, monitoring, persistent storage, encrypted backup/restore and signing-key rotation ceremony — GAP-004;
- gateway reporter reputation/enrollment, edge rate limiting and volumetric/DDoS controls — GAP-008;
- production Google OAuth publication/verification — GAP-001;
- controlled real Outlook acceptance — GAP-002;
- real Apple/Google/web merchant activation, receipt verification, native package signing/notarization and store distribution;
- native Windows/macOS/Android/iOS shell/background/notification/share/camera integrations after Workstream W owner acceptance.

Do not mark these complete from a local fixture or unit test.

## Automated — not owner browser work

Automation covers implementation contracts including process-local protected sessions and replay rejection; all five provider adapters; Gmail/Microsoft PKCE; native-vault custody; encrypted policy/scan/relationship/community/consumer state; bounded QR/HTML/attachment/archive/link analysis; authentication provenance/alignment/PSL boundaries; RFC 8058 authorization; DNS validation/socket pinning; community thresholding/signatures/recovery/capacity; account/family/billing lifecycle; realtime/mobile/browser/intervention contracts; protection-profile invariants; adversarial consumer corpus; package lifecycle; and dependency blocking policy on Windows, macOS and Ubuntu/Linux.

## Status rule

A green literal-head Engineering Gate means **repository engineering is ready for owner/live acceptance**. Workstream W is formally closed only after MAN-F01 through MAN-F58 applicable owner checks pass with no unresolved reproducible defect. GAP-001/002/004/005/008 and native/store/deployment work remain separately external even after the pre-native milestone closes.
