# Email Shield — Manual / Live Test Handoff

This source-controlled template is used by `npm run gate` to create `artifacts/engineering/MANUAL_TEST_HANDOFF.md`.

## Handoff rule

The owner continues only after the generated verification report says **PASSED**. Build, strict typecheck, unit/API/regression tests, five-provider corpus, Worker runtime, cryptographic validation, local-session/CSRF/replay tests, browser-source checks, compiled smoke and dependency audits belong to automation and must not be manually re-created as a substitute for the gate.

For every owner check record only PASS/FAIL, the check ID, browser/OS when relevant and the exact visible failure. Never include credentials, app passwords, OAuth codes/tokens, mailbox bodies, local session values, private provider message IDs, private URL query strings or signing private keys.

The complete owner-controlled Milestone 2 plan is `docs/MILESTONE_2_LIVE_ACCEPTANCE.md`. The checklist below is the visible/browser portion generated with each gate.

## Visible fixture checks

1. **Initial render** — open `http://127.0.0.1:4173`; confirm one stable render without blank/frozen state, overlap, browser security warning or permanent loading.
2. **Responsive layout** — desktop and narrow/mobile width keep text, counters, policy tables, cards and actions readable/reachable.
3. **Five-provider fixtures** — connect Gmail, Outlook, iCloud, Yahoo and Generic IMAP in Fixture mode; each completes Quick Scan visibly.
4. **Scan presentation** — run Quick, Full Mailbox and Spam/Junk fixture scans; progress/counters/Safe audit/cards do not duplicate or stay stale.
5. **Stop/restart** — stop a Full scan during progress and start another scan without a refresh.
6. **Protected local session** — normal connection, scans and actions produce no visible CSRF/nonce/unauthorized-session errors.
7. **Refresh behavior** — refresh once; the UI obtains a valid local session without exposing/asking for a session secret.
8. **Process restart** — leave the tab open, restart `npm run dev`, attempt one harmless stale-tab action and verify a clear reload/session-expired requirement rather than silent success; reload and continue.
9. **Action replay** — after one successful controlled fixture action, repeated/rapid reuse must require a rescan or visibly reject the stale action instead of executing twice.
10. **Action separation** — Report Scam, Move to Spam/Junk, Mark Safe, Trust sender, Trash where offered and unsubscribe remain distinct controls.
11. **Report Scam privacy** — the confirmation describes account-local protection, privacy-reduced sharing, independent community thresholds and a separate optional exact-sender block; it must not claim body/subject/mailbox/credential/provider-ID/raw private URL upload.
12. **Immediate campaign memory** — report a controlled fixture campaign without moving it, rescan and verify local Confirmed Threat protection while the provider folder is unchanged.
13. **Provider movement** — use a different controlled fixture message; Move to Spam/Junk changes exactly the intended message and does not imply shared reporting.
14. **Policy centre** — selected-account search/filter, single/bulk revoke, category clear/reset and policy counts/rows remain synchronized.
15. **Policy export/import** — export contains policy data only; merge/replace affects only the selected account.
16. **Scan history/resume** — refresh during a longer scan, stop/resume an eligible scan and verify completed scans do not remain falsely resumable.
17. **Account isolation** — connect at least two fixture accounts and verify results/policies/actions do not cross-link.
18. **Background protection** — for two fixture accounts, enable different intervals, verify each selected account shows only its own status, a manual scan visibly takes priority, Pause is immediate, and Disconnect removes that account without changing the other schedule.
18. **QR/HTML/attachment presentation** — controlled fixture evidence remains readable; malformed/oversized inspection cases do not freeze the UI or falsely appear Safe.
19. **Unsubscribe presentation** — manual web/mailto remains available where appropriate; RFC 8058 one-click is not offered merely from a One-Click declaration without the required trusted DKIM proof.
20. **Final state** — refresh once; no permanent blank page, uncaught visible error, broken layout or stale-session loop.

## Live provider checks

Follow the detailed IDs in `docs/MILESTONE_2_LIVE_ACCEPTANCE.md`.

- **iCloud / Yahoo / Generic IMAP:** provider-approved app passwords, bounded Quick scan, controlled exact provider action and reconnect when accounts are available.
- **Gmail:** guided loopback OAuth, Quick scan, controlled exact provider action, Disconnect/revocation, reconnect and stable account-policy identity. Production OAuth publication remains GAP-001 until accepted.
- **Outlook:** Microsoft public desktop/mobile registration with `http://localhost`, no guided-flow client secret, scopes `offline_access`, `User.Read`, `Mail.ReadWrite`, loopback PKCE connect, Quick scan, controlled exact provider action, Disconnect, reconnect and stable Graph-account policy identity. This is the owner acceptance required by GAP-002.

## Live network/deployment checks

These cannot be proven by the desktop CI gate:

- controlled public Analyze Links infrastructure acceptance — GAP-005;
- production community DNS/TLS, monitoring, persistent storage, encrypted backup/restore drill and signing-key rotation ceremony — GAP-004;
- gateway reporter reputation/enrollment, edge rate limiting and volumetric/DDoS controls — GAP-008.

Do not mark these complete from a local fixture or unit test.

## Automated — not owner browser work

Automation covers the implementation contracts including:

- process-local HttpOnly sessions, protected reads, same-origin one-time mutations, replay rejection, loopback/Host/forwarded-header isolation and response redaction;
- all five provider adapters and canonical scan/action/report parity;
- Gmail/Microsoft PKCE, stable identity, token rotation/revocation and native-vault custody contracts;
- Windows Credential Manager, macOS Keychain and Linux Secret Service round trips;
- encrypted personal policy, scan state, relationship history, community state/outbox and descriptor-bound local-file integrity;
- relationship/thread privacy and non-authorizing behavior;
- bounded local QR, HTML interaction, attachment MIME/hash and link-structure analysis;
- Authentication-Results provenance, author-domain alignment and Public Suffix List boundaries;
- RFC 8058 DKIM/list-header authorization;
- Analyze Links DNS validation/socket pinning/redirect/resource limits;
- community thresholding, encrypted storage, signed-feed validation, recovery/readiness/public-error/resource boundaries;
- dependency inventory and production dependency blocking policy on Windows, macOS and Ubuntu/Linux.

## Status rule

A green Engineering Gate means **ready for owner/live acceptance**, not that GAP-001/002/004/005/008 are automatically closed. Milestone 2 becomes formally closed only after the applicable owner/deployment evidence in `docs/MILESTONE_2_LIVE_ACCEPTANCE.md` is PASS and no reproducible defect remains unresolved.

The owner also verifies MAN-020: refresh the Privacy-safe operations table after a fixture scan and explicit Safe/scam-report review actions; confirm its aggregate counts/status are readable with keyboard, screen reader, 200%/400% zoom, narrow layout and forced colors, and that no mailbox/message identity or content appears.
