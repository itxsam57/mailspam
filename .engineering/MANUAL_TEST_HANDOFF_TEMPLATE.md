# Email Shield — Manual Browser Test Handoff

This source-controlled template is used by `npm run gate` to create `artifacts/engineering/MANUAL_TEST_HANDOFF.md`.

## Handoff rule

The owner performs only the visible checks listed below after the generated report says **READY**. Build, typecheck, unit/API, integration, corpus, Worker, cryptographic, local-session, CSRF, replay, browser-source, smoke and dependency checks belong to automation.

For each visible check record PASS/FAIL, browser/viewport and the exact visible failure. Never include credentials, mailbox contents, local session values or private provider identifiers.

## Visible checks

1. **Initial render** — open `http://127.0.0.1:4173`; confirm one stable render without blank/frozen state, overlap, browser security warning or permanent loading.
2. **Responsive layout** — inspect desktop and narrow/mobile width; all text, counters, tables, cards and actions remain readable and reachable.
3. **Five-provider fixtures** — connect Gmail, iCloud, Outlook, Yahoo and Generic IMAP in Fixture mode; each completes Quick Scan visibly.
4. **Scan presentation** — run Quick, Full Mailbox and Spam/Junk fixture scans; progress/counters/Safe audit/cards do not duplicate or remain stale.
5. **Stop behavior** — stop a Full scan during progress and start another scan without refresh.
6. **Protected local session** — perform normal fixture connection, scan and message actions. Confirm the dashboard does not show a CSRF, nonce, unauthorized-session or cross-origin error during ordinary use.
7. **Refresh behavior** — refresh the dashboard once. Confirm it reconnects to a valid local session and ordinary fixture actions still work without exposing or asking for any local session secret.
8. **Process-restart behavior** — with the dashboard open, stop and restart `npm run dev`, then attempt a harmless action in the old tab. Confirm it shows a clear reload/session-expired message rather than silently succeeding. Reload the page and confirm normal operation returns.
9. **Action replay feedback** — execute one controlled fixture message action successfully, then rapidly click or revisit its control. Confirm the used control is disabled or the app requires a rescan; the action must not visibly execute twice.
10. **Action separation** — verify cards and Safe rows clearly distinguish:
    - `Report Scam to Email Shield`
    - `Move to Spam/Junk`
    - `Mark this message Safe`
    - `Trust sender`
    - unsubscribe when available.
11. **Report Scam privacy text** — on a controlled fixture message, press Report Scam and verify the dialog says:
    - matching campaigns are protected locally;
    - only privacy-reduced indicators are shared;
    - body, subject, mailbox address, contacts, credentials, provider ID and raw private URLs are not uploaded;
    - one report cannot globally block a sender.
12. **Optional sender block** — continue the controlled Report Scam flow. Verify a second, separate choice asks whether to block the exact sender and warns against blocking shared delivery platforms. Choose Cancel unless deliberately testing with a direct fixture sender.
13. **Local shield result** — accept Report Scam, do not move the message. Confirm visible success says the campaign is protected locally and shows candidate/queued/warning/confirmed community state truthfully.
14. **Immediate memory** — rescan the same fixture mailbox. Confirm the matching campaign becomes Confirmed Threat with `LOCALLY_REPORTED_SCAM_CAMPAIGN`; the message remains in its folder because shared reporting alone does not move/delete it.
15. **Provider movement remains separate** — on another controlled fixture message, choose Move to Spam/Junk. Confirm exactly one selected message disappears from Inbox and appears in Spam/Junk after rescan; no shared-report success is claimed.
16. **Safe correction** — from Safe messages, report one controlled false-Safe fixture campaign. Rescan and verify immediate local campaign protection without exposing body/provider identifiers.
17. **Adult campaign presentation** — explicit first-contact adult-site solicitation with external redirect/unrelated Reply-To is High Risk; ordinary ambiguous social introductions are not all promoted automatically.
18. **Account isolation** — connect two fixture accounts, switch between them and confirm results/actions do not cross-link. A locally reported campaign applies only to the reporting account until signed community thresholds publish it.
19. **Rapid interaction** — safely click scan/account/action controls rapidly; duplicate work is prevented/reported and the UI does not freeze.
20. **Controlled live iCloud** — reconnect when an app-specific password is available and run the listed non-destructive scan. Credentials remain hidden. Perform Report Scam only on a message intentionally selected; it must not move mail unless Move to Spam/Junk is separately chosen.
21. **Final state** — refresh once; no permanent blank page, uncaught visible error, broken layout or stale-session loop.

## Automated—not owner browser work

Automation proves:

- process-local HttpOnly session creation and restart invalidation;
- CSRF protection for account/developer reads;
- exact same-origin and one-time nonce requirements for mutations;
- nonce replay and successful opaque-action replay rejection;
- loopback-only binding, forwarded-header rejection and DNS-rebinding Host rejection;
- restrictive CSP, anti-framing and browser capability headers;
- credential, OAuth-code, bearer and JWT-like error redaction;
- privacy-reduced payload contents;
- all-five-provider report-context parity;
- one-reporter deduplication;
- 3-reporter warning and 5-reporter confirmed thresholds;
- per-indicator support thresholds;
- encrypted report/outbox/policy storage;
- Ed25519 signing, trust, tamper and expiry rejection;
- central API disabled by default and correct when explicitly enabled;
- failed network report queuing and retry path;
- signed feed enforcement in scan workers.

## Excluded deployment acceptance

These are registered deployment/product gaps, not browser failures:

- public DNS/TLS and hosting of the community service;
- reverse-proxy/API-gateway rate limiting, DDoS and reporter-reputation controls;
- operational monitoring, backup/restore and executed production key rotation;
- guided Gmail/Outlook OAuth;
- operating-system credential-vault and provider refresh-token custody;
- signed-executable/process binding beyond the implemented local browser/API boundary;
- production QR decoding;
- destructive bulk mailbox operations.

The repository implements the self-hostable community client/server protocol and the process-local desktop API boundary. A public operating network and long-lived OAuth-token custody require the separate controls in later milestones.