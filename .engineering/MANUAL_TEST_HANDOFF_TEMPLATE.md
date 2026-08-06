# Email Shield — Manual Browser Test Handoff

This source-controlled template is used by `npm run gate` to create `artifacts/engineering/MANUAL_TEST_HANDOFF.md`.

## Handoff rule

Perform only these visible checks after the generated report says **READY**. Build, typecheck, unit/API, integration, corpus, Worker, cryptographic, browser-source, smoke and dependency checks belong to automation.

For each visible check record PASS/FAIL, browser/viewport and the exact visible failure. Never include credentials, mailbox contents or private provider identifiers.

## Visible checks

1. **Initial render** — open `http://127.0.0.1:4173`; confirm one stable render without blank/frozen state, overlap or permanent loading.
2. **Responsive layout** — inspect desktop and narrow/mobile width; all text, counters, tables, cards and actions remain readable and reachable.
3. **Five-provider fixtures** — connect Gmail, iCloud, Outlook, Yahoo and Generic IMAP in Fixture mode; each completes Quick Scan visibly.
4. **Scan presentation** — run Quick, Full Mailbox and Spam/Junk fixture scans; progress/counters/Safe audit/cards do not duplicate or remain stale.
5. **Stop behavior** — stop a Full scan during progress and start another scan without refresh.
6. **Action separation** — verify cards and Safe rows clearly distinguish:
   - `Report Scam to Email Shield`
   - `Move to Spam/Junk`
   - `Mark this message Safe`
   - `Trust sender`
   - unsubscribe when available.
7. **Report Scam privacy text** — on a controlled fixture message, press Report Scam and verify the dialog says:
   - matching campaigns are protected locally;
   - only privacy-reduced indicators are shared;
   - body, subject, mailbox address, contacts, credentials, provider ID and raw private URLs are not uploaded;
   - one report cannot globally block a sender.
8. **Optional sender block** — continue the controlled Report Scam flow. Verify a second, separate choice asks whether to block the exact sender and warns against blocking shared delivery platforms. Choose Cancel unless deliberately testing with a direct fixture sender.
9. **Local shield result** — accept Report Scam, do not move the message. Confirm visible success says the campaign is protected locally and shows candidate/queued/warning/confirmed community state truthfully.
10. **Immediate memory** — rescan the same fixture mailbox. Confirm the matching campaign becomes Confirmed Threat with `LOCALLY_REPORTED_SCAM_CAMPAIGN`; the message remains in its folder because shared reporting alone does not move/delete it.
11. **Provider movement remains separate** — on another controlled fixture message, choose Move to Spam/Junk. Confirm exactly one selected message disappears from Inbox and appears in Spam/Junk after rescan; no shared-report success is claimed.
12. **Safe correction** — from Safe messages, report one controlled false-Safe fixture campaign. Rescan and verify immediate local campaign protection without exposing body/provider identifiers.
13. **Adult campaign presentation** — explicit first-contact adult-site solicitation with external redirect/unrelated Reply-To is High Risk; ordinary ambiguous social introductions are not all promoted automatically.
14. **Account isolation** — connect two fixture accounts, switch between them and confirm results/actions do not cross-link. A locally reported campaign applies only to the reporting account until signed community thresholds publish it.
15. **Rapid interaction** — safely click scan/account/action controls rapidly; duplicate work is prevented/reported and the UI does not freeze.
16. **Controlled live iCloud** — reconnect when an app-specific password is available and run the listed non-destructive scan. Credentials remain hidden. Perform Report Scam only on a message intentionally selected; it must not move mail unless Move to Spam/Junk is separately chosen.
17. **Final state** — refresh once; no permanent blank page, uncaught visible error or broken layout.

## Automated—not owner browser work

Automation proves:

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
- OS-keychain integration;
- production QR decoding;
- destructive bulk mailbox operations.

The repository implements the self-hostable community client/server protocol. A public operating network requires the separate deployment controls in `.engineering/COMMUNITY_DEPLOYMENT.md`.