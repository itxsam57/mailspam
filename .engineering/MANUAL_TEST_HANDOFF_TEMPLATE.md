# Email Shield — Manual Browser Test Handoff

This file is a source-controlled template. `npm run gate` creates the current report at `artifacts/engineering/MANUAL_TEST_HANDOFF.md`.

## Handoff rule

The owner performs only the visible checks listed in the generated report. Command-line build, typecheck, unit, integration, corpus, worker, browser-source, API smoke and dependency checks belong to the automated engineering gate.

Do not begin visible browser acceptance when the report status is **BLOCKED**.

## Required evidence for each visible check

- Result: `PASS` or `FAIL`
- Browser and viewport/device
- Exact visible error or unexpected behavior on failure
- Screenshot only when it helps explain a visible defect
- No mailbox password, app password, OAuth token, message body or private provider identifier

## Standard visible checks

1. **Initial render** — open `http://127.0.0.1:4173`; confirm the dashboard renders once without blank/frozen state, overlapping panels or permanent loading indicator.
2. **Responsive layout** — inspect normal desktop width and a narrow/mobile width; confirm text, buttons, counters, tables and cards remain readable and reachable.
3. **Fixture provider parity** — connect Gmail, iCloud, Outlook, Yahoo and Generic IMAP in Fixture mode; each must visibly appear as the selected account and complete a Quick Scan.
4. **Scan presentation** — run Quick, Full Mailbox and Spam/Junk fixture scans; confirm progress, counters, Safe audit and warning cards update without duplicate or stale content.
5. **Stop behavior** — start a Full scan, press Stop during progress, confirm controls return and another scan can start without refresh.
6. **Safe audit** — open Safe messages; verify subject/sender/parse/evidence presentation, and that Trust sender, unsubscribe or Report Spam is shown only when available.
7. **Review actions** — on fixture results, inspect Mark this message Safe, Trust sender, Report Spam, Block sender, Block domain, Move to Trash and unsubscribe confirmation text; cancel any action you do not intend to execute.
8. **Exact-message Report Spam** — in a fixture Inbox/Quick result, choose one identifiable message and press Report Spam. Confirm the dialog states that only this message moves and the sender is not blocked. Accept it and verify success appears only after provider confirmation.
9. **Report Spam result** — rerun the same fixture Quick Scan and confirm only the selected message disappeared from Inbox. Run Spam/Junk Scan and confirm that same subject appears there. Confirm unrelated messages remain. Report Spam must not appear on cards already scanned from Spam/Junk.
10. **Safe Report Spam** — from the Safe audit, report one controlled fixture Safe message as Spam and repeat the exact-one Inbox/Spam verification. This confirms the user can correct a Safe classification without exposing provider identifiers.
11. **Action feedback** — execute only controlled fixture actions; verify success appears only after confirmation and errors remain visible/retryable.
12. **Adult campaign presentation** — confirm a fixture or controlled test item matching explicit adult-site solicitation plus external redirect/reply mismatch is shown High Risk with understandable evidence; ordinary non-explicit social introductions must not all be promoted to High Risk.
13. **Account isolation** — connect two fixture accounts, switch between them and confirm selected-account state/results/actions do not visually cross-link.
14. **Rapid interaction** — click scan/account/action controls rapidly but safely; confirm duplicate requests are prevented or reported and the UI does not freeze.
15. **Controlled live iCloud** — when an iCloud app-specific password is available, reconnect and run the explicitly listed non-destructive live scan; verify credentials are not displayed after connection and visible progress/errors are truthful. Do not perform a live Report Spam action unless you intentionally want that exact real message moved into iCloud Junk.
16. **Final browser state** — refresh once after the controlled tests; confirm no permanent blank page, uncaught visible error or broken layout.

## Excluded from current acceptance

- Guided Gmail OAuth
- Guided Outlook OAuth
- Production internet deployment
- OS-keychain encryption
- Production QR decoding
- Privacy-reduced Email Shield community scam reporting/aggregation
- Any destructive bulk mailbox operation not explicitly listed in the generated report

Provider-level Report Spam for one exact message is included. It is separate from future Email Shield community reporting and does not claim provider-wide model training.

These exclusions are registered product gaps, not browser-test failures.