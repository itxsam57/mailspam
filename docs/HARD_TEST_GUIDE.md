# Hard-test guide

## Automated engineering handoff

1. Install Node.js 22 LTS.
2. Extract or clone the project into a clean folder.
3. Run `npm config set registry https://registry.npmjs.org/` when the npm registry was previously changed.
4. Run `npm ci` for a clean locked installation, or `npm install` for an existing developer checkout.
5. Run `npm run verify`.
6. Open `artifacts/engineering/VERIFICATION_REPORT.md`.
7. Continue only when the report says **PASSED**.
8. Run `npm run dev`.
9. Open `artifacts/engineering/MANUAL_TEST_HANDOFF.md` and perform only its remaining visible browser checks at `http://127.0.0.1:4173`.

Build, strict typecheck, unit tests, integration tests, scam-corpus parity, compiled Worker runtime, browser-source validation, privacy/wiring checks, localhost API/SSE smoke and the enabled dependency audit belong to the automated gate. Do not make the owner repeat those commands manually.

GitHub Actions runs the same gate on Windows and Ubuntu and uploads the verification report and browser handoff even when a stage fails.

## Fixture visible test

Connect each fixture provider, then follow the generated handoff for Quick, Full and Spam scans. Safe messages must increment counters and appear only in the privacy-reduced Safe audit, not as warning cards.

## Controlled real iCloud

Create an Apple app-specific password. Select iCloud, choose Live, enter the full iCloud email address and app-specific password. Never enter the normal Apple ID password.

Use only the live actions explicitly listed in the generated handoff. Confirm:

- progress appears in bounded pages;
- repeated MIME variants are scored consistently;
- Stop returns control promptly;
- another scan can start without refresh;
- the developer suite and dashboard remain responsive;
- credentials are not displayed after connection;
- an action reports success only after provider confirmation.

## Real Yahoo / Generic IMAP

Use provider-approved app passwords. Generic IMAP requires TLS and defaults to port 993. These live-provider tests are performed only when the generated handoff explicitly includes them and controlled credentials are available.

## Failure capture

When a visible test fails, record the exact checklist item, visible error, browser/viewport and relevant terminal output. Do not replace a detailed error with “Failed to fetch.” Do not include mailbox passwords, app passwords, OAuth tokens, full message bodies or private provider identifiers.

The scan worker is isolated, so a failed worker must not freeze the UI server. Any recurrence belongs in `.engineering/REGRESSION_REGISTER.md` with an automated test before closure.