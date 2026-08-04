# Hard-test guide

1. Install Node.js 22 LTS.
2. Extract the project into a clean folder.
3. Run `npm config set registry https://registry.npmjs.org/`.
4. Run `npm install`.
5. Run `npm run verify`.
6. Run `npm run dev`.
7. Open `http://127.0.0.1:4173` in a new browser tab.

## First test: fixtures

Connect each fixture provider, then run Quick, Full and Spam scans. Safe messages must only increment counters. They must not render as cards.

## Real iCloud

Create an Apple app-specific password. Select iCloud, choose Live, enter the full iCloud email address and app-specific password. Never enter the normal Apple ID password.

Run Spam first. Confirm:
- progress appears in bounded pages;
- repeated MIME variants are scored consistently;
- Stop returns control within about two seconds;
- another scan can start immediately;
- the developer suite remains responsive.

## Real Yahoo / Generic IMAP

Use provider-approved app passwords. Generic IMAP requires TLS and defaults to port 993.

## Failure capture

When a scan fails, record the exact visible error and the terminal output. Do not replace it with “Failed to fetch.” The scan worker is isolated, so a failed worker must not freeze the UI server.
