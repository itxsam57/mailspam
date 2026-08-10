# Hard-test guide

## Automated engineering handoff

1. Install Node.js 22.
2. Extract or clone the project into a clean folder.
3. Run `npm config set registry https://registry.npmjs.org/` only if the npm registry was previously changed.
4. Run `npm ci` for a clean locked installation.
5. Run `npm run gate`.
6. Open `artifacts/engineering/VERIFICATION_REPORT.md`.
7. Continue only when the report says **PASSED**.
8. Run `npm run dev`.
9. Open the generated `artifacts/engineering/MANUAL_TEST_HANDOFF.md` and `docs/MILESTONE_2_LIVE_ACCEPTANCE.md`.

Build, strict typecheck, unit/API/regression tests, scam-corpus parity, compiled Worker runtime, browser-source/privacy/wiring validation, desktop/community smoke and dependency audits belong to the automated gate. Do not make the owner repeat those tests manually as a substitute for CI evidence.

GitHub Actions runs the Engineering Gate on **Windows, macOS and Ubuntu/Linux**, with real Linux Secret Service coverage, and uploads the verification report/manual handoff.

## Fixture visible test

Connect each fixture provider, then follow the generated handoff for Quick, Full and Spam/Junk scans. Verify visible progress, Stop/restart, account isolation, policy controls and action separation. Safe messages belong in the privacy-reduced Safe audit rather than warning cards unless later local/signed evidence changes their status.

## Live provider testing

Use `docs/MILESTONE_2_LIVE_ACCEPTANCE.md` as the authoritative owner sequence.

### iCloud / Yahoo

Use provider-approved app-specific passwords only. Never enter the normal account password. Verify bounded Quick scan, controlled exact provider action, Stop behavior and reconnect while credentials remain hidden after connection.

### Generic IMAP

Use TLS and a provider-approved app password. Port 993 is the normal default but the controlled server's actual TLS configuration is authoritative. Verify bounded scanning and only the exact provider actions that the server supports.

### Gmail

Use the guided desktop loopback OAuth flow. Verify consent/callback, stable account identity, Quick scan, controlled exact provider action, Disconnect/provider revocation behavior and reconnect. Do not capture authorization codes or tokens in evidence. Production publication/consent verification remains GAP-001 until actually accepted.

### Outlook

Configure the Microsoft Entra application as a public mobile/desktop client with `http://localhost` as the loopback redirect. The guided Email Shield flow uses PKCE and `offline_access`, `User.Read` and `Mail.ReadWrite`; it does not require a client secret. Verify consent/callback, Graph mailbox validation, protected local token custody/rotation, Quick scan, a controlled exact provider action, Disconnect, reconnect and stable account-policy identity. This is GAP-002 owner acceptance.

## Controlled network/deployment testing

Do not simulate these with fixtures and call them complete:

- **GAP-005:** Analyze Links against deliberately managed public HTTPS/DNS/redirect infrastructure, including public-to-private rejection and resource-limit behavior.
- **GAP-004:** deployed dedicated community service behind real DNS/TLS with monitoring, persistent encrypted state, backup/restore drill and signing-key rotation ceremony.
- **GAP-008:** production gateway rate limiting, reporter reputation/enrollment and volumetric/DDoS controls under controlled load.

## Failure capture

When a visible/live test fails, record the exact test ID, visible error, OS/browser when relevant and a concise terminal/provider status description. Do not replace a detailed error with only “Failed to fetch.” Never include mailbox passwords, app passwords, OAuth codes/tokens, full message bodies, private provider IDs, private URL queries or signing private keys.

A failure discovered during owner/live acceptance is a real defect/gap. Reproduce it, add an automated regression where technically possible, fix the root cause, run the full Engineering Gate on the exact final head, merge only that tested head, then repeat the failed owner item.
