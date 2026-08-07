# Email Shield — Milestone 2 Live Credential-Vault Acceptance

## Acceptance date

August 7, 2026

## Accepted runtime baseline

- Branch accepted by owner: `main`
- Runtime commit: `b01c045f2c8c0d9e28c4e7a98151a031b747d8a9`
- Change: Windows iCloud/Yahoo/generic-IMAP app-password sessions behind the protected credential-vault boundary
- Post-merge Engineering Gate: run 179
- Automated result: Windows PASS, Ubuntu PASS, Gate Result Summary PASS

## Owner-controlled live iCloud acceptance

The owner tested the merged Windows build against a real iCloud mailbox and reported all requested checks as PASS.

### PASS — live connect and Quick Scan

- Real iCloud account connected successfully with the normal app-specific-password flow.
- Quick Scan completed successfully after connection.
- Existing scanning behavior remained functional after the credential-custody refactor.

### PASS — credential privacy at the browser boundary

- The iCloud app-specific password was not visible in the connected-account UI.
- The credential was not visible in scan results or scan-status output.
- The credential was not visible in browser-visible errors.
- The credential was not present in normal post-connection Network response/preview payloads inspected through browser developer tools.
- The initial connect request remains the expected boundary where the locally entered credential must transit from the browser to the local Email Shield server; this acceptance does not claim otherwise.

### PASS — disconnect, reconnect and reuse

- The real iCloud account was removed/disconnected.
- The account was connected again using the normal flow.
- A subsequent Quick Scan completed successfully.
- No visible regression was observed after protected credential cleanup and recreation.

## Acceptance meaning

This evidence closes the owner-visible acceptance for the Windows iCloud app-password vault path introduced by `REG-042`.

It does **not** mark the complete Milestone 2 Protected Credential Vault work package finished. The following remain explicitly open:

- Gmail guided OAuth and stable-account token custody;
- Outlook guided OAuth and stable-account token custody;
- local policy-encryption key custody/migration;
- macOS Keychain backend;
- Linux Secret Service/keyring backend;
- complete backup/export/uninstall credential-exclusion and cleanup acceptance.

## Regression rule

Any later Windows change that causes a real iCloud credential to appear in browser-visible post-connection responses, prevents a vault-backed reconnect/Quick Scan, or breaks disconnect/reconnect cleanup is a regression against this accepted baseline and must not be treated as a new product limitation.
