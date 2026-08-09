# Email Shield — Milestone 2 Live Gmail OAuth Acceptance

## Status

**OWNER ACCEPTANCE: PASS**

Acceptance date: **2026-08-09**

Accepted runtime baseline: `56bee670cb30dda13ee136f06bfce626ff88b2ad`

## Automated evidence

The guided Gmail OAuth root-fix PR passed the full Engineering Gate on Windows and Ubuntu before merge. The post-merge `main` run encountered one unrelated Windows Credential Manager integration timeout on its first Windows attempt; no Gmail or vault code was changed. The exact same `main` commit was rerun on a fresh Windows runner and passed, including the real Windows Credential Manager store/read/delete integration. Ubuntu and the combined Gate Result Summary were also green.

The accepted Gmail implementation retains:

- Authorization Code + PKCE S256;
- random loopback callback on `127.0.0.1`;
- state, nonce and callback replay protection;
- matching Google Desktop OAuth client credentials used only inside the local OAuth/provider runtime;
- no client secret in the authorization URL or browser-visible status/callback surfaces;
- verified Google `sub` as stable account identity;
- refresh token independent policy identity;
- Windows refresh-token custody behind the native credential vault;
- serialized validation/commit versus disconnect/revocation;
- final-session provider revocation;
- protected dashboard Disconnect action.

## Owner-controlled live acceptance

The owner completed the following against a real Gmail account and the accepted runtime baseline:

1. **Guided Gmail connection** — PASS
   - Gmail → Live → Continue with Google completed successfully.
   - Google consent completed and Email Shield created the connected Gmail account.

2. **First real Gmail Quick Scan** — PASS
   - Quick Scan completed successfully against the connected live Gmail account.

3. **Disconnect** — PASS
   - Deliberate Gmail Disconnect completed successfully.
   - The connected Gmail account was removed from the dashboard as expected.

4. **Reconnect same Gmail account** — PASS
   - Guided Google authorization completed again successfully.
   - The same Gmail account reconnected successfully.

5. **Quick Scan after reconnect** — PASS
   - A second live Gmail Quick Scan completed successfully after disconnect/reconnect.

## Acceptance boundary closed by this evidence

This closes the owner-visible acceptance boundary for the **guided Gmail OAuth + protected refresh-token lifecycle** introduced during Milestone 2.

A later change is a regression if it causes any of the following without an intentional, reviewed product change:

- real Gmail guided OAuth can no longer complete using the configured matching Google Desktop OAuth client credentials;
- OAuth client secret, authorization code, PKCE verifier, refresh token, access token or ID token appears in normal browser-visible Email Shield responses/status/callback output;
- Gmail Quick Scan stops working after a successful guided connection;
- deliberate Gmail Disconnect fails to remove the connected account when provider revocation/local cleanup succeed;
- reconnecting the same Gmail account breaks stable account identity or policy continuity because of refresh-token replacement;
- Quick Scan fails after a successful disconnect/reconnect cycle;
- Windows Gmail refresh-token persistence silently falls back to plaintext storage.

## Explicitly still open

This acceptance does **not** close the whole Milestone 2 Protected Credential Vault package or Milestone 2 overall. Remaining credential work includes at least:

- guided Outlook/Microsoft OAuth and stable-account token custody;
- local policy-encryption key custody/migration;
- macOS Keychain backend;
- Linux Secret Service/keyring backend;
- production packaging/distribution handling for application-level OAuth client credentials;
- remaining backup/export/uninstall credential-exclusion and cleanup acceptance.
