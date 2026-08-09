# Email Shield — Guided Gmail OAuth (Desktop PKCE)

## Scope

This Milestone 2 package replaces the old live-Gmail developer credential entry path with a guided desktop OAuth flow while preserving fixture mode and the existing Gmail provider/detection behavior.

The implementation follows Google's installed desktop application model:

- system/browser authorization at Google's HTTPS authorization endpoint;
- temporary `127.0.0.1` loopback listener on a random available port;
- Authorization Code flow;
- PKCE with a unique high-entropy verifier and `S256` challenge;
- cryptographically random `state` for callback CSRF protection;
- cryptographically random OpenID Connect `nonce` checked against the verified ID token;
- no manual copy/paste/OOB flow;
- no required desktop `client_secret`;
- one-time callback consumption before asynchronous token exchange;
- callback listener closed after the first valid-state response or expiry.

## Google application configuration

Development builds read the application-owned public desktop OAuth client ID from:

`EMAIL_SHIELD_GOOGLE_CLIENT_ID`

A client ID is public application metadata, not a password or refresh token. The browser does not supply an arbitrary client ID to the local server.

The Google Cloud project must have the Gmail API enabled and use an OAuth client of type **Desktop app**. Public production distribution will require the appropriate Google OAuth consent-screen/scopes verification before this flow is treated as production-ready.

## Requested permissions

Guided Gmail OAuth requests:

- `openid`
- `email`
- `https://www.googleapis.com/auth/gmail.modify`

`gmail.modify` is used because Email Shield already provides both mailbox scanning and explicit provider-native Trash/Spam actions. It does not grant immediate permanent deletion that bypasses Trash.

Google's installed-app documentation states that incremental authorization is not supported for installed apps. Email Shield therefore does not pretend to implement a read-only-to-modify incremental grant for this desktop flow. Provider capability/scope presentation remains part of the later capability-matrix work.

## Stable account identity

Guided Gmail sessions use the verified Google ID token `sub` claim as the stable account identifier.

The refresh token is **not** part of guided Gmail policy identity. This prevents refresh-token replacement or rotation from orphaning the user's existing Email Shield personal rules.

The account-scoped policy key is derived from:

- provider (`gmail`);
- Email Shield's application-owned Google client ID;
- verified Google `sub`.

The email address is display metadata only and is never used as the unique Google account identifier.

## Refresh-token custody

On a platform with an available native credential vault:

1. Google returns the refresh token only to the local loopback/token-exchange process.
2. The token is validated by a real Gmail provider connection before a long-lived Email Shield account session is committed.
3. The refresh token is stored behind a deterministic opaque `oauth-refresh-token` vault reference derived from client ID + verified Google `sub`.
4. The long-lived session stores only that handle.
5. Scans/actions resolve the token only when the Gmail provider adapter connects.

On platforms whose native vault backend has not yet been implemented, the current compatibility boundary remains process-memory-only storage; Email Shield does not substitute plaintext persistent storage.

## Browser privacy boundary

The dashboard receives only:

- OAuth flow ID;
- Google authorization URL containing public client metadata plus one-time state/nonce/challenge;
- pending/complete/error status;
- resulting Email Shield account ID and display label after success.

The dashboard must never receive:

- authorization code after Google's redirect;
- PKCE verifier;
- refresh token;
- access token;
- ID token;
- Windows Credential Manager target contents.

## Explicitly not claimed by this package

- Outlook guided OAuth;
- macOS Keychain;
- Linux Secret Service;
- local policy-encryption key migration;
- Google DPoP-bound refresh tokens;
- final public Google OAuth app verification/production consent publishing;
- provider capability-matrix UI;
- background token-expiry notifications.

These remain separate Milestone 2 work.