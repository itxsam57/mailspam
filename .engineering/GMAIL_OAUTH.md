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
- callback listener closed after the first valid-state response or expiry;
- exact loopback Host, `GET` method and root callback path enforcement;
- bounded provider token-response handling.

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
2. The verified Google `sub` establishes stable account identity.
3. Real Gmail provider validation and secure credential/session commit execute inside the same serialized account-lifecycle transaction.
4. The refresh token is stored behind a deterministic opaque `oauth-refresh-token` vault reference derived from client ID + verified Google `sub`.
5. The long-lived session stores only that handle.
6. Scans/actions resolve the token only when the Gmail provider adapter connects.

Serializing validation and commit with disconnect/revocation prevents a race where an old session could revoke the Google grant after a new connection validates but before the new token is committed.

On platforms whose native vault backend has not yet been implemented, the current compatibility boundary remains process-memory-only storage; Email Shield does not substitute plaintext persistent storage. Guided Gmail disconnect still performs provider-side revocation from the secure in-memory handle before that handle is released.

## Provider-side revocation and Disconnect

A deliberate Gmail Disconnect is a credential-lifecycle operation, not just a UI removal.

- Multiple Email Shield sessions for the same verified Google account share the same account identity.
- Removing one duplicate session does not revoke the Google authorization while another same-account session remains.
- The final same-account session asks Google's OAuth revocation endpoint to revoke the protected refresh token.
- Only after revocation is confirmed, or Google reports the token is already invalid, may Email Shield delete the local vault credential and remove the final session.
- If provider revocation cannot be confirmed, the account remains retryable and the local credential is not silently deleted.
- If local native-vault deletion fails after provider revocation, Email Shield reports failure rather than claiming a fully successful cleanup.

The dashboard exposes a protected **Disconnect** action. Successful cleanup reloads the local dashboard so stale selected-account/action state does not survive removal.

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

The callback result page likewise exposes only a generic success/failure message. Provider error bodies and secret-bearing lower-layer failures are not surfaced into browser-visible diagnostics.

## Automated acceptance boundary

The engineering gate locks:

- PKCE verifier/challenge derivation;
- state and nonce handling;
- callback Host/method/path restrictions;
- callback replay rejection before token exchange;
- verified stable `sub` identity;
- refresh-token rotation without policy-identity rotation;
- vault-backed and memory-only custody behavior;
- provider validation + commit serialization against concurrent disconnect;
- final-session-only provider revocation;
- revocation failure truthfulness;
- absence of OAuth secrets from public callback/status surfaces;
- all prior Gmail fixture, provider, scan/action and Milestone 1 regression suites.

Real Google authorization and a real Gmail Quick Scan remain owner-controlled acceptance because CI must never receive live mailbox credentials.

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