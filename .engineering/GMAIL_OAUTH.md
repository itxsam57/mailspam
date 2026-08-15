# Email Shield — Guided Gmail OAuth (Desktop PKCE)

## Scope

Email Shield uses a consumer desktop OAuth flow for Gmail. Normal users never configure Google developer settings and never type their Google password into Email Shield.

The consumer flow is:

1. the user clicks **Continue with Google**;
2. Email Shield opens Google's HTTPS authorization page in the system browser;
3. Google authenticates the user and collects consent;
4. Google redirects to a temporary loopback listener owned by the local Email Shield process;
5. Email Shield validates the one-time state/nonce/PKCE transaction;
6. the local process exchanges the authorization code for tokens;
7. the refresh token is stored behind the operating-system credential-vault boundary;
8. the connected Gmail account is restored on later launches without asking the user to configure OAuth again.

The implementation uses:

- Google Desktop OAuth application identity;
- Authorization Code flow;
- PKCE with a unique high-entropy verifier and `S256` challenge;
- cryptographically random `state` for callback CSRF protection;
- cryptographically random OpenID Connect `nonce` checked against the verified ID token;
- a temporary `127.0.0.1` loopback listener on a random available port;
- one-time callback consumption before asynchronous token exchange;
- exact loopback Host, `GET` method and root callback path enforcement;
- bounded token-response handling;
- no manual copy/paste or out-of-band authorization flow.

## Consumer application identity

The product-owned Google Desktop OAuth client ID is public application metadata. It is embedded into qualified portable Email Shield launchers so customers never need an environment variable, developer console, client-ID field or developer account.

The current consumer release identity is validated by the release packager before an artifact can qualify.

Developer/source runs may still override the public client ID with:

`EMAIL_SHIELD_GOOGLE_CLIENT_ID`

A Google Desktop application cannot keep a client secret confidential on an end-user computer. Email Shield therefore does not require a client secret for the consumer PKCE path. The token exchange sends a client secret only if an explicit developer override supplies one; the normal consumer package does not depend on one.

The Google Cloud project must:

- have the Gmail API enabled;
- use an OAuth client of type **Desktop app**;
- have an External consent configuration for a public consumer product;
- list owner/test accounts while the consent project remains in Testing;
- complete the required Google OAuth verification before unrestricted public production use.

## Requested permissions

Guided Gmail OAuth requests:

- `openid`
- `email`
- `https://www.googleapis.com/auth/gmail.modify`

`gmail.modify` is required because Email Shield scans mailbox content and provides provider-native Trash/Spam actions. It does not grant permanent deletion that bypasses Trash.

## Stable account identity

Guided Gmail sessions use the verified Google ID-token `sub` claim as the stable account identifier.

The refresh token is **not** part of policy identity. Refresh-token replacement therefore cannot create a new Email Shield policy account.

The account-scoped policy key is derived from:

- provider (`gmail`);
- Email Shield's application-owned Google client ID;
- verified Google `sub`.

The email address remains display metadata rather than the unique account identifier.

## Credential custody

For guided Gmail:

1. the browser receives only the public authorization request and one-time OAuth transaction values;
2. the authorization code is returned only to the local loopback listener;
3. the local process performs token exchange using client ID + PKCE verifier;
4. the verified Google `sub` establishes stable account identity;
5. real Gmail provider validation completes before the account session is committed;
6. on supported platforms, the refresh token is stored behind a deterministic opaque credential-vault reference;
7. the long-lived session stores the vault handle rather than the raw refresh token;
8. scans/actions materialize the protected token only when the Gmail provider connects.

The consumer package does not store a Google password, access token or refresh token in the browser.

## Provider validation

A successful Google login is not enough to claim the mailbox is connected. Before committing the account, Email Shield validates Gmail API access using the real provider adapter.

Failure is staged truthfully:

- `ES-GOOGLE-01` — authorization-code/token exchange failed;
- `ES-GOOGLE-02` — Google identity/nonce verification failed;
- `ES-GOOGLE-03` — Google signed in but Gmail API validation failed;
- `ES-GOOGLE-04` — Google signed in but protected local credential/session commit failed.

## Disconnect semantics

A final Gmail Disconnect is a credential-lifecycle operation.

- Duplicate local sessions for the same verified Google account share stable account identity.
- Removing one duplicate does not revoke authorization while another same-account session remains.
- The final same-account session requests provider-side token revocation.
- Local protected credential removal occurs only according to the existing revocation/credential lifecycle contract.
- Failures remain retryable and are not reported as successful cleanup.

## Browser privacy boundary

The dashboard may receive only:

- OAuth flow ID;
- Google authorization URL containing public client metadata and one-time state/nonce/challenge;
- pending/complete/error status;
- resulting Email Shield account ID and display label after success.

The dashboard must never receive:

- the user's Google password;
- authorization code after callback consumption;
- PKCE verifier;
- refresh token;
- access token;
- ID token;
- operating-system credential-vault contents.

## Release acceptance boundary

The engineering gate locks:

- the product-owned Google desktop client ID into portable launchers;
- package verification of that exact release configuration;
- authoritative consumer provider-card ownership;
- direct consumer calls into the hardened Google OAuth owner instead of hidden synthetic OAuth clicks;
- PKCE verifier/challenge generation;
- state and nonce validation;
- callback Host/method/path restrictions;
- callback replay rejection;
- absence of secrets from browser-visible surfaces;
- stable verified Google subject identity;
- provider validation before account commit;
- existing provider/scan/action regressions.

Real Google authorization and a real Gmail scan remain owner-controlled acceptance because CI must never contain live mailbox credentials.

## Production boundary

While the Google OAuth consent project is **External / Testing**, only configured test users can complete owner acceptance. Public consumer release requires the Google project to move through the appropriate production/verification process for the requested Gmail scope.

That provider publication process is external to the local Email Shield codebase; the application must not claim unrestricted public Gmail availability until it is completed.
