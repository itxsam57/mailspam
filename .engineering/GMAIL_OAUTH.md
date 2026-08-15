# Email Shield — Guided Gmail OAuth (Desktop PKCE)

## Scope

Email Shield uses a consumer desktop OAuth flow for Gmail. Normal users never configure Google developer settings and never type their Google password into Email Shield.

The consumer flow is:

1. the user clicks **Continue with Google**;
2. Email Shield opens Google's HTTPS authorization page in the system browser;
3. Google authenticates the user and collects consent;
4. Google redirects to a temporary loopback listener owned by the local Email Shield process;
5. Email Shield validates the one-time state/nonce/PKCE transaction;
6. the local process exchanges the authorization code using the matching Email Shield Desktop OAuth client ID and client secret;
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

## Application configuration

Email Shield's guided Gmail path uses one matching Google **Desktop app** OAuth credential pair owned by the product:

`EMAIL_SHIELD_GOOGLE_CLIENT_ID`

`EMAIL_SHIELD_GOOGLE_CLIENT_SECRET`

Neither value is accepted from browser request data. The client secret is never inserted into Google's authorization URL, dashboard state, callback HTML, OAuth status response, scan result or community report.

For source/owner acceptance, the repository root `.env.local` supplies these values. `npm run dev` loads that file automatically. `.env.local` is ignored by Git and must never be committed.

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

## Credential custody and restart continuity

The Google client secret is **application-level runtime configuration**. The Gmail refresh token is **mailbox/account-level protected state**. They deliberately have different lifecycles.

For guided Gmail:

1. the browser receives only the public authorization request and one-time OAuth transaction values;
2. the authorization code is returned only to the local loopback listener;
3. the local process performs token exchange with client ID + matching client secret + PKCE verifier + exact redirect URI;
4. the verified Google `sub` establishes stable account identity;
5. initial real Gmail provider validation uses the same matching client credentials;
6. the refresh token is written to the native OS credential vault;
7. the per-mailbox encrypted live-connection registry stores only bounded account metadata and the opaque refresh-token vault reference;
8. the application-level Google client secret is **not** copied into that mailbox registry;
9. after restart, Gmail adapter materialization rehydrates the application-level client secret from process configuration and the mailbox refresh token from the OS vault;
10. scans/actions therefore retain the same matching OAuth client credentials without persisting the application secret as mailbox data.

Legacy developer Gmail configurations that do not have a verified Google `sub` remain memory-only and do not inherit the guided persistent-session contract.

## Provider validation

A successful Google login is not enough to claim the mailbox is connected. Before committing the account, Email Shield validates Gmail API access using the real provider adapter.

Failure is staged truthfully:

- `ES-GOOGLE-01` — authorization-code/token exchange failed;
- `ES-GOOGLE-02` — Google identity/nonce verification failed;
- `ES-GOOGLE-03` — Google signed in but Gmail API validation failed;
- `ES-GOOGLE-04` — Google signed in but protected local credential/session commit failed.

The consumer Google card is enabled only when both the configured client ID and matching client secret are present. A client ID alone is not treated as live-ready.

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
- Google client secret;
- authorization code after callback consumption;
- PKCE verifier;
- refresh token;
- access token;
- ID token;
- operating-system credential-vault contents.

## Current owner acceptance boundary

Repository/source execution is the authoritative live acceptance path. The root `.env.local` must contain the matching Google Desktop client ID and client secret, and then `npm run dev` starts Email Shield with those values.

Microsoft/Outlook remains implemented internally but is intentionally omitted from normal consumer provider onboarding until its separate live acceptance is resumed. iCloud, Yahoo and generic IMAP remain available through their provider-approved app-password/IMAP paths.

## Engineering regression boundary

The engineering gate must preserve all of these together:

- Google token exchange fails closed when the matching client secret is absent;
- the token POST includes matching client ID, client secret, PKCE verifier, authorization code, grant type and exact redirect URI;
- the client secret never enters the authorization URL/browser surfaces;
- guided Gmail mailbox persistence stores the refresh token only behind an OS-vault reference and does not persist the application client secret;
- restored Gmail adapter configuration rehydrates the application-level client secret from process configuration;
- provider-card identity is explicit rather than inferred from DOM position;
- Outlook can be removed from normal consumer onboarding without remapping iCloud/Yahoo/IMAP;
- PKCE/state/nonce/replay and stable Google-sub protections remain unchanged.

This contract restores the previously owner-proven matching-client-credential behavior while retaining the later one-time-login persistence architecture.

## Production boundary

While the Google OAuth consent project is **External / Testing**, only configured test users can complete owner acceptance. Public consumer release requires the Google project to move through the appropriate production/verification process for the requested Gmail scope.

That provider publication process is external to the local Email Shield codebase; the application must not claim unrestricted public Gmail availability until it is completed.
