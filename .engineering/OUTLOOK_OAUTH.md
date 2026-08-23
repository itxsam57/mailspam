# Email Shield — Guided Outlook / Microsoft OAuth

## Scope

This Milestone 2 package replaces Outlook's former confidential-server credential assumption with a guided desktop OAuth flow appropriate for Email Shield's local application model.

The guided path uses:

- Microsoft identity platform v2 `common` authority so a correctly configured application registration can support both personal Microsoft accounts and organizational accounts;
- system-browser Authorization Code flow;
- PKCE with a unique high-entropy verifier and `S256` challenge;
- a random local callback port;
- an IPv4 loopback-only listener;
- `http://localhost:<ephemeral-port>` as the authorization/token redirect URI, matching Microsoft's native system-browser localhost registration behavior;
- cryptographically random `state` validated before a callback is consumed;
- exact callback Host, method and root-path restrictions;
- callback consumption before asynchronous token exchange to prevent replay.

The guided desktop path is a **public client**. It does not create, request, accept from the browser, or depend on a Microsoft client secret.

## Microsoft application configuration

Development builds read only the application-owned public client ID from:

`EMAIL_SHIELD_MICROSOFT_CLIENT_ID`

The Microsoft application registration must be configured as a **Mobile and desktop application / public client** for system-browser use with:

`http://localhost`

The application must allow the account audience intended for the Email Shield build. A development registration intended to test both Outlook.com/personal accounts and Microsoft 365 work/school accounts must choose a supported account type that includes both.

No Microsoft client secret is required or expected for guided desktop OAuth.

### Source live-acceptance handoff

For an owner-controlled source test, keep the application ID only in the ignored repository-local `.env.local` file. Start from `.env.example` when creating that file and set:

```text
EMAIL_SHIELD_MICROSOFT_CLIENT_ID=<Microsoft Application (client) ID>
```

Do **not** add a Microsoft client secret. The guided desktop path is intentionally a public client and source startup reads `.env.local` before launching the local server.

Then start the production-like consumer source boundary with:

```text
npm run dev
```

Do not use `npm run dev:fixtures` for real Microsoft acceptance. Before starting sign-in, the Outlook connection surface must report that Microsoft OAuth is configured; if it does not, stop and correct the application-ID handoff instead of testing with a different OAuth path.

## Requested permissions

The guided Outlook path requests only:

- `offline_access`
- `https://graph.microsoft.com/User.Read`
- `https://graph.microsoft.com/Mail.ReadWrite`

`offline_access` is required so Email Shield can obtain a refresh token for ongoing local protection.

`User.Read` is used to read the signed-in account's own Graph profile and establish the stable Graph `/me.id` account identifier.

`Mail.ReadWrite` is required because Email Shield reads mailbox content and already provides explicit provider-native Trash/Junk actions. The guided path does **not** request `Mail.Send`.

## Stable account identity

A rotating Microsoft refresh token must never define Email Shield account identity.

After token exchange, Email Shield validates Microsoft Graph:

1. `GET /me?$select=id,displayName,mail,userPrincipalName`
2. requires a non-empty Graph `id`;
3. uses email/UPN/display name only as display metadata;
4. validates Inbox access before committing the long-lived session.

The account-scoped policy key and native-vault refresh-token reference are derived from:

- provider (`outlook`);
- Email Shield's Microsoft client ID;
- stable Graph `/me.id`.

Changing or replacing a refresh token therefore does not move personal policy state or create a new account credential reference.

## Refresh-token custody and rotation

Microsoft may issue a replacement refresh token during refresh-token use. Email Shield treats that as credential replacement, not a new account.

For a guided Outlook account on Windows:

1. initial authorization code + PKCE exchange occurs only in the local OAuth process;
2. Graph account identity and Inbox permission are validated before persistence;
3. the initial refresh token is written to Windows Credential Manager behind one deterministic opaque `oauth-refresh-token` reference;
4. the long-lived session stores the handle, not the raw token;
5. a scan/action materializes the token only immediately before provider connection;
6. Microsoft refreshes the access token;
7. Graph `/me.id` must still match the protected account identity;
8. if Microsoft supplies a replacement refresh token, Email Shield writes it back to the **same secure handle** before accepting it as current;
9. failure to persist the replacement fails provider connection instead of silently continuing with uncommitted credential state.

On platforms without an implemented native credential backend, current compatibility remains process-memory-only. There is no plaintext persistent substitute. A Worker receives a cloned memory handle, so replacement-token persistence back to the parent process is not claimed on those unsupported platforms; full rotating-token persistence there remains dependent on the native Keychain/Secret Service work.

## Disconnect semantics

Normal Outlook Disconnect removes Email Shield's local account session and protected refresh-token record when the final shared reference is removed.

Email Shield deliberately does **not** call Microsoft Graph `revokeSignInSessions` for ordinary Outlook Disconnect. That operation has broader user-session semantics and can invalidate refresh tokens beyond Email Shield. Local account removal must not sign the user out of unrelated Microsoft applications.

Provider-wide authorization revocation, if later exposed, requires a separately designed user-visible operation with provider-appropriate semantics. It is not silently coupled to ordinary local Disconnect.

## Browser privacy boundary

The browser receives only:

- OAuth flow ID;
- Microsoft authorization URL containing public client metadata and one-time PKCE/state values;
- pending/complete/error status;
- Email Shield account ID and display label after success.

The browser must never receive or store:

- authorization code after callback;
- PKCE verifier;
- access token;
- refresh token;
- a Microsoft client secret.

The callback page exposes only a generic success/failure result and safe stage code.

## Automated acceptance boundary

The engineering gate locks:

- PKCE S256 generation;
- public-client authorization/token exchange without `client_secret`;
- exact required scope set and absence of `Mail.Send`;
- random-port loopback callback restrictions;
- one-time state/callback consumption and replay rejection;
- safe error stages;
- stable Graph account identity independent of refresh-token rotation;
- deterministic opaque Windows vault reference;
- replacement refresh-token overwrite of the same secure handle;
- fail-closed rotation when secure persistence fails;
- account mismatch rejection before replacement persistence;
- browser OAuth secret exclusion;
- all existing provider-neutral scan/action/detection regressions.

Real Microsoft authorization and a real Outlook Quick Scan remain owner-controlled acceptance because CI must not contain live mailbox credentials.

## Explicitly not claimed by this package

- macOS Keychain;
- Linux Secret Service/keyring;
- persistent rotating-token propagation from an unsupported-platform Worker back into the parent process;
- tenant-admin consent for organization policies that independently require it;
- provider-wide Microsoft session revocation as an ordinary Disconnect operation;
- local personal-policy encryption-key migration;
- final production publisher/consent verification or store packaging.
