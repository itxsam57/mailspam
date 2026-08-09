# Gmail OAuth Refresh-Token Re-consent Regression — 2026-08-09

## Owner-visible failure

During controlled real-Google acceptance, the first guided Gmail attempt reached Email Shield's loopback callback but failed later because Google canonicalized the OIDC `email` permission as `https://www.googleapis.com/auth/userinfo.email`. That compatibility issue was corrected.

On the next controlled attempt, Email Shield reported `ES-GOOGLE-01` during the authorization-code/token stage.

## Root cause

A successful Google consent can remain associated with the OAuth client even when Email Shield rejects or fails the later local setup. Google's installed-app OAuth behavior does not guarantee a new refresh token on every later authorization once consent already exists. Email Shield, however, requires a refresh token before it can create the protected long-lived Gmail credential session.

The original guided authorization URL requested `access_type=offline` but did not explicitly request fresh consent. After the earlier failed local connection, a later authorization could therefore return a valid token response without a new `refresh_token`; Email Shield correctly refused to create an incomplete persistent session, but surfaced that refusal only as `ES-GOOGLE-01`.

## Root fix

Every explicit user-initiated **Connect Gmail** authorization now requests:

- `access_type=offline`;
- `prompt=consent`;
- Authorization Code + PKCE S256;
- the same required OpenID/email/Gmail modify scopes.

This makes the explicit connection operation request a fresh Google consent decision when Email Shield needs a new protected offline refresh token. The runtime still requires a refresh token before completing the account session; it does not downgrade to access-token-only behavior.

No OAuth client secret was added. PKCE, state, nonce, loopback-host validation, replay resistance, token redaction, stable Google `sub` identity, protected credential custody and final-account revocation remain unchanged.

## Permanent regression coverage

`tests/unit/gmailOAuthGoogleCompatibility.test.ts` now asserts that the generated guided authorization URL contains both `access_type=offline` and `prompt=consent`, retains `code_challenge_method=S256`, requests the required scopes and never emits a `client_secret` parameter.

## Acceptance status

Automated acceptance must pass on Windows and Ubuntu before merge. Real Gmail owner acceptance remains open until the user connects successfully, completes Quick Scan, verifies browser-response token privacy, disconnects and reconnects successfully.