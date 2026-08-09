# Gmail OAuth ES-GOOGLE-01 Owner Failure — 2026-08-09

## Evidence

During controlled owner acceptance on Windows, Google consent returned to Email Shield's loopback callback and Email Shield displayed:

`Google token exchange could not be completed (ES-GOOGLE-01).`

The failure occurred after a previous real authorization had reached the callback but was rejected later by Email Shield's earlier Google-scope compatibility defect.

## Diagnosis

The Desktop OAuth request shape itself remains standards-compliant and no client secret is required for Email Shield's public desktop client model. The actionable defect was the guided connect contract: Email Shield requires a refresh token for protected offline custody, while Google may omit a new refresh token on later authorizations when the user has already granted consent.

The earlier rejected local connection could therefore leave Google consent active without leaving Email Shield with a usable protected refresh token. A retry using only `access_type=offline` was insufficient to guarantee the credential Email Shield requires.

## Resolution

The explicit user-initiated Gmail connection URL now combines:

- `access_type=offline`
- `prompt=consent`
- Authorization Code + PKCE S256
- the existing one-time state and nonce
- the existing required Gmail/OpenID scopes

Email Shield still rejects token responses that do not contain the refresh token required for durable protected custody. It does not downgrade to a short-lived access-token-only account.

This failure is locked by `REG-044` and `gmailOAuthGoogleCompatibility.test.ts`.