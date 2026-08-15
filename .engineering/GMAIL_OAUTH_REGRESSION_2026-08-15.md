# Gmail OAuth matching-client regression — 2026-08-15

## Owner evidence

Controlled Windows owner acceptance reached Google's loopback callback and then failed at Email Shield stage `ES-GOOGLE-01` during authorization-code exchange.

This failure matched an earlier owner-acceptance defect already fixed in PR #31: Email Shield's guided Gmail/OIDC flow needed the matching Google Desktop OAuth client secret at the token endpoint and subsequent Gmail OAuth runtime.

## Root regression

PR #71 added durable live-mailbox restoration but also changed the accepted Google client credential from required to optional and removed it from the guided Gmail runtime config. That unintentionally reversed the owner-proven PR #31 behavior.

The later consumer release work then treated the public client ID alone as proof that Google sign-in was configured, so the Google button could become available even though the token exchange could not succeed on the owner's actual Desktop OAuth registration.

## Root repair

The combined architecture now preserves both accepted requirements:

1. Google consumer readiness requires the matching Desktop client ID and client secret.
2. Authorization-code exchange sends client ID + client secret + PKCE verifier + code + grant type + exact loopback redirect URI.
3. Initial Gmail provider validation uses the same matching client credentials.
4. The client secret is application-level runtime configuration, not per-mailbox persisted state.
5. Guided Gmail persistence stores only mailbox identity metadata plus the OS-vault refresh-token handle.
6. Restored Gmail sessions rehydrate the application-level client secret from process configuration when the adapter is materialized.
7. Source `npm run dev` loads root `.env.local`, which remains Git-ignored.
8. CI/package verification no longer treats client ID alone as live OAuth capability.
9. Normal consumer onboarding omits Outlook for the current owner test and maps provider identity explicitly rather than by card position.

## Permanent regression contract

Future changes must not:

- enable consumer Google sign-in from client ID alone;
- omit the configured matching client secret from the real token exchange;
- drop the matching client secret from Gmail refresh/provider runtime after restart;
- write the Google application client secret into the mailbox live-connection registry;
- infer provider identity from consumer-card DOM position;
- expose a deferred provider in normal consumer onboarding merely because its internal adapter remains implemented;
- weaken PKCE, state, nonce, callback replay, host/path/method, native-vault or stable Google `sub` protections to solve OAuth configuration failures.
