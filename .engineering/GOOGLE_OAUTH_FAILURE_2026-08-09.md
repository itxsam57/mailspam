# Gmail OAuth acceptance failure — 2026-08-09

Owner-visible acceptance reached the protected loopback callback but ended with the generic Google connection failure page.

Root engineering findings:

- Google can canonicalize the requested OpenID Connect `email` permission as `https://www.googleapis.com/auth/userinfo.email`; Email Shield must accept either representation while still requiring `openid` and `gmail.modify`.
- A generic post-callback failure was not actionable enough to distinguish token exchange, ID-token/nonce verification, Gmail API validation, and protected local credential setup.

Permanent regression requirements:

1. Accept both `email` and Google's canonical `https://www.googleapis.com/auth/userinfo.email` as the same email grant.
2. Keep `openid` and `https://www.googleapis.com/auth/gmail.modify` mandatory.
3. Never expose Google authorization codes, refresh/access/ID tokens, provider response bodies, or lower-layer credential errors.
4. Return only safe stage diagnostics:
   - `ES-GOOGLE-01` — token exchange boundary;
   - `ES-GOOGLE-02` — ID-token/nonce verification boundary;
   - `ES-GOOGLE-03` — real Gmail API validation boundary;
   - `ES-GOOGLE-04` — protected local credential/session setup boundary.
5. The next owner retry must either connect successfully or identify one of those safe stages.

Automated coverage: `tests/unit/gmailOAuthGoogleCompatibility.test.ts`.
