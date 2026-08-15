# REG-087 — Local Forwarded-Header Boundary

Status: **LOCKED**

## Defect

The loopback desktop server rejected a small hard-coded set of legacy proxy headers (`X-Forwarded-Host`, `X-Forwarded-Proto`, and `X-Forwarded-For`) but did not reject the standardized `Forwarded` header or other `X-Forwarded-*` variants. A request carrying `Forwarded: host=...` could therefore reach the local dashboard even though Email Shield's local-only security contract forbids proxy-forwarded requests.

The Host allowlist still prevented an attacker-controlled non-loopback `Host` value, but accepting forwarding metadata contradicted the fail-closed local-origin boundary and left an unnecessary ambiguity for deployments or software that might interpret proxy headers differently.

## Root repair

`LocalSecurityManager.validateLoopbackRequest` now rejects the standardized `Forwarded` header and every header whose normalized name starts with `x-forwarded-`. The rule is category-based rather than a list of three known names, so future `X-Forwarded-*` variants cannot silently fall outside the local-only boundary.

The existing loopback Host validation, CSRF proof, same-origin checks, single-use mutation nonces, action-token replay protection, response redaction, and route limits remain unchanged.

## Permanent protection

- `tests/unit/localApiSecurity.test.ts` proves an attacker Host is rejected.
- The same regression proves `X-Forwarded-Host`, standardized `Forwarded`, and an additional `X-Forwarded-Port` variant are all rejected with HTTP 421.
- The full Windows/macOS/Ubuntu Engineering Gate and compiled desktop smoke remain blocking release gates.

Any future change that accepts standardized or `X-Forwarded-*` proxy forwarding metadata at the local desktop server is a blocking security regression.