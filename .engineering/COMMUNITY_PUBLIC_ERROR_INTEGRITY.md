# Community Public Error Integrity

## Root cause

The dedicated unauthenticated community service previously exposed internal failure details through multiple paths:

- report ingestion classified failures by substring matching on exception messages and returned that internal message;
- feed publication returned raw exception text on HTTP 503;
- status/public-key failures could reach Express's default error handler;
- malformed or oversized JSON could surface body-parser/Express diagnostics rather than a stable service contract.

The aggregate report validator also relied on TypeScript compile-time shapes at a public runtime boundary. Wrong verdict, evidence-score, evidence-code or indicator types could therefore become internal exceptions or malformed aggregation instead of deterministic validation failures.

## Accepted public error contract

The dedicated public community service returns only stable machine-readable JSON errors:

- malformed JSON -> HTTP 400 `{ "error": "invalid_json" }`;
- invalid report schema/content -> HTTP 400 `{ "error": "invalid_report" }`;
- oversized JSON request -> HTTP 413 `{ "error": "request_too_large" }`;
- reporter rate limit -> HTTP 429 `{ "error": "rate_limited" }`;
- disabled service, aggregate capacity, corrupt/unavailable storage, feed/signing/public-info operational failure -> HTTP 503 `{ "error": "service_unavailable" }`;
- unexpected final middleware failure -> HTTP 500 `{ "error": "internal_error" }`;
- unknown route -> HTTP 404 `{ "error": "not_found" }`.

Every public error response is JSON and `Cache-Control: no-store`.

Raw exception messages, stack traces, filesystem paths, cryptographic/storage diagnostics, provider details and attacker-controlled field values are not part of the public error contract.

## Typed internal failures

Application/domain code uses explicit internal error classes for:

- report validation;
- reporter rate limiting;
- aggregate capacity;
- disabled central-service mode.

The dedicated HTTP service maps those types at its boundary. It does not infer status from message substrings.

Unexpected operational exceptions are collapsed to a generic unavailable/internal code according to the route boundary rather than echoed.

## Runtime report validation

A report must be validated before encrypted aggregate state is read or written.

The version-1 runtime schema requires:

1. a report object with schema version 1;
2. reporter proof and campaign fingerprint as exactly 64 lowercase hexadecimal characters;
3. a bounded parseable report timestamp inside the existing submission window;
4. a supported verdict;
5. a finite numeric evidence score, then the existing bounded score clamp;
6. an evidence-code array of at most 64 values, each matching the existing uppercase code format;
7. 1-32 indicator objects using only supported community indicator types;
8. non-empty indicator values of at most 512 characters;
9. any explicit campaign indicator to equal the report campaign fingerprint;
10. duplicate indicators/evidence codes to be canonicalized without increasing independent support.

Malformed indicator objects or wrong runtime field types are rejected. They are not silently skipped into a partially accepted report.

If the valid report omits its campaign indicator, the aggregate layer continues to add the canonical campaign fingerprint indicator as before.

## Express/body-parser boundary

A final dedicated-service error middleware converts body parser and unexpected Express failures to the stable JSON contract. Default Express HTML error pages and stack output must never cross the unauthenticated community-service boundary.

This contract is separate from the authenticated desktop-local API, which retains its own local-session/CSRF/redaction/error governance.

## Security and privacy boundary

This brick adds no:

- mailbox/provider permission;
- provider API request;
- mailbox content exposure;
- new community report field;
- public diagnostic endpoint;
- signing private-key exposure;
- automatic external destination request.

## Live deployment boundary

This contract does **not** close GAP-004 or GAP-008.

CI proves deterministic application-level public HTTP error isolation. Production reverse-proxy/WAF error pages, TLS/DNS, monitoring, IP/device reputation and volumetric/DDoS controls still require the deployed environment.

No live mailbox or public deployment test is required for this brick.

## Required regression coverage

Automation must prove at minimum:

- malformed JSON returns only `invalid_json` JSON/no-store;
- oversized JSON returns only `request_too_large` JSON/no-store;
- invalid runtime report field types return `invalid_report` before aggregate persistence;
- disabled/rate-limited/capacity failures map to the stable public status/code contract;
- real corrupt encrypted aggregate state cannot leak its content/path/error through status, feed, public-key or report routes;
- unexpected route exceptions are sanitized;
- unknown routes use the stable JSON 404 contract;
- architecture tests lock typed disabled-service behavior instead of raw-message coupling;
- existing community reporting/signing/network behavior remains green;
- strict type/build and the full Windows/macOS/Ubuntu Engineering Gate remain green.
