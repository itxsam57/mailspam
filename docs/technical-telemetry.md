# Technical Telemetry

Email Shield's PostHog connection is an optional engineering-health channel. It is disabled by default and does not install browser analytics, autocapture, session replay or request-context tracking.

## Runtime configuration

Provide these environment variables only in the runtime environment. Do not commit a real PostHog project token to this repository.

```text
EMAIL_SHIELD_TELEMETRY=1
EMAIL_SHIELD_POSTHOG_PROJECT_TOKEN=<PostHog project ingestion token>
EMAIL_SHIELD_POSTHOG_HOST=https://us.i.posthog.com
EMAIL_SHIELD_RELEASE_VERSION=0.2.0
```

`EMAIL_SHIELD_POSTHOG_HOST` may be changed to the PostHog ingestion host for the deployment region. The host must be HTTPS and must not contain embedded credentials, query parameters or fragments. If telemetry is not explicitly enabled, the project token is absent, or the host is invalid, telemetry remains disabled.

## Allowed events

The desktop server may emit only:

- `email_shield_app_started`
- `email_shield_protected_state_ready`
- `email_shield_protected_state_failed`
- `email_shield_server_listening`

The only event-specific properties are a bounded `duration_ms` for protected-state readiness and the fixed `failure_kind=initialization_error` classification for protected-state failure. Common properties are the fixed component label, application version and operating-system platform.

The transport uses a constant anonymous runtime identifier, requests no PostHog person profile and disables GeoIP enrichment in the payload.

## Forbidden data

The telemetry boundary must never receive or send email bodies, subjects, sender or recipient identity, mailbox addresses, URLs, provider message IDs, attachment data, account identity, device identity, personal-policy contents, credentials, OAuth tokens, app passwords, raw exception messages or stack traces.

Unknown event names and unknown property names are rejected at runtime. This remains true even if compile-time TypeScript checks are bypassed.

## Failure behavior

Telemetry is non-authoritative. A disabled configuration, invalid payload, timeout, network failure or non-success PostHog response causes that telemetry call to return `false`; it does not change Email Shield's local protection behavior. Protected-state failure reporting is best-effort and non-blocking so telemetry can never delay, replace or reorder the application's original startup failure.
