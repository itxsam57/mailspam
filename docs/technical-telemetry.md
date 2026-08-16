# Technical Telemetry

Email Shield's PostHog connection is an optional engineering-health channel. It is disabled by default and does not install browser analytics, autocapture, session replay or request-context tracking.

Source/live owner testing also has a separate **local runtime workflow trace**. `npm run dev` and `npm run dev:fixtures` enable that bounded local trace automatically unless `.env.local` explicitly sets `EMAIL_SHIELD_RUNTIME_TRACE=0`. The local trace is authoritative for debugging and is stored under the managed Email Shield data directory in `diagnostics/runtime-workflow-trace.jsonl` with bounded rotation.

## Runtime configuration

Provide these environment variables only in the runtime environment. Do not commit a real PostHog project token to this repository.

```text
EMAIL_SHIELD_RUNTIME_TRACE=1
EMAIL_SHIELD_TELEMETRY=1
EMAIL_SHIELD_POSTHOG_PROJECT_TOKEN=<PostHog project ingestion token>
EMAIL_SHIELD_POSTHOG_HOST=https://us.i.posthog.com
EMAIL_SHIELD_RELEASE_VERSION=0.2.0
```

`EMAIL_SHIELD_RUNTIME_TRACE=1` controls only the local developer workflow recorder. The source development launchers turn it on automatically. `EMAIL_SHIELD_TELEMETRY=1` remains a separate explicit remote opt-in.

`EMAIL_SHIELD_POSTHOG_HOST` may be changed to the PostHog ingestion host for the deployment region. The host must be HTTPS and must not contain embedded credentials, query parameters or fragments. If telemetry is not explicitly enabled, the project token is absent, or the host is invalid, remote telemetry remains disabled even when the local runtime trace is active.

## Allowed events

The desktop server may emit only:

- `email_shield_app_started`
- `email_shield_protected_state_ready`
- `email_shield_protected_state_failed`
- `email_shield_server_listening`
- `email_shield_workflow_trace` — only through the separately validated runtime-trace mirror

The ordinary startup event-specific properties remain a bounded `duration_ms` for protected-state readiness and the fixed `failure_kind=initialization_error` classification for protected-state failure. Common properties are the fixed component label, application version and operating-system platform.

The workflow trace mirror accepts only the already-sanitized local record fields: opaque run/trace UUIDs, fixed stage/action/workflow/provider/scan-type labels, fixed component/step/outcome labels, masked route templates, HTTP method/status, bounded durations/counters/page sizes and fixed error codes. It independently revalidates every field before the PostHog request. Unknown fields reject the entire mirror event.

The transport uses a constant anonymous runtime identifier, requests no PostHog person profile and disables GeoIP enrichment in the payload.

## What the local workflow trace records

For source/browser acceptance, the trace can correlate one human action across the layers that actually execute it:

1. semantic browser control (`mailbox.scan.full`, `message.report_scam`, provider connect, navigation, etc.);
2. expected workflow (`full_mailbox_audit`, provider connection, message policy action, etc.);
3. masked protected API request and response metadata;
4. scan stream lifecycle, including the provider returned by the real server;
5. the Worker's reported bounded batch size for scans;
6. terminal success/failure/cancel classifications and bounded counters.

Synthetic programmatic button clicks do not replace the trace for the original human action. This prevents compatibility shims such as a provider card forwarding to a hidden Connect control from losing the provider that the owner actually selected.

## Forbidden data

Neither the local workflow trace nor the remote telemetry boundary may receive or send email bodies, subjects, sender or recipient identity, mailbox addresses, raw URLs, provider message IDs, attachment names/content, account IDs, device identity, personal-policy contents, credentials, OAuth tokens, app passwords, raw exception messages or stack traces.

Browser workflow tracing does not read visible DOM text, form values or request bodies. Dynamic account IDs and flow/scan IDs are replaced with fixed route-template placeholders before persistence. Unknown event fields are rejected at runtime. The PostHog mirror repeats this validation independently even though the local recorder already validated the record.

## Local inspection

When runtime tracing is active, the protected developer endpoint below returns only the current run's sanitized records:

```text
GET /api/dev/runtime-trace/current?limit=200
```

It is available only through the loopback protected local session boundary. The JSONL files remain the authoritative source if PostHog is disabled or unavailable.

## Failure behavior

Tracing and telemetry are non-authoritative. A disabled configuration, invalid payload, unwritable trace file, timeout, network failure or non-success PostHog response does not change Email Shield's local protection behavior. The local recorder fails soft; the remote mirror is best-effort and never blocks the browser action or protection workflow.
