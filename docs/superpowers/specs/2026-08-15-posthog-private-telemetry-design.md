# Privacy-Safe PostHog Technical Telemetry Design

## Purpose

Connect Email Shield's desktop server to the existing PostHog project for narrowly scoped engineering health signals without weakening Email Shield's local-first privacy boundary.

## Architecture

A single `server/src/telemetry/technicalTelemetry.ts` module owns all outbound telemetry. The module is disabled by default and becomes active only when `EMAIL_SHIELD_TELEMETRY=1` and a PostHog project token are present. It uses Node's built-in `fetch`, so the integration adds no runtime dependency and does not disturb the locked dependency graph.

The module exposes a small event allowlist and property allowlist. Callers cannot send arbitrary mailbox data. Runtime validation rejects unknown event names and unknown properties even if TypeScript checks are bypassed.

## Privacy Boundary

Permitted data is limited to:

- fixed component name (`desktop_server`)
- application version
- operating-system platform
- bounded technical duration values
- fixed failure classifications with no raw error messages or stack traces

The transport must never send email bodies, subjects, sender or recipient identity, addresses, attachment data, OAuth tokens, credentials, personal policy contents, device identity, account identity, or session replay data.

All events use one constant anonymous distinct ID, disable person-profile processing, and disable GeoIP enrichment. No request-context middleware, autocapture, or browser/session replay is installed.

## Failure Behavior

Telemetry is non-authoritative. Disabled telemetry, invalid configuration, invalid event data, HTTP failures, timeouts, or PostHog outages return `false` and must never prevent Email Shield from starting or protecting mail.

## Integration Points

The desktop startup path emits only these initial signals:

- `email_shield_app_started`
- `email_shield_protected_state_ready` with `duration_ms`
- `email_shield_protected_state_failed` with a fixed failure classification
- `email_shield_server_listening`

The protected-state failure signal is emitted before rethrowing the original startup error; the original error remains the source of truth locally.

## Verification

Unit tests must prove opt-in behavior, exact anonymous payload shape, rejection of unknown/sensitive fields, and fail-soft network behavior. The repository's existing cross-platform Engineering Gate remains the release gate.