# Email Shield — Community Operational Metrics and Diagnostics

Date: 2026-08-11  
Status: application boundary implemented; deployed monitoring and gateway reputation/volumetric controls remain external.

## Metrics access

The dedicated community service exposes `GET /metrics` only when `EMAIL_SHIELD_COMMUNITY_METRICS_TOKEN` contains at least 32 bytes. Without a token the route returns the same generic 404 shape as an unknown path. With a configured token, the route requires an exact `Authorization: Bearer <token>` value compared in constant time, returns `Cache-Control: no-store`, and emits Prometheus text.

The token belongs in the deployment secret manager. It must not be placed in source control, command history, monitoring labels, URLs or logs. The production reverse proxy should additionally restrict `/metrics` to the monitoring network or workload identity.

## Cardinality and privacy contract

All metric names and label values are fixed by code. The process exports only:

- readiness and signed-feed availability gauges;
- active request and uptime gauges;
- request counts/status classes and cumulative duration by fixed route name;
- accepted, duplicate, invalid, rate-limited, capacity-rejected, unavailable and internal report outcomes;
- fixed operational diagnostic counts;
- aggregate retained campaign/warning/confirmed counts when storage is readable.

Metrics never contain raw request paths, query strings, IP addresses, user agents, reporter proofs, campaign fingerprints, indicators, destinations, mailbox/provider/message/account identity, report bodies, feed entries, cache keys, key IDs, signing material, credentials, tokens, filesystem paths, exception text or stack traces.

The registry uses fixed maps and numeric counters, so attacker input cannot create a new time series or grow an in-memory label set.

## Structured diagnostics

The production community entry point writes one JSON object per operational event to standard error. Its exact schema is:

```json
{
  "schemaVersion": 1,
  "timestamp": "ISO-8601 timestamp",
  "component": "email-shield-community",
  "severity": "warning or error",
  "event": "fixed event name"
}
```

The only event names are readiness failure, invalid JSON/report, rate limiting, capacity rejection, service unavailable, request too large, internal error and metrics authentication failure. No exception or attacker-controlled value is accepted by the event constructor. Every event increments its aggregate counter, while JSON-line emission is bounded to one line per event type per 30 seconds to prevent request-driven log amplification. Sink failures are swallowed so logging cannot change a public request result.

## Abuse boundary

These counters make application-level invalid traffic, reporter-proof rate limiting and storage capacity rejection observable. They do not provide device enrollment, IP reputation, bot defence or volumetric/DDoS protection. GAP-008 remains open until the production gateway supplies and proves those controls. GAP-004 remains open until the metrics endpoint is connected to real monitoring/alerting with TLS, access controls, retention and incident procedures.

## Automated evidence

`communityOperationalMetrics.test.ts` locks disabled-by-default behavior, strong token validation, exact bearer authorization, fixed-label output, accepted/duplicate/invalid accounting, readiness and aggregate gauges, JSON-line schema and explicit absence of sensitive source values. Existing public-error, readiness and network integration suites remain blocking.
