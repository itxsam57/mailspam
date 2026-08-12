# Deployment, Capacity and Cost Planning

Version: 1.0 — 2026-08-11

This document turns Email Shield’s code ceilings into an operator-owned sizing and cost worksheet. It is not a throughput, latency, availability or cloud-price SLA.

## Proven application boundaries

| Boundary | Enforced value | Evidence |
|---|---:|---|
| Community report request | 64 KiB | Express/strict report validation |
| Receipt / signed feed | 32 KiB / 4 MiB | streamed acquisition and schema gates |
| Signed feed entries | 20,000 | signer/client exact bounds |
| Authoritative snapshot+journal+keys | 192 MiB | runtime and recovery shared ceiling |
| Append journal | 16 MiB | compaction-before-capacity failure |
| Campaign records | 100,000 | aggregate store capacity rejection |
| Reporter submissions | 50/day | application reporter-proof limit |
| Reporter contribution retention | 90 days | prune/restart/feed tests |
| Destination analysis | 4 active, 256 queued, 512 cached | bounded coordinator |
| Background scanning | 1 active; 20 messages/run (10 live IMAP); 30 min–24 h | scheduler/compiled Worker smoke |
| Scan history / schedules | 40 records/account; 128 scheduled accounts | encrypted local stores |

The release-capacity regression accepts 10,000 independent reporters against the real validation/encrypted-journal/dedupe/restart/sign/consume path and proves a duplicate remains one reporter. It runs through `npm run test:capacity` during Linux CI and release signing, not inside the workstation unit suite. The ordinary unit suite keeps the same durability, restart, dedupe, retention, recovery and tamper invariants at a deterministic representative scale. This proves the 10,000-client scenario, not sustained 10,000-request concurrency, multi-region availability or a public throughput SLA. The community store is a single-service local encrypted state design; horizontal writers require a new consistency/storage architecture.

The background smoke runs the compiled Worker under a 192 MiB V8 heap and blocks if the fixture scan exceeds 30 seconds or grows RSS by 128 MiB. Real mailbox latency and OS background policy still require platform acceptance.

## Executable plan

`config/capacity/v1/community-baseline.json` models 10,000 clients, 500 reports/day, daily 512 KiB feed acquisition, 90-day report payload planning, one authoritative service instance and three backup copies. Run:

```text
npm run capacity:plan
```

The output reports daily/monthly requests, ingest/feed egress, retained-payload planning ratio, provisioned active+backup storage and exact application ceilings. It intentionally omits price totals until the operator supplies all current contracted unit prices:

```text
npm run capacity:plan -- --compute-instance-hour <price> --storage-gib-month <price> --egress-gib <price> --request-million <price>
```

The four prices use one operator-selected currency consistently. Compute uses 730 hours/month; traffic uses 30 days/month; GiB uses 1024³ bytes. Taxes, support, gateway/WAF, monitoring/log retention, DNS/TLS, secret manager, backup operations, staff/on-call, signing/notarization and mobile-store fees are outside the arithmetic and must be added separately.

`npm run check:capacity` imports the compiled runtime constants, rejects baseline storage planning above 70% of the 192 MiB authoritative ceiling, locks concurrency/network budgets and verifies cost arithmetic. Linux CI enables the 10,000-reporter qualification in the Engineering Gate; release signing runs it explicitly. Workstation gates run deterministic capacity invariants without imposing central-service stress work on consumer-app development. Every full gate retains the low-heap background smoke and package size verification.

## Production sizing and alerts

Before launch, replace the baseline with measured report frequency/feed size, run a production-shaped load test against the actual TLS/gateway/storage stack, and record p50/p95/p99 latency, CPU, RSS, event-loop delay, disk latency, journal compaction, feed build/sign time and recovery time. Test normal, burst, malicious-invalid, storage-near-capacity and dependency-failure traffic.

Recommended planning triggers (operator policy, not code guarantees):

- keep projected authoritative use below 70%; alert at measured 70%, page at 85%, reject safely at enforced capacity;
- alert on readiness failure, any sustained 5xx rise, capacity rejection, journal compaction failure, backup failure, feed signature/anti-rollback rejection and unexpected report-rate change;
- keep at least one isolated authenticated restore copy and enough storage for active state plus every retained backup;
- provision two service instances only when the storage architecture guarantees one authoritative writer—do not point independent writers at the same files;
- budget feed egress explicitly; at the baseline, feed delivery dominates request bytes even before gateway/monitoring costs.

## Deployment sequence

1. Approve the exact commit only after the three-OS Engineering Gate and zero blocking advisories.
2. Build/verify the host package; run provider compatibility, Regression Vault and capacity gates before production signing.
3. Provision least-privilege runtime identity, encrypted persistent volume, secret manager, owner-controlled signing keys and independent backups.
4. Bind the community process to loopback/private network behind TLS/HSTS, request limits, IP/behavioral rate controls, bot/enrollment/reputation and DDoS protection.
5. Restrict `/metrics` to the monitoring network with its separate strong bearer token; retain only fixed aggregate labels.
6. Execute readiness, warning/confirmed thresholds, bad-feed rejection, outbox recovery, backup/restore, key overlap/switchover/retirement and incident drills.
7. Record actual cost/usage/latency and set reviewed alerts. Re-run the plan on material traffic, price, retention, schema or architecture change.

The complete community commands/endpoints/key/backup acceptance are in `.engineering/COMMUNITY_DEPLOYMENT.md`; release installation/signing details are in `.engineering/RELEASE_UPDATE_LIFECYCLE.md`.
