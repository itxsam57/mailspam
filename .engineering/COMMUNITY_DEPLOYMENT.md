# Email Shield Community Shield — Deployment Runbook

This document describes the implemented self-hosted community reporting service and the production controls that remain operational responsibilities.

## Architecture

Email Shield clients normalize Gmail, iCloud, Outlook, Yahoo and Generic IMAP messages into one canonical envelope. `Report Scam to Email Shield` produces a privacy-reduced report from that canonical envelope, so the shared intelligence contract is provider neutral.

A report contains only:

- a stable pseudonymous reporter proof generated with an installation-local random HMAC key;
- campaign fingerprint;
- eligible direct sender indicator;
- unrelated Reply-To organizational domain;
- unrelated destination organizational domains;
- attachment SHA-256 hashes;
- deterministic evidence codes, bounded score and verdict.

It excludes mailbox address/proof, subject, body, contacts, credentials, OAuth/app-password values, provider message IDs, raw URL paths/query values, attachment names and attachment content.

## Aggregation rules

- A reporter proof counts once per campaign.
- One or two reports create a private candidate only; no feed entry is published.
- At least three reporter proofs plus the warning weight create a signed warning.
- At least five reporter proofs, at least three strong reports and the confirmed weight create a confirmed campaign.
- Each Confirmed indicator must itself be supported by all five required reporter proofs.
- Three explicit human reports can create a warning even when the earlier detector called the messages Safe.
- Evidence-free human reports cannot create Confirmed Threat status by themselves.
- Generic no-reply/reporting delivery addresses are not published as exact sender indicators, protecting shared carriers from mass false blocks.
- Invalid reports, oversized payloads, forged timestamps and excessive per-reporter daily submissions are rejected.
- Accepted reports are durably appended to a bounded encrypted journal and periodically compacted into the encrypted aggregate snapshot, so ingestion does not rewrite the complete database per request.
- Reporter-attributed campaign state has a fixed 90-day retention boundary; expired reporters no longer contribute to thresholds or signed feed entries.
- The blocking capacity suite sends 10,000 independent reporters through validation, encrypted persistence, deduplication, restart recovery and signed-feed consumption.

A reporter proof is privacy preserving but is not a complete Sybil defence across reinstallations or devices. Public operation still requires gateway enrollment, reputation and volumetric abuse controls.

## Build and start the dedicated service

```bash
npm ci
npm run verify
npm run build
```

Set:

```text
EMAIL_SHIELD_COMMUNITY_SERVER=1
EMAIL_SHIELD_DATA_DIR=/secure/persistent/email-shield
EMAIL_SHIELD_COMMUNITY_METRICS_TOKEN=<secret-manager token of at least 32 bytes>
HOST=127.0.0.1
PORT=4174
```

Then run:

```bash
npm run start:community
```

The dedicated `communityIndex` entry point exposes no desktop dashboard, mailbox account API, scan Worker, provider credential route or mailbox action.

For production signing, supply both halves through a secret manager:

```text
EMAIL_SHIELD_COMMUNITY_PRIVATE_KEY=<Ed25519 PKCS8 PEM>
EMAIL_SHIELD_COMMUNITY_PUBLIC_KEY=<Ed25519 SPKI PEM>
```

When neither is supplied, the service generates a pair under `EMAIL_SHIELD_DATA_DIR`. The private file must be backed up securely and must never enter source control, CI artifacts or application logs.

Dedicated endpoints:

```text
GET  /health
POST /api/community/v1/report
GET  /api/community/v1/feed
GET  /api/community/v1/public-key
GET  /api/community/v1/status
GET  /metrics  (disabled unless a metrics token is configured; bearer protected)
```

The dedicated process refuses to start unless `EMAIL_SHIELD_COMMUNITY_SERVER=1`.

`/metrics` exports fixed-label Prometheus counters/gauges and requires the exact bearer token configured through `EMAIL_SHIELD_COMMUNITY_METRICS_TOKEN`. Store that token in the deployment secret manager and restrict the route to the monitoring network at the reverse proxy. The endpoint is absent when the token is not configured. Its application privacy/cardinality contract is `.engineering/COMMUNITY_OPERATIONAL_METRICS.md`.

## Client configuration

```text
EMAIL_SHIELD_COMMUNITY_URL=https://community.example.com
EMAIL_SHIELD_COMMUNITY_PUBLIC_KEYS=["-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"]
```

Clients refuse non-HTTPS remote services except loopback development and follow no redirects. A downloaded feed is used only after Ed25519 trust, signature and freshness verification. Invalid, expired or untrusted intelligence becomes unavailable, never implicitly Safe.

Failed reports are encrypted locally and retried on a later feed refresh. When no remote URL is configured, the UI labels aggregation as a local test network and does not claim cross-user protection.

## Required production perimeter

Put the dedicated community service behind a reverse proxy or API gateway with:

- HTTPS and HSTS;
- request-size limits at or below the application’s 64 KB JSON limit;
- per-IP and behavioral rate limiting in addition to reporter-proof limits;
- bot, enrollment, reputation and denial-of-service controls;
- structured security logging that never records report bodies or secrets;
- health, latency and error monitoring;
- authenticated scraping of `/metrics` with alerts for readiness, 5xx, rate-limit, capacity and storage-availability signals;
- encrypted persistent volume and tested backups;
- restricted outbound networking;
- process isolation and least-privilege filesystem permissions.

The repository implements application validation, deduplication, evidence thresholds, encrypted storage and reporter-proof limits. Gateway-level identity/reputation and volumetric abuse controls cannot be proven by repository CI.

## Key rotation

Clients support more than one trusted public key. Rotate without breaking verification:

1. Generate the new Ed25519 pair in a protected environment.
2. Distribute the **new public key alongside the old key** through `EMAIL_SHIELD_COMMUNITY_PUBLIC_KEYS`.
3. Confirm clients accept a controlled feed signed by the new key.
4. Change the central service’s configured private/public pair.
5. Retain the old public key longer than the maximum 48-hour validity plus rollout margin.
6. Remove the old public key after all old feeds expire and rollout is confirmed.
7. Archive or destroy the old private key according to policy.

A configured private key without its matching public key, an incomplete on-disk pair or a mismatched pair causes startup failure rather than silent replacement.

## Backup and recovery

Back up together:

- `community-reports.enc.json`
- `community-reports.journal.enc.ndjson`
- `community-storage.key`
- `community-feed-private.pem`
- `community-feed-public.pem`

The encrypted snapshot and journal are unusable without their storage key. The built-in backup/restore operation preserves the matched snapshot, journal, storage key and signing pair under one authenticated recovery envelope. Losing the signing pair changes the feed identity and requires a client public-key rollout.

Do not delete corrupted files as the first response. Preserve copies for diagnosis and restore the matched database/key pair from backup.

## Deployment acceptance

Before public use:

1. Run `npm ci` and `npm run verify` on the deployment commit.
2. Start `npm run start:community` in explicit server mode using a clean persistent directory.
3. Confirm `/health` is ready and `/`, `/api/accounts` and desktop routes return 404.
4. Confirm the service publishes a verifiable public key and empty signed feed.
5. Submit three controlled reporter proofs and verify warning publication.
6. Submit five controlled strong reports and verify confirmed publication.
7. Tamper with a copied feed and confirm client rejection.
8. Stop the service during a client report and confirm encrypted outbox queuing and later flush.
9. Verify local-only clients label their scope truthfully.
10. Complete external TLS, gateway rate-limit, enrollment/reputation, monitoring, backup and restore tests.
11. Confirm unauthenticated `/metrics` access fails, authenticated output has only fixed labels, and the monitoring pipeline stores no bearer token, reporter/campaign value or request body.

Repository CI completes item 1 and application-level forms of items 3–9. Public DNS/TLS, gateway controls and operational monitoring require the actual deployment environment.
