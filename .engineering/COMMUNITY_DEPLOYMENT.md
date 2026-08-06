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
- One or two reporters create a private candidate only; no feed entry is published.
- At least three independent reporters plus evidence weight create a signed warning.
- At least five independent reporters, at least three strong reports and the confirmed evidence weight create a confirmed campaign.
- Each Confirmed indicator must itself be supported by all five required reporters.
- Generic no-reply/reporting delivery addresses are not published as exact sender indicators, protecting shared carriers from mass false blocks.
- Invalid reports, oversized payloads and excessive per-reporter daily submissions are rejected.

## Central service configuration

The same compiled server can operate as the aggregation node.

Required environment:

```text
EMAIL_SHIELD_COMMUNITY_SERVER=1
EMAIL_SHIELD_DATA_DIR=/secure/persistent/email-shield
HOST=127.0.0.1
PORT=4173
```

For production signing, supply both halves through a secret manager:

```text
EMAIL_SHIELD_COMMUNITY_PRIVATE_KEY=<Ed25519 PKCS8 PEM>
EMAIL_SHIELD_COMMUNITY_PUBLIC_KEY=<Ed25519 SPKI PEM>
```

When neither is supplied, the service generates a pair under `EMAIL_SHIELD_DATA_DIR`. The private file must be backed up securely and must never enter source control, CI artifacts or application logs.

Endpoints:

```text
POST /api/community/v1/report
GET  /api/community/v1/feed
GET  /api/community/v1/public-key
GET  /api/community/v1/status
```

Report ingestion and feed/public-key serving are disabled unless `EMAIL_SHIELD_COMMUNITY_SERVER=1`.

## Client configuration

```text
EMAIL_SHIELD_COMMUNITY_URL=https://community.example.com
EMAIL_SHIELD_COMMUNITY_PUBLIC_KEYS=["-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"]
```

Clients refuse non-HTTPS remote services except loopback development. They follow no redirects. A downloaded feed is used only after Ed25519 signature and freshness verification. An invalid, expired or untrusted feed becomes unavailable, never implicitly Safe.

Failed reports are encrypted locally and retried on a later feed refresh.

## Required production perimeter

Do not expose the desktop dashboard directly to the internet. Put the community endpoints behind a dedicated reverse proxy or API gateway with:

- HTTPS and HSTS;
- request-size limits at or below the application’s 64 KB JSON limit;
- per-IP and behavioral rate limiting in addition to reporter-proof limits;
- bot/abuse controls and denial-of-service protection;
- structured security logging that never records report bodies or secrets;
- health checks and latency/error monitoring;
- encrypted persistent volume and tested backups;
- restricted outbound networking;
- process isolation and least-privilege filesystem permissions.

The repository implements application-level validation, deduplication, encrypted storage and reporter-proof limits. Gateway-level identity/reputation and volumetric abuse controls cannot be proven by repository CI.

## Key rotation

Clients support more than one trusted public key. Rotate without breaking verification:

1. Generate the new Ed25519 pair in a protected environment.
2. Distribute the **new public key alongside the old key** to clients through `EMAIL_SHIELD_COMMUNITY_PUBLIC_KEYS`.
3. Confirm clients accept a test feed signed by the new key.
4. Change the server’s configured private/public pair.
5. Retain the old public key in clients for longer than the maximum 48-hour feed validity plus rollout margin.
6. Remove the old public key only after all old feeds have expired and client rollout is confirmed.
7. Archive or destroy the old private key according to the incident/retention policy.

A configured private key without its matching public key, an incomplete on-disk pair or a mismatched pair causes startup failure rather than silent key replacement.

## Backup and recovery

Back up together:

- `community-reports.enc.json`
- `community-storage.key`
- `community-feed-private.pem`
- `community-feed-public.pem`

The encrypted database is unusable without its storage key. The signing identity changes if the feed key pair is lost, requiring a public-key trust rollout.

Do not delete corrupted files as the first response. Preserve copies for diagnosis and restore the matched database/key pair from backup.

## Deployment acceptance

Before public use:

1. Run `npm ci` and `npm run verify` on the deployment commit.
2. Start the service in explicit server mode using a clean persistent directory.
3. Confirm client mode returns 404 for ingestion/feed endpoints when server mode is absent.
4. Confirm server mode publishes a verifiable public key and empty signed feed.
5. Submit three controlled independent reports and verify warning publication.
6. Submit five controlled independent reports and verify confirmed publication.
7. Tamper with a copied feed and confirm client rejection.
8. Stop the service during a client report and confirm encrypted outbox queuing and later flush.
9. Complete external TLS, gateway rate-limit, monitoring, backup and restore tests.

Repository CI completes items 1 and application-level forms of 3–8. Public DNS/TLS, gateway controls and operational monitoring require the actual deployment environment.