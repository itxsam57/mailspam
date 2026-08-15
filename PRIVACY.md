# Email Shield Privacy Notice

Effective: 2026-08-15

Email Shield is local-first mailbox protection. The desktop client inspects messages on the user’s device and does not send message bodies to an Email Shield service. A separately configured community service receives only the privacy-reduced report described below. Optional technical telemetry is disabled by default and, when explicitly enabled, is limited to the anonymous engineering-health events described below. A self-hosted operator is responsible for its own deployment, notices and legal obligations.

## What the desktop client processes

With the user’s authorization, Email Shield reads bounded mailbox folders and message parts needed to normalize sender/authentication metadata, visible text, links, attachment metadata and selected bounded QR/hash-capable attachment bytes. Raw message content and acquired attachment bytes are transient. They are used by the local deterministic engine and are not placed in the community report, operational metrics, optional technical telemetry or Regression Vault automatically.

Provider credentials are held in Windows Credential Manager, macOS Keychain or Linux Secret Service through opaque references. Unsupported native-vault environments are memory-only and do not create a plaintext credential fallback. OAuth authorization still involves the selected email provider under that provider’s terms.

## Local stored data

The data directory contains encrypted, account-scoped state: personal policy, locally reported campaign memory, up to 40 scan-history records per account, resumable provider cursors/hashes for interrupted scans, relationship aggregates represented by HMAC fingerprints, background schedules, the community outbox and signed-feed rollback/cache state. Relationship history is bounded to 20,000 relationship profiles and 100,000 observed-message replay fingerprints per account. It records counts/timestamps/folder categories, not message bodies.

Encryption keys and provider secrets use native credential custody where supported. Some community service keys and public cache material have separate operational custody documented in `.engineering/COMMUNITY_DEPLOYMENT.md`. Encryption protects data at rest; a compromised unlocked user account or endpoint may still access data available to the running application.

Disconnect removes the account session credential reference and its background schedule. Personal policy/history may remain under the stable account key so reconnect can preserve protection. Ordinary uninstall preserves user data. Explicit purge is separately confirmed and restricted to a marked Email Shield data directory. Users or administrators may delete that directory and corresponding Email Shield native-vault entries when permanent local deletion is required, subject to backup retention.

## Community report

`Report Scam to Email Shield` is a separate explicit action. When a community URL is configured, the client may submit:

- a pseudonymous reporter proof derived from an installation-local random HMAC key;
- campaign fingerprint and eligible sender/Reply-To/destination organizational-domain indicators;
- bounded attachment SHA-256 hashes;
- deterministic evidence codes, score, verdict and report time.

It excludes mailbox address/proof, subject, body, contacts, provider message IDs, raw URL paths/query strings, attachment names/content, credentials, OAuth values and app passwords. A pseudonymous proof is linkable across reports from the same installation and is not anonymous against an operator with other identifying network data. The application does not retain IP address or user-agent fields; a production gateway may process them under the operator’s own notice.

Failed submissions may remain in the encrypted local outbox, deduplicated and bounded to 2,000 pending reports, until a later retry or local deletion. The central service retains reporter-attributed campaign state for 90 days; expired reporter contributions are removed from thresholds and published feed state. Operational backups may extend physical recoverability according to the operator’s disclosed backup schedule.

## Analyze Links and operational data

`Analyze Links` is explicit. It sends the selected destination to that destination’s public server through a DNS-validated, address-pinned, bounded fetch without mailbox cookies or provider credentials. Results and URLs are not written to operational telemetry. Its in-memory cache uses process-random HMAC keys and expires on a fixed short lifetime or process exit.

The protected desktop operations view and optional community Prometheus endpoint expose fixed aggregate counters only. They do not accept or emit mailbox identity, reporter/campaign/indicator values, subjects, bodies, destinations, credentials or exception text.

## Optional technical telemetry

PostHog technical telemetry is disabled unless the user or operator explicitly sets `EMAIL_SHIELD_TELEMETRY=1` and provides a project ingestion token at runtime. Email Shield does not include browser autocapture, session replay, form capture or request-context tracking for this integration.

The desktop telemetry boundary may emit only fixed application-start, protected-local-state readiness/failure and local-server-listening events. Properties are restricted in code to the application version, operating-system platform, a fixed component label, a bounded startup-duration value and the fixed failure classification `initialization_error`. A constant anonymous runtime identifier is used; person-profile processing and GeoIP enrichment are disabled in the event payload.

The telemetry boundary rejects unknown event names and unknown property names. It must not receive or send mailbox addresses, sender/recipient identity, subjects, message bodies, URLs, attachment data, provider message IDs, account or device identity, personal-policy contents, credentials, OAuth tokens, app passwords, raw exception messages or stack traces. Telemetry transport failures are non-authoritative and cannot prevent the local application from starting or protecting mail.

No advertising SDK or cross-service behavioral profiling SDK is included. The optional PostHog connection is limited to the technical engineering-health contract above.

## Choices and requests

Users choose whether to connect a provider, enable background protection, Analyze Links, move/report/block/trust/approve mail, submit a scam report, and enable optional technical telemetry. Provider authorization can be revoked at the provider; local accounts can be disconnected; account policies can be exported, reviewed, revoked or reset in the dashboard.

For a public community deployment, access/deletion/objection requests must go to that deployment’s identified operator because this repository does not identify a universal data controller. A reporter proof is pseudonymous and may not be independently attributable without information supplied by the requester. Operators should verify requests without asking for mailbox passwords, OAuth tokens, recovery codes or message bodies.

Material privacy changes must update this notice, the threat model, tests and the versioned data contracts before release.