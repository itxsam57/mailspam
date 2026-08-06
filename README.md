# Email Shield — Local Detection and Shared Community Protection

Email Shield is a local-first, deterministic email scam-detection layer. Mailbox scans and message content remain on the user's machine. When the user explicitly selects **Report Scam to Email Shield**, the client may send a privacy-reduced indicator report to a configured community service; it never uploads the message body, subject, mailbox address, contacts, credentials, provider message ID, raw private URL path/query values, attachment names, or attachment content.

## Run it

```bash
npm install
npm run verify
npm run dev
```

Open `http://127.0.0.1:4173`. Fixture mode loads the synthetic scam corpus without credentials. Live mode connects directly from the user's computer to the selected provider.

## Providers

One canonical envelope, detection pipeline, review workflow and community-report contract are shared by:

- Gmail
- iCloud
- Outlook
- Yahoo
- Generic IMAP

Current live onboarding:

- **iCloud / Yahoo:** email address plus app-specific password.
- **Generic IMAP:** host, port, username and app password.
- **Gmail / Outlook:** adapters support OAuth credentials, but guided browser OAuth onboarding is not exposed yet.

The iCloud path has been exercised against a real mailbox on Windows for bounded MIME retrieval, scan cancellation, exact Trash movement, sender/domain blocks, persistence and repeated rescans.

## Detection architecture

The detector is provider-neutral and does not contain a hardcoded list of the developer's subscriptions. It evaluates:

- SPF, DKIM, DMARC and ARC results;
- organizational-domain, Reply-To and relay alignment;
- shared consumer mailbox versus organizational identity;
- List-ID and unsubscribe identity signals;
- displayed URL versus actual destination;
- shortened, IP, punycode and unusual-port URLs;
- credential, callback, BEC, delivery, job, crypto, romance, reward and adult-site lure combinations;
- local relationship and personal policy signals;
- verified signed community/identity intelligence.

A failed, expired, tampered or untrusted signed feed is treated as unavailable, never as evidence that a message is clean.

## Report Scam versus provider Spam/Junk

These are deliberately separate actions.

### Report Scam to Email Shield

- Immediately stores the campaign fingerprint in the selected mailbox's encrypted local policy.
- Matching future campaign messages become local Confirmed Threat, even if the scam rotates addresses while preserving the campaign structure.
- Optionally blocks the exact sender only after a separate explicit choice.
- Submits or queues a privacy-reduced community report.
- Does not move or delete the message.

### Move to Spam/Junk

- Moves exactly one selected message through the provider-native Spam/Junk mechanism.
- Requires exact provider confirmation.
- Does not create shared Email Shield intelligence.
- Does not automatically block the sender.

## Privacy-reduced community reports

Eligible reports contain only:

- a pseudonymous reporter proof derived with an installation-local random HMAC key;
- campaign fingerprint;
- eligible direct sender address;
- unrelated Reply-To organizational domain;
- unrelated destination organizational domains;
- attachment SHA-256 hashes;
- deterministic evidence codes, bounded score and verdict.

They exclude:

- mailbox address or account proof;
- message subject or body;
- contacts;
- OAuth tokens, passwords and app passwords;
- provider message IDs;
- raw URL paths, query strings and fragments;
- attachment names or contents.

Generic no-reply/reporting addresses used by shared delivery platforms are not published as exact malicious senders. Email Shield uses the campaign, Reply-To, destination and attachment indicators instead, avoiding global blocks of legitimate carriers.

## Community aggregation rules

- One pseudonymous reporter counts once per campaign.
- One or two reports remain private candidates and are not published.
- Three independent reports plus the warning evidence threshold create a signed warning.
- Five independent reports, at least three strong reports and the confirmed evidence threshold create a confirmed campaign.
- Every confirmed indicator must itself be supported by all five required reporters.
- Three human reports can create a warning even when the old detector called the messages Safe.
- Evidence-free human reports cannot create Confirmed Threat status by themselves.
- Per-reporter rate limits, report-size limits, timestamp windows and bounded storage apply.

Failed remote submissions are saved in an encrypted bounded outbox and retried during later community-feed refreshes. Immediate local protection does not depend on network availability.

## Signed feed

The central service publishes canonical Ed25519-signed documents containing warning or confirmed indicators for:

- exact sender address;
- Reply-To organizational domain;
- destination organizational domain;
- attachment hash;
- campaign fingerprint.

Feeds include key ID, generation time and expiry. Clients use only documents that pass public-key trust, signature and freshness checks. A valid cached feed may be used only until it expires.

## Running a self-hosted community service

The same repository can run the aggregation node:

```text
EMAIL_SHIELD_COMMUNITY_SERVER=1
EMAIL_SHIELD_DATA_DIR=/secure/persistent/email-shield
HOST=127.0.0.1
PORT=4173
```

Clients connect with:

```text
EMAIL_SHIELD_COMMUNITY_URL=https://community.example.com
EMAIL_SHIELD_COMMUNITY_PUBLIC_KEYS=["-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"]
```

Remote URLs require HTTPS except loopback development. Report ingestion, signed-feed serving and public-key metadata are disabled on normal desktop clients unless server mode is explicitly enabled.

Production deployment additionally requires a reverse proxy/API gateway, TLS, edge rate limiting and abuse controls, monitoring, backups and protected key rotation. See `.engineering/COMMUNITY_DEPLOYMENT.md`.

## Encrypted local storage

The default location is:

```text
~/.email-shield/
```

It can be overridden with `EMAIL_SHIELD_DATA_DIR`.

The directory may contain:

- encrypted personal policies and locally reported campaigns;
- encrypted community retry outbox;
- encrypted central aggregate store when server mode is enabled;
- local reporter HMAC key;
- Ed25519 signing key pair for embedded/server mode;
- signed feed cache.

The local key files protect against accidental plaintext disclosure. They do not replace full-disk encryption, operating-system account security or production secret management.

## What's built

- Canonical MIME normalization across all provider adapters
- Quick, Full Mailbox and Spam/Junk scans
- Killable scan Workers and bounded early retry
- Stage-specific IMAP timeouts
- Bounded readable MIME retrieval without attachment-body downloads
- Organization-neutral detection and signed intelligence consumption
- Persistent account-scoped blocks, trust, exact-message approvals and campaign memory
- Exact-message Trash and provider Spam/Junk actions
- RFC 8058, web-link and mailto unsubscribe workflows
- Privacy-reduced Safe and diagnostic audits
- Privacy-reduced Report Scam client
- Independent reporter deduplication and evidence thresholds
- Encrypted community aggregate store and offline outbox
- Ed25519 feed signing, verification and expiry
- Self-hostable community ingestion/feed/public-key APIs
- Developer test suite, five-provider fixture parity and automated Windows/Ubuntu engineering gate

## Known limitations before public production operation

- Guided Gmail and Outlook OAuth onboarding is not exposed.
- Local encryption keys are file protected rather than OS-keychain backed.
- A public community deployment still needs DNS/TLS, an API gateway, volumetric abuse controls, monitoring, backups and an executed signing-key rotation process.
- Hardened destination analysis needs controlled real-URL validation.
- Production QR decoding remains behind an injectable interface.
- The desktop dashboard API has no session authentication/CSRF layer and must remain localhost-only.
- Full policy-management/unblock/revoke UI and persisted resumable scan cursors remain incomplete.

Run `npm run verify` before browser acceptance. The generated owner-only checklist is written to `artifacts/engineering/MANUAL_TEST_HANDOFF.md`.