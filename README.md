# Email Shield — Milestone 1

Local-first email scam detection engine. Runs entirely on your machine; no
message content is sent to Email Shield servers.

## Run it

```bash
npm install
npm run verify
npm run dev
```

Open `http://127.0.0.1:4173`. Fixture mode loads the synthetic scam corpus
without credentials. Live mode connects directly from your computer to the
selected mail provider.

## Connecting a real mailbox

- **iCloud / Yahoo**: email address plus an app-specific password.
- **Generic IMAP**: host, port, username and app password.
- **Gmail / Outlook**: the adapters support OAuth credentials, but the guided
  browser OAuth onboarding flow is not exposed in the dashboard yet.

The iCloud IMAP path has been exercised against a real mailbox on Windows,
including bounded MIME text retrieval, scan cancellation, one-message Trash,
Block sender, Block domain and repeated rescans.

## Detection architecture: not trained to one mailbox

The local engine does not contain a list of the developer's subscriptions or a
hardcoded decision table for individual brands. It judges every sender using
provider-neutral structure:

- SPF, DKIM and DMARC results
- organizational-domain and Reply-To alignment
- shared personal mailbox versus organizational sender identity
- relay alias provenance and domains encoded in relay addresses
- List-ID and List-Unsubscribe identity signals
- literal displayed URL versus actual destination
- raw IP, punycode, shortening and unusual-port link structure
- generic intent combinations such as credential pressure, callback invoices,
  payment diversion, parcel fees, romance lures, job overpayment and crypto yield
- local relationship history, personal rules and signed threat intelligence

A company the source code has never seen can still establish an authenticated
organizational identity. Well-known names that cannot be derived from headers
may be supplied as **signed identity feed data** containing aliases and allowed
domains. Adding or correcting an identity entry does not require an application
code release. If the feed fails verification or freshness checks, it is treated
as unavailable rather than clean.

Shared consumer domains such as Gmail, Outlook, Yahoo and iCloud authenticate
the mailbox provider, not the organization claimed in a display name. They are
therefore never accepted as business identity by themselves.

## Local policy persistence

Personal rules survive application restarts and mailbox reconnection. Email
Shield stores only these rule lists:

- blocked sender addresses
- blocked sender domains
- trusted sender addresses
- approved exceptions

The rules are stored in an AES-256-GCM encrypted file under:

```text
~/.email-shield/personal-policies.enc.json
```

A random 32-byte local key is stored separately at:

```text
~/.email-shield/personal-policy.key
```

On Windows, `~` means the current Windows user profile directory. The storage
location can be overridden with `EMAIL_SHIELD_DATA_DIR`.

Mailbox passwords, app passwords, email bodies, subjects, scan results,
provider message IDs and attachment content are not written to this policy
store. The mailbox lookup identity is SHA-256 hashed before it is used as a
record key.

The local key protects against accidental plaintext disclosure. It is not a
replacement for full-disk encryption or operating-system account security.

## What's built

- Shared canonical MIME normalization across all provider adapters
- Quick, Full Mailbox and Spam/Junk scans
- Killable scan Workers and one safe retry for early transient IMAP timeouts
- Stage-specific IMAP timeout diagnostics
- Selective bounded `text/plain` / `text/html` retrieval without attachment bodies
- Organization-neutral sender identity and link analysis
- Updateable signed identity/threat-feed interfaces
- Account-scoped persistent Block sender and Block domain rules
- Reversible provider Trash moves with exact-one-message verification
- RFC 8058, normal web-link and mail-based unsubscribe workflows
- Separate privacy-reduced Safe and diagnostic audits
- Developer Testing Suite and synthetic multi-provider scam corpus

## Known limitations before production Milestone 1 completion

- Gmail and Outlook still need guided OAuth onboarding and real-account validation.
- The encrypted policy key is local-file protected rather than stored in the OS keychain.
- The production signed identity-feed publisher, rotation and rollback service is not yet deployed.
- Hardened destination analysis still needs controlled real-URL testing.
- QR decoding remains behind an injectable interface without a production decoder.
- API session authentication and CSRF protection are not implemented yet; the server
  therefore binds to localhost by default.
- Community reporting aggregation remains Milestone 2 scope.
