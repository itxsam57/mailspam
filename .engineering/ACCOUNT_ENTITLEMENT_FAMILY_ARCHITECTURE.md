# Email Shield Account, Entitlement and Family Shield Architecture

## Purpose

This document defines the canonical product model for Email Shield identity, subscriptions, devices and private family threat sharing. It supplements the portable scanner contract; it does not replace provider adapters or the privacy-first local mail-processing architecture.

## Product identities are separate

- **Email Shield account**: username + stable product account ID.
- **Device**: app-generated cryptographic identity derived from a device public key.
- **Entitlement**: verified plan record independent of device and mailbox.
- **Family Shield circle**: private membership/protection scope.
- **Mailbox account**: provider account identity used only for mailbox operations/personal policy.

No hardware identifier is an account identity.

## Desktop acceptance implementation

Desktop uses:

- Ed25519 device identity stored in native credential vault when available;
- AES-256-GCM encrypted account/family state bound to the managed data directory;
- protected loopback API for account/family UI;
- development-only entitlement switching when `EMAIL_SHIELD_ENABLE_DEVELOPMENT_ENTITLEMENTS=1`;
- mailbox-to-Email-Shield-profile linking by the existing privacy-reduced mailbox policy key.

Development entitlement switching exists only for local acceptance. Production subscriptions require Apple, Google or web purchase verification adapters.

## Account lifecycle

### Create

1. Normalize/validate username.
2. Read the current app-generated device public identity.
3. Derive `dev_*` ID from the public key.
4. Create `acct_*` ID.
5. Generate high-entropy recovery code.
6. Persist only the recovery-code hash.
7. Register the device and default Free entitlement.
8. Display the recovery code once.

### Sign in on an already trusted device

Username resolves the account; the current cryptographic device ID must already be registered and non-revoked. The local loopback app additionally relies on the existing CSRF/origin/session protections. Remote services must require a signed challenge/passkey assertion rather than trusting username + device ID text.

### Recovery

A valid recovery code can register/revive a device. Successful recovery rotates the recovery code immediately. The previous code becomes invalid.

### Device revocation

Devices can be revoked, but the last active trusted device cannot be revoked without first establishing another recovery/trusted-device path.

## Entitlement model

Plans:

- Free: 1 account seat
- Individual: 1 account seat
- Family: default 6 seats, bounded by service policy

Statuses:

- active
- grace
- expired
- revoked

Sources:

- development (acceptance only)
- apple
- google
- web

The browser/app UI never directly assigns a production entitlement. Store/web verifiers return the normalized entitlement after authoritative receipt/subscription validation.

Entitlement state contains no email content and should be safe to centralize in the future account service.

## Family Shield membership

An active Family entitlement owner can create one Shield Circle. The circle contains:

- one owner
- members up to entitlement seat limit
- one-time expiring invite proofs
- Strict Family Protection setting
- privacy-reduced family campaign records

Member mailboxes remain private and independent.

## Family threat sharing

### Personal report

Report Scam always protects the reporting mailbox locally first and moves the current message to Trash. If that mailbox is linked to a Family Shield profile, only its privacy-reduced campaign fingerprint enters the private family circle.

### Personal block

Block Sender/Domain remains personal by default. The user can explicitly choose to share the associated campaign with Family Shield. The raw blocked sender/domain is not copied into the family campaign record.

### Family status

Normal mode:

- one independent family report/block -> warning
- two independent family reports -> confirmed
- two independent family blockers -> confirmed
- owner explicitly shares a family block -> confirmed

Strict mode:

- one family Report Scam -> confirmed

These thresholds are intentionally separate from the public community aggregation thresholds.

## Family disposition

- Family warning -> `FAMILY_WARNING_MATCH` -> Review -> after mailbox enumeration, move matching Inbox mail to provider Spam/Junk.
- Family confirmed -> `FAMILY_CONFIRMED_MATCH` -> Confirmed Threat -> after mailbox enumeration, move matching mail to Trash.

Provider mutation remains bounded and happens after enumeration so offset/UID-based IMAP scans do not skip messages.

## Privacy boundaries

Family records may contain only privacy-reduced identifiers, membership metadata and required timestamps. They must not contain raw body, HTML, subject, mailbox address, provider message ID, credentials, contacts, raw URL/query strings, attachment bodies or full mailbox history.

The account/family encrypted desktop database is separate from scan result presentation memory and provider credential storage.

## Failure boundaries

Local personal protection commits before family/community/provider external effects. Family or community unavailability must not undo local Report Scam/Block decisions.

An invalid global signed feed remains fail-closed even when Family Shield is available.

Family state is account-scoped; concurrent scans for unrelated families must use per-account snapshots and never mutate a shared singleton feed.

## Future shared service

The native mobile contract requires a trusted account/family synchronization service. Its responsibilities are limited to:

- account/device public identity and challenge authentication;
- entitlement verification/state;
- family membership/invites;
- privacy-reduced family campaign records;
- signed/authenticated family snapshots;
- device notification routing.

It must never become a centralized email-content store.

## Desktop acceptance gates

Before this feature can move to main:

- account/family domain tests pass;
- encrypted persistence tests pass;
- local protected API tests pass;
- family warning/confirmed scanner and provider-action tests pass;
- manual and scheduled scan parity passes;
- web source/privacy/navigation checks pass;
- old provider/OAuth/policy/community tests remain green;
- all three operating-system Engineering Gate jobs and summary pass;
- exact tested SHA is promoted to main without regeneration;
- fresh main gate passes.
