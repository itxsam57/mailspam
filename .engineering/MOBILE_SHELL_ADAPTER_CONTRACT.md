# Email Shield Mobile Shell Adapter Contract

Status: engineering contract for the shared account/family/mobile foundation.

## Architectural rule

Android, iOS and desktop are shells around the same Email Shield product domain. A native app must not fork scam verdict policy, personal/family/community precedence, entitlement semantics, family seat rules or privacy rules.

Native shells provide platform adapters; shared TypeScript domain services remain the behavior authority until an explicitly versioned portable-core replacement is introduced.

## Identity separation

Four identities are deliberately separate:

1. **Email Shield account** — stable `acct_*` product identity and username.
2. **Device identity** — app-generated asymmetric keypair; device ID is derived from its public key.
3. **Subscription entitlement** — verified Free / Individual / Family plan with source, status, expiry and seat limit.
4. **Family Shield circle** — private membership graph and privacy-reduced threat-sharing scope.

A mailbox provider account is a fifth, independent identity. Connecting Gmail/iCloud/Outlook/Yahoo/IMAP must never make a provider email address the Email Shield account identifier.

## Forbidden device identifiers

Native adapters MUST NOT use IMEI, serial number, advertising ID, Android hardware ID, MAC address, phone number or other cross-app hardware/tracking identifier as Email Shield identity.

The device adapter generates an asymmetric keypair. The private key remains in platform-protected storage and is non-exportable when the platform supports that property. The shared domain receives only:

- key algorithm
- public key SPKI or equivalent portable public representation
- device label
- platform enum
- signatures over bounded authentication challenges

## Required native adapters

### iOS

- Keychain / Secure Enclave device-key adapter
- passkey / AuthenticationServices sign-in-recovery adapter when enabled
- StoreKit 2 purchase-verification transport
- APNs notification adapter
- HTTPS account/family sync adapter
- existing mail-provider adapter or system OAuth bridge

### Android

- Android Keystore device-key adapter
- Credential Manager/passkey sign-in-recovery adapter when enabled
- Google Play Billing purchase-verification transport
- FCM notification adapter
- HTTPS account/family sync adapter
- existing mail-provider adapter or system OAuth bridge

### Desktop

- native credential-vault device key
- loopback protected local API/browser shell
- development entitlement adapter only for acceptance testing
- web billing adapter later for production desktop entitlement

## Subscription contract

The UI never sets `premium`, `family`, `active` or expiry as authoritative client flags.

A purchase adapter submits a store proof and privacy-reduced Email Shield account reference to a trusted verification service. Only a normalized `VerifiedEntitlement` returned by that verifier may update authoritative entitlement state.

Normalized entitlement fields:

- `plan`: free | individual | family
- `status`: active | grace | expired | revoked
- `source`: development | apple | google | web
- `productId`
- `storeAccountReference` (opaque/obfuscated)
- verification timestamp
- expiry / grace expiry
- seat limit

Production clients must reject the `development` source unless the build is explicitly an acceptance/development build.

## Family Shield privacy contract

Cross-device Family Shield may synchronize:

- Email Shield account IDs
- family circle ID
- owner/member role
- seat state
- one-time invite proof/status
- privacy-reduced campaign fingerprint
- reporter/blocker account proof or server-side independent-count equivalent
- family campaign status
- timestamps required for expiry/retention

It MUST NOT synchronize:

- raw email body or HTML
- subject
- sender mailbox address solely for Family Shield matching
- recipient mailbox address
- contacts
- provider-native message ID
- provider OAuth/app-password material
- raw private URLs or URL query strings
- attachment bodies
- arbitrary mailbox history

Family campaign matching uses the same privacy-reduced `campaignFingerprint` primitive already used by community protection.

## Family protection precedence

The native shell must supply the authenticated family snapshot before a scan begins. It is compiled into portable campaign intelligence:

- family warning -> `FAMILY_WARNING_MATCH` -> Review + reversible provider Spam/Junk quarantine after scan enumeration
- family confirmed -> `FAMILY_CONFIRMED_MATCH` -> Confirmed Threat + provider Trash after scan enumeration

Family rules are never represented as `GLOBAL_*` evidence and never create public community consensus by themselves.

Global signed-feed verification still fails closed. A healthy private family snapshot must never make an invalid/unavailable global signed feed appear clean.

## Local personal/report semantics

- Block Sender: local durable rule + current Trash; future exact-sender matches Trash.
- Block Domain: local durable rule + current Trash; shared consumer-mail domains remain protected from broad domain blocking.
- Optional Family Block: sends only the campaign fingerprint to Family Shield; personal sender/domain block itself is not copied to other family members.
- Report Scam: local campaign rule + current Trash + Family Shield campaign report when linked + privacy-reduced public community report.

Local protection commits before family/community/provider side effects and must not be rolled back because an external sync is temporarily unavailable.

## Background parity

Manual scan, resumed scan and scheduled Background Protection MUST receive the same account-scoped family snapshot. A product shell that cannot supply family state must explicitly run without Family Shield; it may not silently reuse another account's family snapshot.

## Navigation contract

Native presentation is free to use platform conventions, but logical destinations remain stable:

- Home
- Scan
- Protection
- Family Shield
- Community
- History / Activity
- Account & Plan
- Mailboxes & Settings

Mobile primary navigation may expose Home / Scan / Family / Activity / More, with the remaining destinations under More.

## Conformance requirements for a new native shell

Before a native app is accepted it must pass:

1. all portable-core conformance vectors for all provider canonical envelopes it supports;
2. account/family portable-domain tests;
3. device-key identity and challenge-signature tests;
4. purchase-verification adapter contract tests using store sandboxes/fixtures;
5. Family Shield isolation tests with at least two unrelated circles;
6. warning quarantine and confirmed Trash tests;
7. privacy tests proving forbidden mailbox fields never enter account/family sync payloads;
8. offline/restart/recovery tests;
9. provider action idempotency and stale-token tests;
10. platform accessibility and lifecycle acceptance.

A mobile shell is therefore an adapter integration into this repository, not a second Email Shield implementation.
