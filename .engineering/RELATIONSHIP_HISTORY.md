# Email Shield — Local Relationship History Security Contract

Status: Milestone 2 / GAP-011 implementation contract.

## Purpose

Relationship history gives Email Shield durable, account-local context about repeatedly observed senders without creating a plaintext contacts database and without uploading mailbox history. It exists to improve context and detect changes in established patterns. It is not a trust list.

## Stored data

The relationship-history repository may persist only bounded, privacy-reduced aggregate state:

- a per-account HMAC sender fingerprint;
- a per-account HMAC message fingerprint used only for replay/idempotency control;
- bounded HMAC Reply-To fingerprints;
- message count;
- authenticated-message count;
- Safe, Review, High Risk, Confirmed Threat and Unknown counts;
- first/last local observation timestamps;
- last authenticated local observation timestamp;
- normalized folder-category counts.

The same external sender must produce a different stored fingerprint for different Email Shield account identities. The account-specific index key is derived locally from protected key material and the stable `policyAccountKey`.

## Forbidden persisted data

Relationship history must never persist:

- sender or recipient email addresses;
- user contacts/address books;
- subject lines;
- message bodies or text previews;
- raw HTML;
- raw URLs or destination paths/query values;
- raw RFC Message-ID values;
- provider-native message IDs;
- attachment names or content;
- provider credentials or app passwords;
- OAuth access/refresh/ID tokens, authorization codes or PKCE material;
- unsubscribe destinations;
- review/action tokens.

## Encryption and key custody

Persistent relationship history is stored in `relationship-history.enc.json` using AES-256-GCM with format-specific authenticated additional data. Its encryption key is separate from personal-policy and resumable-scan-state keys and is held through the native credential-vault abstraction as `relationship-history-encryption-key-v1` / `local-encryption-key`.

If the native credential service is unavailable on a fresh environment, relationship history is process-memory-only and no plaintext fallback is created. If encrypted relationship history already exists but its protected key cannot be recovered, startup fails closed rather than replacing or resetting the database.

## Trust boundary

Relationship history is context, never authorization or trust.

An established local sender relationship currently requires at least three prior observations, at least two Safe observations, at least two authenticated observations and zero prior Review/High Risk/Confirmed Threat observations. This threshold may become stricter, but must not be weakened without explicit security review and new regression evidence.

Even when history is established:

- it must not mark a message Safe;
- it must not become a sender allowlist;
- it must not override a personal block;
- it must not override signed/global confirmed-threat intelligence;
- it must not cancel strong current-message evidence;
- it must not set canonical `isFirstContact` to false;
- first-contact-specific romance/adult/BEC/other threat rules remain eligible to fire after possible sender compromise.

`ESTABLISHED_LOCAL_SENDER_HISTORY` is therefore informational with zero score contribution.

## Risk-producing historical anomalies

Relationship history may add positive risk evidence when current behavior diverges from a previously stable local pattern. Current protected signals are:

- `RELATIONSHIP_AUTH_DOWNGRADE`: an established sender with prior authenticated history now has an explicit DMARC failure or combined SPF/DKIM failure pattern;
- `RELATIONSHIP_REPLY_TO_CHANGE`: an established sender changes a previously stable, non-empty Reply-To fingerprint;
- `REPEATED_SUSPICIOUS_RELATIONSHIP_HISTORY`: most prior locally observed messages from the sender already required Review or stronger protection.

These are additive risk signals only. They do not independently create provider actions.

## Replay and resumable-scan consistency

Every relationship observation carries a per-account HMAC message fingerprint. Both Worker state and persistent state deduplicate on that fingerprint.

The server commit order for each completed provider page is:

1. merge the page's privacy-reduced relationship observations;
2. persist the encrypted relationship-history database;
3. persist the resumable scan checkpoint/cursor;
4. only then create browser action tokens and emit browser progress.

If relationship persistence fails, the scan stops before its provider cursor advances. If relationship persistence succeeds but scan-checkpoint persistence fails, replaying the same provider page is safe because the relationship message fingerprints are already deduplicated.

Repeated Quick/Full/Spam scans therefore must not inflate relationship counts merely because the same messages are scanned again.

## Worker and browser boundary

The Worker may receive only the selected account's relationship snapshot: account-scoped HMAC index material, aggregate profiles and HMAC replay keys. A retry receives a fresh structured clone of the original snapshot so an unsuccessful pre-progress attempt cannot contaminate the retry.

`relationshipObservations`, the HMAC index key and replay-key set are server/Worker-only. `publicScanProgress` must remove relationship observations alongside provider cursor/checkpoint state before any SSE payload reaches browser JavaScript. Browser source must not depend on these internal fields.

Aggregate current-message relationship flags may appear inside the canonical current-message result because they contain no historical raw identity. Raw historical identities never do.

## Retention limits

Current hard bounds are:

- maximum 20,000 relationship profiles per account;
- maximum 100,000 observed message fingerprints per account;
- maximum 8 Reply-To fingerprints per relationship profile;
- maximum encrypted relationship-history database size 32 MiB.

Relationship profiles are bounded to the most recently observed profiles. The exact message replay index is different: old replay fingerprints are never rotated or evicted merely to admit newer messages, because doing so would allow a later Full scan to count old mailbox messages again. Once the 100,000-message replay index reaches capacity, Email Shield conservatively stops learning new relationship observations for that account until a future reviewed retention design can preserve exact replay safety. Saturation therefore makes history stale rather than corrupting relationship counts or manufacturing trust. Raising, compacting or replacing these limits requires explicit storage/privacy and replay-safety review.

## Regression requirements

The engineering gate must continue proving:

- account-specific HMAC isolation;
- encrypted-at-rest sender/message privacy;
- restart persistence with native-vault key custody;
- fail-closed missing-key behavior;
- memory-only unsupported fresh-platform behavior;
- duplicate message observations count once;
- replay-index saturation freezes new learning instead of evicting old fingerprints and double-counting later scans;
- established history never disables canonical first-contact semantics;
- explicit authentication downgrade and stable Reply-To changes create positive relationship evidence;
- suspicious historical patterns add risk rather than trust;
- high-confidence first-contact adult-campaign detection remains active for established senders;
- relationship observations/HMAC internals never cross the browser progress boundary;
- relationship commit happens before scan-checkpoint advancement.
