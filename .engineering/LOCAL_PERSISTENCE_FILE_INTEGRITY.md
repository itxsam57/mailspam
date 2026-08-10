# Local persistence file integrity

## Scope

This contract governs Email Shield local encrypted/security-sensitive file reads and atomic replacements used by personal policy, resumable scan history, relationship history, community aggregate/outbox/reporter/signing/feed-cache and recovery operations.

## Required invariants

1. A local file used as trusted persistence/security input is opened and validated through the same descriptor before its content is allocated or parsed.
2. Where supported on POSIX, reads refuse symlinks with `O_NOFOLLOW`; the opened descriptor must be a regular file.
3. Size limits are proved before allocation, content is read into exactly the validated size, an extra-byte probe rejects hidden growth, and descriptor size is checked again after the read.
4. Raw private local key material requires owner-only POSIX permissions at consumption time. Windows relies on the platform file/vault boundary instead of POSIX mode bits.
5. Plaintext database ceilings and encrypted JSON/Base64 envelope ceilings are separate contracts. A valid maximum-size plaintext database must not become unreadable solely because AES-GCM metadata/Base64 expands its on-disk representation.
6. Generated first-use key candidates are zeroed after creation/contender handling.
7. Atomic replacement failure must preserve the last good destination. Only the uncommitted temporary file may be cleaned up; a generic rename failure must never trigger deletion of the existing database.
8. Protected scan-history/checkpoint persistence failures must be explicit. They may not disappear in an empty catch or be represented to the browser as a durable resumable checkpoint when the final write failed.
9. These rules do not weaken existing AES-GCM authentication, native-vault custody, account isolation, storage schemas, provider-neutral behavior, community privacy, or deployment boundaries.

## Non-goals

This contract does not claim filesystem protection against an already-compromised operating-system account, hardware-backed storage, installer/process signing, production community deployment, or live provider acceptance.
