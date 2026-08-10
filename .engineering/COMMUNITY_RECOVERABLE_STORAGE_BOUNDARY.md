# Community Recoverable Storage Boundary

## Root cause

Email Shield already had a bounded portable disaster-recovery format. The recovery tooling accepted at most 192 MiB of authoritative community source material, but the live encrypted aggregate store had no corresponding persistence/read ceiling.

That mismatch meant a correctly operating production service could continue growing `community-reports.enc.json` until the built-in backup command was guaranteed to reject the authoritative state. Runtime reads also called `readFileSync` on the aggregate database before any file-size check, allowing an unexpectedly oversized file to allocate memory before failing.

## One recovery-compatible size contract

The shared community resource contract now defines:

- authoritative recovery source set: 192 MiB;
- each signing-key representation: at most 64 KiB;
- community storage encryption key: 32 bytes;
- aggregate encrypted database ceiling: the 192 MiB source budget minus the reserved 32-byte storage key and two 64 KiB signing-key budgets.

The existing backup export aliases the shared 192 MiB constant instead of defining an independent value.

Configured signing PEMs are checked against the same 64 KiB/key ceiling before recovery processing, so configured and file-managed signing identities use the same recoverability budget.

This is not a new campaign/business quota. It makes live persistence respect the recovery capability already accepted by the project.

## Bounded aggregate reads

When the aggregate database exists, the runtime store:

1. opens the database read-only;
2. uses `O_NOFOLLOW` on platforms where it is supported;
3. checks the exact opened descriptor is a regular file;
4. checks descriptor size against the aggregate database ceiling before `readFileSync`;
5. reads from that same descriptor;
6. defensively verifies the resulting byte count did not cross the ceiling while being read;
7. only then parses/decrypts/validates the database.

An oversized aggregate file therefore fails before the database content or storage key is loaded for that operation. It is preserved for diagnosis and is not truncated or normalized.

## Fail-before-persist writes

Before encrypting a modified in-memory aggregate database, the writer serializes the version-1 plaintext and calculates the exact final encrypted-envelope byte length.

AES-GCM ciphertext length equals plaintext byte length and Base64 length is deterministic, while the version/algorithm/IV/auth-tag JSON overhead is fixed for this format. If the predicted final file would exceed the aggregate database ceiling, the writer throws the existing capacity error before AES encryption, Base64 creation, temporary-file creation or replacement of the previous database.

After encryption, the final serialized envelope is checked against the same ceiling again before the temporary file is written. Atomic replacement behavior remains unchanged for accepted writes.

A report that would cross the recoverability boundary is therefore not durably accepted and the previous valid database remains authoritative.

## Security and compatibility boundary

This brick adds no:

- new plaintext persistence;
- storage migration;
- provider/mailbox permission;
- public report field;
- network request;
- lower campaign-count quota;
- deployment/gateway claim.

The existing `MAX_CAMPAIGNS` limit and all aggregation semantics remain unchanged.

This contract is specifically about the encrypted aggregate database and recovery-source budget. It does not claim a new runtime implementation for storage-key file reads beyond the existing exact 32-byte validation.

## Live deployment boundary

No live mailbox or public deployment test is required for this deterministic storage/recovery consistency brick.

GAP-004 remains open because a real deployed backup/restore drill still must prove actual filesystem/storage capacity, secret distribution, backup transfer, restore cutover and operational monitoring.

## Required regression coverage

Automation must prove at minimum:

- recovery and runtime authoritative-source constants cannot drift apart;
- aggregate database ceiling reserves the storage key plus two bounded signing keys inside the recovery source budget;
- an oversized sparse database fails before aggregate content/storage-key loading;
- ordinary production aggregate state remains below the database ceiling and can be exported by the recovery tooling;
- configured signing PEMs above the reserved key budget are rejected;
- the writer performs predicted envelope-size rejection before encryption and final serialized-size rejection before temporary-file persistence;
- existing recovery, aggregate-state, public-error, readiness and community reporting regressions remain green;
- strict type/build and the full Windows/macOS/Ubuntu Engineering Gate remain green.
