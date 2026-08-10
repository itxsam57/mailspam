# Community Storage-Key Read Integrity

## Root cause

The encrypted community aggregate store already created `community-storage.key` with an atomic `wx` write and required the loaded key to be exactly 32 bytes. However, runtime loading still called path-based `readFileSync(this.keyPath)` before checking that length.

A corrupt or replaced key path could therefore cause an unnecessarily large allocation before rejection. On POSIX, a symbolic link at the key path was also followed by the runtime read.

## Accepted key-read contract

The existing storage-key location, AES-256-GCM format and `wx` creation contract remain unchanged.

When the key is not already cached:

1. the data directory is prepared with the existing private-directory behavior;
2. if the key path does not exist, a 32-byte candidate is generated and written with `mode: 0600` and `flag: wx`;
3. if another initializer wins that atomic create, `EEXIST` remains the accepted contender path and the loser never overwrites the winner;
4. the generated candidate buffer is explicitly zeroed after the create attempt;
5. the key path is opened read-only, with `O_NOFOLLOW` where the platform supports it;
6. `fstat` on that exact descriptor must prove a regular file whose size is exactly `COMMUNITY_STORAGE_KEY_BYTES` before `readFileSync` is called;
7. the key is read from the same descriptor;
8. a defensive post-read length check rejects a file that changed while being read;
9. only a successfully validated 32-byte Buffer is cached.

## Fail-closed behavior

A missing/unsafe open, non-regular file, wrong-size file, POSIX symlink, or changed-size read fails closed. The runtime does not truncate, normalize, regenerate over, or accept such state.

The error is subsequently contained by the existing community public error/readiness boundaries where applicable.

## Security and compatibility boundary

This brick adds no:

- storage migration;
- new key location;
- new key format;
- provider/mailbox permission;
- public community field;
- network request;
- deployment or hardware-backed-custody claim.

This is file-read integrity for the existing local aggregate encryption key. It does not replace the separate desktop native-vault architecture used for provider/policy secrets.

## Live deployment boundary

No live mailbox or public deployment test is required. The behavior is deterministic local filesystem/key-file handling and is fully CI-testable.

GAP-004 remains open for the actual deployed community filesystem/storage, backup/restore, monitoring and signing-rotation acceptance.

## Required regression coverage

Automation must prove at minimum:

- normal atomic key creation still produces a usable 32-byte key and existing database state remains readable;
- wrong-size key files fail closed;
- sparse oversized key files fail before their bytes can be accepted as key material;
- POSIX symbolic links at the key path are refused;
- source-order regression locks `wx` creation, `EEXIST` handling, generated-buffer zeroing, descriptor open/fstat/exact-size validation, then descriptor read;
- existing aggregate-state/recovery/storage-boundary/community reporting regressions remain green;
- strict type/build and the full Windows/macOS/Ubuntu Engineering Gate remain green.
