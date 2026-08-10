# Community Recovery and Signing-Key Rotation

## Purpose

The public community service stores two classes of authoritative security state: the encrypted aggregate-report store and the Ed25519 identity used to sign distributed threat feeds. Production deployment must be recoverable without copying raw secrets casually, and signing-key replacement must not create a client trust outage.

This contract defines the code-level disaster-recovery and rotation tooling. It does not claim that a production restore or key-rotation ceremony has been executed; those remain live deployment acceptance under GAP-004.

## Portable encrypted backup

The operator command creates one authenticated encrypted backup envelope containing only authoritative recovery state:

- `community-storage.key` and `community-reports.enc.json` together when aggregate state exists;
- the current Ed25519 signing private/public pair, including externally configured signing keys when explicitly supplied to the operation.

Derived `community-feed-cache.json` data is intentionally excluded because it can be regenerated from authoritative state.

The portable bundle uses:

- AES-256-GCM authenticated encryption;
- scrypt key derivation with fixed reviewed parameters;
- versioned associated data;
- a minimum 16-byte passphrase;
- a 192 MiB decoded authoritative-source ceiling;
- a 384 MiB encrypted backup-file ceiling;
- canonical per-file SHA-256 integrity metadata inside the authenticated payload;
- strict known file names and file-mode metadata.

The passphrase itself must never be accepted in process argv. CLI use requires `EMAIL_SHIELD_COMMUNITY_BACKUP_PASSPHRASE_FILE`.

On POSIX systems the passphrase file must be a non-symlink regular file whose same opened file descriptor shows no group/other permission bits. Secret/signing/aggregate source files are opened with descriptor-bound size checks and POSIX no-follow semantics so the exact bytes read are the bytes constrained by the resource boundary.

Portable backup is deliberately bounded. If production aggregate storage outgrows this envelope, operators must use a deployment-specific volume/database snapshot mechanism rather than silently raising in-process memory limits.

## Restore contract

Restore is never in-place.

A restore must:

1. require a target path that does not exist;
2. authenticate and decrypt the bundle before trusting its contents;
3. reject unknown/duplicate files, invalid canonical base64, invalid hashes, incomplete aggregate pairs, incomplete signing pairs and resource-limit violations;
4. write recovered material into a sibling staging directory with controlled file modes;
5. instantiate the real `CommunityFeedSigner` against the staged signing pair;
6. instantiate/read the real encrypted aggregate store when aggregate state exists;
7. only after successful validation atomically rename the staged directory into the requested target path;
8. delete staging data on any failure;
9. never overwrite an existing target or silently reset corrupt encrypted state.

Wrong passphrases and ciphertext tampering must fail authentication without creating the final target.

## Signing-key rotation preparation

Key rotation is intentionally two-phase. Code prepares a next-key package but does not silently activate it.

Preparation:

- validates the current Ed25519 signing identity;
- generates a distinct next Ed25519 key pair;
- writes the next private key only to a protected local package file;
- emits a public manifest containing current/next public keys and key IDs but no private key;
- self-verifies the next private/public pair and manifest before atomically exposing the package;
- leaves the current production signer unchanged.

The required live rollout sequence is:

1. deploy overlap trust so clients accept both current and next public keys;
2. verify a current-key-signed feed is still accepted;
3. activate the next signing private/public pair through the real production secret/config system;
4. verify a next-key-signed feed is accepted by production clients;
5. only after the overlap period and relevant feed lifetime retire the old public-key trust.

The generated next private-key package is temporary sensitive material. It must be transferred into the production secret manager/configuration channel and securely removed according to the deployment runbook after successful activation.

## CLI boundary

`server` exposes `ops:community` with:

- `backup <data-dir> <backup-file>`
- `restore <backup-file> <new-data-dir>`
- `prepare-rotation <data-dir> <new-package-dir>`

The CLI may print paths, timestamps and public key IDs. It must never print the backup passphrase or private-key contents.

## Automated acceptance

Automation must prove at minimum:

- a real aggregate report and signing identity survive encrypted backup/restore;
- the encrypted backup does not expose private-key or report-evidence plaintext;
- wrong passphrase and tampering fail closed;
- incomplete aggregate state refuses backup;
- existing restore targets refuse overwrite;
- externally configured signing identity is recoverable;
- CRLF-terminated secret files are handled without changing the passphrase;
- POSIX group/world-readable passphrase files are rejected;
- POSIX symlinked passphrase files are rejected;
- weak passphrases are rejected;
- rotation packages self-verify and contain a distinct next key;
- rotation preparation leaves the active signer unchanged;
- the public manifest contains no private-key material;
- existing output paths refuse overwrite;
- configured current signing keys can prepare rotation without being copied into the source directory;
- strict type/build and the full Windows/macOS/Ubuntu Engineering Gate remain green.

## Live acceptance still required

This tooling does not close GAP-004. After the community service is deployed, the owner/operator must perform:

### Recovery drill

- create controlled report state on the deployed service;
- create an encrypted backup using the production secret-handling path;
- restore into a fresh production-equivalent data location;
- start the service on restored state;
- confirm the same signing key ID, aggregate counts and valid signed feed;
- confirm client verification, health/readiness and monitoring after cutover.

### Signing-key rotation ceremony

- prepare the next-key package;
- publish old+new trust overlap through the real client/config distribution path;
- verify old-key feed acceptance;
- activate the next signing key through the production secret manager/runtime;
- verify next-key feed acceptance;
- retire old trust only after the required overlap window;
- verify the old key is rejected and the new key remains accepted.

DNS/TLS, gateway configuration, monitoring, deployment backup scheduling and volumetric/reputation controls remain separate live production concerns under GAP-004/GAP-008.
