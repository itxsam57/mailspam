# Email Shield — Personal-Policy Encryption Key Custody

## Scope

Email Shield stores personal policy state (blocked senders/domains, trusted senders, exact Safe exceptions, unsubscribe history and locally reported campaigns) in `personal-policies.enc.json` using AES-256-GCM.

Before this Milestone 2 package, the 32-byte AES key was stored as a raw local file:

`~/.email-shield/personal-policy.key`

That file-backed key is no longer created by the current implementation.

## Windows protected custody

On Windows, the policy encryption key now uses the shared Email Shield credential-vault contract and Windows Credential Manager.

The credential reference is:

- kind: `local-encryption-key`
- internal ID: `personal-policy-encryption-key-v1`

The visible Windows Credential Manager target is still derived through the existing opaque SHA-256 target-name function. The raw policy path, mailbox identity and key value are not placed in the target metadata.

The key is resolved once during desktop-process startup. After initialization, the repository keeps only its in-process 32-byte key copy and policy reads/writes remain synchronous AES-256-GCM operations.

Microsoft's current Windows security guidance recommends Credential Manager (`CredWrite` / `CredRead`) for locally persisted credentials and other secrets. Email Shield reuses the already-reviewed Windows vault backend instead of creating a second native bridge.

## Existing installation migration

When both `personal-policies.enc.json` and legacy `personal-policy.key` exist on Windows, startup performs these steps in order:

1. read the existing 32-byte legacy key;
2. instantiate the AES-GCM repository with that key;
3. fully parse and authenticate the existing encrypted policy database;
4. write the key to Windows Credential Manager through the `local-encryption-key` reference;
5. read the protected value back from Credential Manager;
6. decode and constant-time compare the protected value with the legacy key;
7. only after all checks pass, delete `personal-policy.key`;
8. continue using the same encrypted database without re-keying or resetting policy state.

The database ciphertext format and AAD remain unchanged, so successful migration does not rewrite or discard policy data merely to move key custody.

## Failure semantics

Migration is fail-closed.

Email Shield does **not** delete the legacy key file when:

- the legacy key is not exactly 32 bytes;
- the existing encrypted database cannot be authenticated/decrypted with it;
- Credential Manager write fails;
- protected read-back fails;
- protected read-back is not a valid 32-byte key;
- protected read-back differs from the legacy key;
- the legacy key file cannot be deleted after successful protected custody.

If an existing protected key and an existing legacy key disagree, startup fails rather than choosing one and potentially making recoverable policy data inaccessible.

If an encrypted policy database exists but neither a protected nor legacy key can be recovered, startup fails visibly. Email Shield must not silently create a new key and present an empty policy database.

## Fresh Windows installation

If no encrypted database and no legacy key exist:

1. Email Shield generates a cryptographically random 32-byte key;
2. writes it directly to Windows Credential Manager;
3. reads it back and verifies equality;
4. constructs the encrypted policy repository;
5. never creates `personal-policy.key`.

## Unsupported native vault platforms

macOS Keychain and Linux Secret Service are still open Milestone 2 work.

Until those backends exist:

- an already-existing legacy encrypted policy database/key pair may continue to operate so an upgrade does not destroy working state;
- the legacy key is not automatically deleted because there is no protected replacement backend yet;
- a fresh unsupported-platform installation with no legacy policy data uses process-memory-only personal policy state;
- Email Shield does not create a new plaintext `personal-policy.key` fallback;
- an encrypted database without any readable key fails closed rather than resetting itself.

This compatibility boundary is temporary and does not close macOS/Linux portions of GAP-003.

## Startup boundary

The production desktop entry point resolves/migrates policy-key custody before the local server begins listening.

Direct unit/server construction may use an isolated in-memory policy repository. The deferred global repository refuses to switch to persistent storage after temporary in-memory state has already been used, preventing a process from falsely treating earlier non-durable mutations as persisted.

## Automated protection

The following regressions protect this package:

- encrypted policies contain no plaintext policy values;
- encrypted repository creation no longer emits `personal-policy.key`;
- legacy Windows database/key migration preserves policy contents;
- vault write failure preserves the old recoverable key/database;
- vault read-back mismatch preserves the old key;
- conflicting protected and legacy keys fail closed;
- fresh Windows policy persistence creates only protected key custody;
- fresh unsupported platforms are memory-only and create no raw key file;
- existing unsupported-platform legacy data remains readable;
- encrypted data with no recoverable key fails closed;
- Windows CI performs a real Credential Manager legacy-key migration/read-back and removes the CI-only credential afterward.

This package is tracked as **REG-046 / A-36**. It closes the Windows local-policy encryption-key portion of GAP-003 only.