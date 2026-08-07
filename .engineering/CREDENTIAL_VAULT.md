# Email Shield — Credential Vault Boundary

## Milestone 2 status

This document defines the first protected-credential brick after the accepted Milestone 1 baseline.

- **2A.1 Local API and Process Isolation:** inherited as complete from the Milestone 1 hardening work and locked by `REG-032` through `REG-034` plus resolved `GAP-007`.
- **Credential vault foundation / Windows backend:** active in this change.
- **Provider credential migration into the vault:** not yet claimed complete.
- **macOS Keychain and Linux Secret Service:** not yet implemented.

## Security invariant

Email Shield must never silently fall back from an operating-system credential vault to plaintext files, browser storage, environment-variable persistence, policy storage, logs, diagnostics or backup/export payloads.

If the native vault is unavailable, credential persistence fails closed.

## Shared contract

The credential-vault layer accepts only:

- an opaque Email Shield credential reference;
- a constrained credential kind;
- the secret value for a write operation.

The operating-system target name is derived from a SHA-256 namespace hash. Mailbox addresses, provider account IDs and secret values are not used as visible target metadata.

Supported credential kinds in the foundation:

- OAuth refresh token;
- OAuth client secret;
- IMAP/app password;
- local encryption key.

## Windows backend

The Windows backend uses the native Windows Credential Manager Generic Credential APIs (`CredWriteW`, `CredReadW`, `CredDeleteW`) through a non-interactive Windows PowerShell bridge.

Security properties:

- the PowerShell executable is resolved from the Windows system directory rather than through a shell command;
- no shell is used;
- the secret is supplied over the child process stdin and never placed in command-line arguments;
- the PowerShell script is passed as an encoded command and contains no runtime secret;
- Windows Credential Manager stores the secret for the signed-in Windows user;
- credential blobs are bounded to the Windows Generic Credential maximum and are never truncated;
- temporary unmanaged write buffers and managed byte arrays are zeroed before release where the bridge controls them;
- bridge stderr and raw lower-layer failures are not surfaced through public vault errors;
- delete treats an already-missing credential as a successful idempotent cleanup.

## Claims deliberately not made

Windows Credential Manager is user-bound, but Email Shield does **not** claim universal hardware-backed storage or cryptographic application binding. Those capabilities differ by machine and deployment model.

The current foundation also does not claim that existing live account credentials have already been migrated. Existing Milestone 1 account behavior remains unchanged until the account lifecycle is converted to stable credential references in a separately tested change.

## Platform capability state

| Platform | Backend | Current state |
|---|---|---|
| Windows | Windows Credential Manager | Implemented foundation and Windows-only round-trip test |
| macOS | Keychain | Not implemented; fails closed |
| Linux | Secret Service / keyring | Not implemented; fails closed |
| iOS | Keychain design | Future platform work |
| Android | Keystore design | Future platform work |

## Required next migration rule

Before Gmail or Outlook guided OAuth stores a long-lived refresh token, account configuration must stop carrying the refresh token as persistent account identity. OAuth token rotation must not create a new policy identity or orphan existing personal rules.

The later migration must therefore introduce a stable provider/account identity plus an opaque credential reference. Provider adapters may receive a secret only in process memory immediately before the provider operation; browser payloads and policy persistence must never receive the secret.
