# Email Shield — Credential Vault Boundary

## Milestone 2 status

This document defines the protected-credential work built on the accepted Milestone 1 baseline.

- **2A.1 Local API and Process Isolation:** inherited as complete from the Milestone 1 hardening work and locked by `REG-032` through `REG-034` plus resolved `GAP-007`.
- **Credential vault foundation / Windows backend:** implemented and proven by a real Windows Credential Manager round trip.
- **Windows app-password session migration:** implemented for iCloud, Yahoo and generic IMAP account sessions.
- **Gmail/Outlook OAuth credential migration:** not yet complete; OAuth secrets remain memory-only until guided OAuth establishes stable account identity independent of token rotation.
- **Local policy-encryption key migration:** not yet complete; its synchronous repository lifecycle requires a deliberate migration rather than a blocking/deasync bridge.
- **macOS Keychain and Linux Secret Service:** not yet implemented.

## Security invariant

Email Shield must never silently fall back from an operating-system credential vault to plaintext files, browser storage, environment-variable persistence, policy storage, logs, diagnostics or backup/export payloads.

If a native vault advertises availability and a protected write fails, account session creation fails. On platforms where a native persistent backend has not yet been implemented, credentials may remain **memory-only for the current process**, but must not be persisted through an insecure substitute.

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

## App-password account-session lifecycle

For iCloud, Yahoo and generic IMAP on Windows:

1. The submitted app password is used transiently to validate the provider connection and folder discovery.
2. After provider validation succeeds, Email Shield derives a deterministic opaque credential reference from stable non-secret account identity:
   - iCloud/Yahoo: provider + normalized mailbox user;
   - generic IMAP: normalized host + port + normalized mailbox user.
3. The app password is written to Windows Credential Manager.
4. The long-lived Email Shield account session stores only the secret handle/reference, not the raw app password.
5. Scans and explicit provider actions resolve the handle only when the provider adapter connects.
6. Windows scan Worker payloads carry the vault handle rather than the raw app password.
7. The short-lived runtime provider adapter is discarded on disconnect.

The deterministic reference is intentionally independent of the password value. Rotating an app password therefore does not create a new personal-policy identity or orphan existing user rules.

### Shared-reference ownership

Multiple active sessions for the same mailbox can legitimately share one deterministic credential reference. Email Shield reference-counts that ownership and serializes credential lifecycle mutations so reconnect and remove operations cannot race.

- Removing one of several same-account sessions does **not** delete the shared native credential.
- The final same-account session removal deletes the native credential before the account is reported removed.
- If native deletion fails, the session remains present/retryable rather than falsely claiming cleanup success.
- A reconnect and old-session removal cannot interleave in a way that deletes the credential underneath the new session.

## Unsupported-platform boundary

Until their native backends exist, macOS and Linux do not persist provider secrets through a substitute file or environment store. Existing current-process flows may use a memory-only secret handle. Removing the session clears that memory handle.

This is a deliberate compatibility boundary, not a claim that Keychain or Secret Service support is complete.

## Claims deliberately not made

Windows Credential Manager is user-bound, but Email Shield does **not** claim universal hardware-backed storage or cryptographic application binding. Those capabilities differ by machine and deployment model.

This work also does **not** claim that every credential class has been migrated. Gmail/Outlook OAuth credentials and the local policy-encryption key remain open work, and macOS/Linux native stores remain absent.

## Platform capability state

| Platform | Backend | Current state |
|---|---|---|
| Windows | Windows Credential Manager | Vault foundation proven; iCloud/Yahoo/generic IMAP app-password sessions migrated |
| macOS | Keychain | Not implemented; persistent secret storage unavailable, current-process memory-only behavior only |
| Linux | Secret Service / keyring | Not implemented; persistent secret storage unavailable, current-process memory-only behavior only |
| iOS | Keychain design | Future platform work |
| Android | Keystore design | Future platform work |

## Required OAuth migration rule

Before Gmail or Outlook guided OAuth stores a long-lived refresh token, account configuration must stop using the refresh token as persistent policy identity. OAuth token rotation must not create a new policy identity or orphan existing personal rules.

The OAuth migration must therefore introduce a stable provider/account identity plus opaque credential references. Provider adapters may receive a secret only in process memory immediately before the provider operation; browser payloads and policy persistence must never receive the secret.

## Remaining 2B boundary

Protected Credential Vault is **active, not complete** until the remaining canonical custody work is deliberately implemented and verified:

- stable-account-identity Gmail/Outlook OAuth token custody;
- local policy-encryption key custody/migration;
- macOS Keychain backend;
- Linux Secret Service/keyring backend;
- backup/export behavior proving secrets are excluded;
- uninstall/removal cleanup and later platform packaging acceptance.
