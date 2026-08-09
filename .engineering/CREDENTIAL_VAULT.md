# Email Shield — Credential Vault Boundary

## Milestone 2 status

This document defines the protected-credential boundary built on the accepted Milestone 1 baseline.

- **2A.1 Local API and Process Isolation:** inherited as complete and locked by `REG-032` through `REG-034` plus resolved `GAP-007`.
- **Shared credential-vault contract:** implemented with opaque deterministic references, bounded secrets, secret-safe public errors and no plaintext fallback.
- **Windows Credential Manager:** implemented and proven by real Windows CI round trips.
- **macOS Keychain:** implemented and proven by a real macOS CI round trip.
- **Linux Secret Service:** implemented and proven by a real Ubuntu CI round trip inside an isolated D-Bus/GNOME Keyring user session.
- **App-password custody:** iCloud, Yahoo and generic IMAP use native-vault handles whenever a supported native vault is available.
- **Guided OAuth custody:** Gmail and Outlook refresh tokens use the same native-vault abstraction and stable account identities independent of token rotation.
- **Local policy-encryption key custody:** the AES-256-GCM key uses the same native vault; legacy raw policy-key migration verifies encrypted state and vault read-back before deleting the legacy key.

Native desktop credential custody is therefore implemented for Windows, macOS and Linux. Protected Credential Vault remains a broader Milestone 2 work package: backup/export proof, uninstall/removal cleanup, packaging acceptance, and provider-specific live acceptance remain separate work and are not declared complete by this document.

## Security invariant

Email Shield must never silently fall back from an operating-system credential vault to plaintext files, browser storage, environment-variable persistence, policy storage, logs, diagnostics or backup/export payloads.

If a native vault advertises availability and a protected write fails, the protected operation fails. If the operating system or current user session does not provide the expected native service, Email Shield uses the existing memory-only/fail-closed boundary rather than inventing persistent plaintext storage.

## Shared contract

The credential-vault layer accepts only:

- an opaque Email Shield credential reference;
- a constrained credential kind;
- the secret value for a write operation.

The operating-system lookup identifier is derived from a SHA-256 namespace hash. Mailbox addresses, provider account IDs and secret values are not used as readable native-store metadata.

Supported credential kinds are:

- OAuth refresh token;
- OAuth client secret where a legacy provider flow requires one;
- IMAP/app password;
- local encryption key.

All native backends implement one `CredentialVault` contract and expose truthful capabilities. Provider/session code does not choose a platform-specific storage path itself.

## Windows Credential Manager backend

The Windows backend uses Windows Credential Manager Generic Credential APIs (`CredWriteW`, `CredReadW`, `CredDeleteW`) through a non-interactive Windows PowerShell bridge.

Security properties:

- PowerShell is resolved from the Windows system directory rather than through a shell command;
- no shell is used;
- the runtime secret is supplied over child-process stdin and never placed in command-line arguments;
- the encoded PowerShell program contains no runtime secret;
- the secret is stored for the signed-in Windows user;
- credential blobs are bounded and are never truncated;
- temporary unmanaged write buffers and managed byte arrays are zeroed where the bridge controls them;
- bridge stderr and raw lower-layer failures are not surfaced through public vault errors;
- delete treats an already-missing credential as successful idempotent cleanup.

## macOS Keychain backend

The macOS backend uses the system `/usr/bin/security` client for generic-password items under the fixed service namespace `EmailShieldCredentialV1`.

Security properties:

- no shell is used;
- native item account metadata is the same opaque SHA-256-derived Email Shield target, not a mailbox address, provider identity or secret;
- write secrets are Base64-wrapped only for transport safety and are supplied through `security -i` on stdin;
- the child process command line contains only the `security` executable plus `-i`, so the runtime secret is not exposed through argv;
- reads use `find-generic-password ... -w`, validate and decode the stored payload, and reject malformed secret data;
- deletes use exact service + opaque-account matching and treat an already-missing item as idempotent cleanup;
- stderr is discarded and native error details are mapped to secret-safe Email Shield vault errors.

The interactive write path is intentional. Apple SecurityTool's `-w` option without an argument prompts through `getpass()` on the terminal rather than reading stdin. Email Shield therefore uses SecurityTool's documented interactive command mode, whose command stream is read from stdin, instead of putting the secret in process arguments or relying on a TTY prompt.

## Linux Secret Service backend

The Linux backend uses `/usr/bin/secret-tool` against the desktop Secret Service API.

Security properties:

- no shell is used;
- lookups use fixed `application=email-shield-v1` plus an opaque `credential=<sha256-derived-target>` attribute;
- `secret-tool store` receives the runtime secret on stdin until EOF, never in argv;
- no newline is appended to the secret because `secret-tool` treats stdin content as the secret value;
- reads and deletes use only the fixed non-secret attributes;
- stderr is discarded and public failures do not include lower-layer secret-bearing text;
- the backend reports native availability only when `secret-tool` exists and the current Linux login session exposes a D-Bus session bus.

If the Linux desktop session has no reachable Secret Service, the backend is unavailable and Email Shield must not replace it with a plaintext file or environment store.

## App-password account-session lifecycle

For iCloud, Yahoo and generic IMAP when a native persistent vault is available:

1. The submitted app password is used transiently to validate the provider connection and folder discovery.
2. After provider validation succeeds, Email Shield derives a deterministic opaque credential reference from stable non-secret account identity:
   - iCloud/Yahoo: provider + normalized mailbox user;
   - generic IMAP: normalized host + port + normalized mailbox user.
3. The app password is written to the selected operating-system vault.
4. The long-lived Email Shield account session stores only the secret reference, not the raw app password.
5. Scans and explicit provider actions resolve the reference only when the provider adapter connects.
6. Worker/session payloads carry the vault handle rather than the raw app password when native persistence is active.
7. The short-lived runtime provider adapter is discarded on disconnect.

The deterministic reference is intentionally independent of the password value. Rotating an app password therefore does not create a new personal-policy identity or orphan existing user rules.

### Shared-reference ownership

Multiple active sessions for the same mailbox can legitimately share one deterministic credential reference. Email Shield reference-counts that ownership and serializes credential lifecycle mutations so reconnect and remove operations cannot race.

- Removing one of several same-account sessions does **not** delete the shared native credential.
- The final same-account session removal deletes the native credential before the account is reported removed.
- If native deletion fails, the session remains present/retryable rather than falsely claiming cleanup success.
- A reconnect and old-session removal cannot interleave in a way that deletes the credential underneath the new session.

## Guided OAuth custody

Guided Gmail and Outlook use stable provider/account identity rather than a refresh token as personal-policy identity. Refresh-token rotation therefore does not create a new policy identity.

After provider identity and scope validation, the refresh token is committed through the same selected native vault. Provider adapters receive the resolved secret only in process memory immediately before provider work; browser payloads and policy persistence never receive it.

Real provider consent/mailbox acceptance is tracked separately from native vault implementation because CI intentionally receives no live mailbox credentials.

## Personal-policy encryption-key custody

The encrypted personal-policy repository uses AES-256-GCM. At process startup, its 32-byte encryption key is resolved through the native credential vault before the desktop server begins accepting production requests.

For a legacy `personal-policy.key` migration when a native vault is available:

1. validate the legacy key length;
2. authenticate/decrypt the existing encrypted policy database with that key;
3. write the same key to the deterministic `local-encryption-key` native-vault reference;
4. read it back from the native vault and compare it byte-for-byte;
5. only after those checks succeed, delete the raw legacy key file.

A missing protected key for an existing encrypted database, a conflicting protected/legacy key, a failed vault write/read-back, or an unreadable database fails closed instead of resetting personal policy state.

## Missing-service and unsupported-platform boundary

Windows, macOS and Linux now have native vault implementations. Availability is still truthful at runtime: for example, a Linux process without a usable Secret Service login session does not pretend that persistent native storage exists.

Other operating systems, or supported systems whose required native user-session service is unavailable, use the existing memory-only/fail-closed boundary. No new raw key or provider-secret file is created as a substitute.

## Claims deliberately not made

The native stores are user-bound, but Email Shield does **not** claim universal hardware-backed storage or cryptographic application binding. Those properties vary by operating system, device configuration, executable signing/packaging and native-store policy.

This work also does **not** claim that backup/export behavior, uninstall cleanup, executable packaging/ACL acceptance, or every live provider flow has been owner-accepted. Those remain separate Milestone 2/deployment responsibilities.

## Platform capability state

| Platform | Backend | Current state |
|---|---|---|
| Windows | Windows Credential Manager | Implemented; real native CI round trip and real policy-key migration covered |
| macOS | Keychain | Implemented through `/usr/bin/security`; real native CI write/read/delete and desktop policy startup covered |
| Linux | Secret Service / keyring | Implemented through `secret-tool`; real isolated D-Bus/GNOME Keyring CI round trip covered; requires a reachable user-session Secret Service at runtime |
| iOS | Keychain design | Future platform work |
| Android | Keystore design | Future platform work |

## Remaining Protected Credential Vault boundary

The cross-platform desktop native-store implementation is complete, but the broader Protected Credential Vault work package remains active until its remaining canonical operational work is finished and verified:

- backup/export behavior proving protected secrets are excluded;
- uninstall/removal cleanup behavior;
- signed/packaged executable acceptance and any platform-specific native-store ACL behavior;
- controlled real-Outlook owner acceptance, tracked separately from the vault backend itself;
- any future mobile-platform credential-store implementation if mobile becomes part of the canonical product.
