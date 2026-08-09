# Native Vault Completion — macOS Keychain and Linux Secret Service

Date: 2026-08-09
Milestone: 2
Scope: desktop native credential-vault completion

## Goal

Extend the existing fail-closed `CredentialVault` contract beyond Windows Credential Manager without creating a parallel storage architecture or weakening the accepted Windows path.

The same native-vault factory is used by:

- iCloud/Yahoo/generic-IMAP app-password custody;
- guided Gmail refresh-token custody;
- guided Outlook refresh-token custody;
- the AES-256-GCM personal-policy encryption key.

## Implemented backends

### macOS

Backend: macOS Keychain through `/usr/bin/security`.

- opaque SHA-256-derived account target;
- fixed Email Shield service namespace;
- no shell execution;
- Base64-wrapped runtime secret supplied through SecurityTool interactive stdin;
- child argv contains only `/usr/bin/security -i` for writes;
- read-back is decoded and validated before use;
- exact delete is idempotent when the item is already absent;
- no universal hardware-backed or application-bound claim.

### Linux

Backend: freedesktop Secret Service through `/usr/bin/secret-tool`.

- fixed application attribute plus opaque SHA-256-derived credential attribute;
- no shell execution;
- `secret-tool store` receives the complete runtime secret on stdin until EOF;
- read/delete arguments contain only non-secret lookup attributes;
- runtime availability requires `secret-tool` and a D-Bus user session;
- missing Secret Service never causes a plaintext fallback.

## First three-platform gate finding

Engineering Gate 232 (`31315476975`) intentionally exercised real native stores.

Windows and Linux native vault round trips worked. Ubuntu's gate was blocked only by an over-broad source assertion that mistook `stdin: request.secret` for argv leakage.

macOS exposed a real implementation defect: the initial write path used `security add-generic-password ... -w` while attempting to supply the password on stdin. Apple SecurityTool source shows that `-w` without an argument invokes `getpass()` on the controlling terminal; it does not consume stdin as the password. The subsequent Keychain read therefore did not yield the expected Base64 credential payload, and the production desktop smoke failed for the same root cause when policy-key custody exercised Keychain.

## Root correction

The macOS bridge now uses `security -i` and writes one SecurityTool command to stdin:

`add-generic-password -a <opaque-target> -s EmailShieldCredentialV1 -U -w <base64-secret>`

SecurityTool interactive mode reads command lines from stdin when stdin is not a terminal and returns the executed command result. The runtime secret therefore remains outside process argv while using the native tool's actual supported input model.

The Linux regression was narrowed to inspect argv construction specifically rather than rejecting the required stdin assignment.

## Accepted automated evidence

Engineering Gate 235 (`31315779519`) passed on the corrected code head `39473e0d0013d3754ba0c681456f12d673deef07` before governance-only updates:

- Ubuntu: PASS, including isolated D-Bus + GNOME Keyring Secret Service native write/read/delete;
- macOS: PASS, including real Keychain native write/read/delete and compiled desktop startup with native policy-key custody;
- Windows: PASS, preserving real Windows Credential Manager and policy-key migration coverage;
- Gate Result Summary: PASS.

A final exact-head gate is required after the governance records in this branch are complete. The PR must not merge on Gate 235 alone because the engineering contract itself changed afterward.

## Locked boundary

`REG-047` / `A-37` require:

- one opaque-reference contract across all three desktop native stores;
- no write secret in process argv;
- no shell execution;
- secret-safe lower-layer error handling;
- real native write/read/delete CI coverage for Windows, macOS and Linux;
- no plaintext persistence fallback when a native store or user-session service is unavailable.

`GAP-003` is resolved for desktop OS-keychain-backed provider-token and local-encryption-key custody. This does not close the broader Protected Credential Vault work package or unrelated provider/deployment acceptance work.
