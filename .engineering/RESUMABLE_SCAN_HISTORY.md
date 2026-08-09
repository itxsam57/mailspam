# Email Shield — Resumable Scan History Contract

## Purpose

Email Shield may continue or resume a mailbox scan without storing complete messages, bodies, HTML, credentials, OAuth material, unsubscribe targets or browser action tokens. Resume state is local, account scoped, encrypted and bounded.

## Stable account ownership

Scan history is stored under the same stable `policyAccountKey` used for account-scoped personal policy. A history record becomes visible or resumable only after the same provider account is connected in the current desktop process. A scan ID alone is not sufficient to cross account boundaries.

The record never stores a raw mailbox address merely to recover account ownership.

## Storage boundary

Scan state uses its own AES-256-GCM database:

- file: `scan-state.enc.json`;
- AAD: `email-shield-scan-state-v1`;
- key reference: `local-encryption-key:scan-history-encryption-key-v1`;
- key custody: the existing native vault factory (Windows Credential Manager, macOS Keychain or Linux Secret Service when available).

The scan-state key is separate from the personal-policy encryption key. No raw scan-state key file is created.

If an encrypted scan-state database exists but its protected key is unavailable, startup fails closed rather than replacing or resetting the database. A fresh environment without an available native vault may use memory-only scan history; it must not create a plaintext persistence substitute.

## What may be persisted

A bounded history record may contain only:

- opaque scan UUID;
- scan type (`quick`, `full`, `spam`);
- status (`running`, `interrupted`, `completed`, `failed`, `stopped`);
- timestamps;
- aggregate verdict/parse counters;
- while resumable only: opaque provider cursor state, completed-folder names, SHA-256 sender recurrence hashes and SHA-256 message-dedupe hashes.

The local encrypted repository is capped to a bounded number of records and bounded checkpoint/database sizes.

## What must never be persisted in scan history

- message body or text preview;
- raw HTML;
- subject or sender address solely for history/resume;
- raw Message-ID or provider-native message ID;
- attachment body/content;
- provider credentials or app passwords;
- access tokens, refresh tokens, authorization codes, PKCE verifier or client secrets;
- unsubscribe destination/target;
- review/unsubscribe browser action tokens;
- community reporter proof or raw report payload.

Sender recurrence and cross-folder dedupe survive resume only through domain-separated SHA-256 hashes.

## Checkpoint ordering

For each successfully returned provider page:

1. Worker returns counters plus the server-only checkpoint.
2. Desktop server updates the encrypted record.
3. The encrypted checkpoint write must succeed.
4. Only then may presentation-only browser action tokens be generated and the privacy-reduced progress payload be sent to an attached dashboard.

If the checkpoint write fails, the scan stops rather than continuing without the promised resumability boundary.

If the SSE/browser stream has detached, step 4 is skipped entirely. The Worker may continue checkpointing in the local process, but no review/unsubscribe action tokens are accumulated for a browser that cannot receive them.

## Browser boundary

The browser may receive:

- opaque scan ID;
- scan type/status;
- timestamps;
- aggregate counters;
- `resumable` boolean;
- ordinary privacy-reduced live scan presentation already permitted by the scan UI.

The browser must never receive:

- provider cursor;
- folder cursor map;
- completed-folder checkpoint material as a resume input;
- sender/message checkpoint hashes;
- the encrypted database/key.

`publicScanProgress()` is the explicit server boundary that removes `cursor` and `checkpoint` before live progress is serialized.

The Scan History UI never writes history/checkpoint data to `localStorage` or `sessionStorage`.

## Refresh and restart behavior

A dashboard refresh or temporary EventSource disconnect does not cancel the Worker. The scan continues in the local process and advances encrypted checkpoints. Explicit **Stop** remains the browser cancellation action.

If the whole Email Shield process exits, no Worker survives. At next protected scan-state initialization, any persisted `running` record is converted to `interrupted`.

After the same account is reconnected, `interrupted`, `failed` and `stopped` records with a checkpoint may be resumed by their opaque scan ID.

## Completion behavior

A completed scan is history, not a future execution capability. On successful completion:

- status becomes `completed`;
- completion timestamp and final counters are retained;
- the checkpoint is set to `null` before the final record is saved.

Completed scans therefore cannot be resumed and no provider cursor remains in their persisted history record.

## Provider-neutral recovery

### Quick Scan

Resume starts from the last confirmed provider cursor while retaining cumulative counters and scan-local sender recurrence hashes. The original Quick Scan message cap remains authoritative after resume.

### Full Mailbox Audit

Resume retains:

- per-folder provider cursors;
- completed-folder set;
- cumulative counters;
- sender recurrence hashes;
- message dedupe hashes across folders.

Completed folders are not scanned again. Previously counted messages are not intentionally counted again when the provider cursor remains valid.

### Spam/Junk Scan

Resume starts from the last confirmed Spam/Junk cursor with cumulative counters and sender recurrence state.

Provider cursor invalidation remains a provider-specific read condition. Email Shield does not weaken provider integrity checks to force an invalid cursor to continue.

## Security boundary

History reads remain under protected local-session + CSRF proof. Resume SSE uses the existing same-origin protected scan-source boundary. Stop remains a protected mutation using the existing CSRF/same-origin/single-use nonce architecture.

No new public network endpoint is introduced.

## Automated enforcement

- `scanStatePersistence.test.ts`
- `resumableScanWorkflow.test.ts`
- `scanHistoryApi.test.ts`
- `scanDetachedStreamContract.test.ts`
- `check:web`
- compiled Worker integration tests
- compiled desktop server smoke
- Windows/macOS/Ubuntu engineering gate

Canonical locks: **REG-049 / A-39**.
