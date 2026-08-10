# Email Shield — Scheduled Background Protection Contract

Date: 2026-08-11
Status: Milestone 3 repository implementation complete; native-platform visible/background-policy acceptance remains platform work.

## Account and persistence boundary

- Each connected account owns one schedule keyed only by its existing 64-character opaque policy-account hash. Mailbox addresses, provider labels, raw credentials, messages and scan results are not schedule fields.
- Schedule state uses a dedicated AES-256-GCM database and a separate `background-protection-encryption-key-v1` native-vault reference. The database is bounded to 256 KiB and 128 account records.
- If the expected native vault is unavailable on a fresh platform, schedules are process-memory only and the dashboard says so. Existing encrypted schedule state without its protected key blocks startup rather than being reset.
- Interrupted `running` state becomes a generic protected-state failure with a bounded retry after restart. No exception text or provider/mailbox value is persisted or returned.

## Execution and quota boundary

- Intervals are whole minutes from 30 minutes through 24 hours.
- One background scan may run in the process at a time. A manual account scan always wins; a due background run is deferred five minutes without increasing its failure count.
- Each run is a read-only Quick Scan through the existing compiled Worker. It examines no more than 20 messages, or 10 for live IMAP-family providers using two-message pages.
- The hard wall-clock deadline is four minutes. First-progress and next-progress deadlines are independently enforced.
- Provider failures back off from five minutes to at most six hours without exceeding the user interval. Successful completion resets the failure count.
- Background runs never mint browser action tokens, execute mailbox mutations, submit community reports, invoke explicit Analyze Links, or display raw scan results. They update only the existing encrypted privacy-reduced scan history and HMAC relationship history.

## Lifecycle and UI

- The account-scoped protected API supports enable, pause, interval selection and visible scheduled/running/deferred/failed/completed status.
- Disconnect terminates an active Worker through the existing session lifecycle and removes the account schedule so orphaned work cannot restart.
- The dashboard uses `role=status`, `aria-live=polite`, locale-aware date/time formatting and text-only status rendering.
- Platform shells must still prove their native background-task policy, notification behavior, energy/quota compliance and visible pause/resume behavior. iOS is explicitly quota-scheduled, never described as a continuous daemon.
