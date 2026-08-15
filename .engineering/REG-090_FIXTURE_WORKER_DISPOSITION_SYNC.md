# REG-090 — Fixture Worker Disposition Synchronization

Status: **LOCKED**

## Defect

Consumer hard-testing of the published desktop package proved that an account-local reported campaign was correctly classified as `LOCALLY_REPORTED_SCAM_CAMPAIGN` and the scan Worker invoked durable automatic Trash, but the synthetic fixture message reappeared in Inbox on the next scan.

The live provider protection path was not the cause. Gmail, Outlook and IMAP-family mutations are external provider state. The engineering fixture instead stored folder overrides inside the account configuration object. `workerData` is structured-cloned at the Worker boundary, so a fixture adapter inside the Worker mutated only its cloned `fixtureFolderOverrides` object. The desktop owner never observed that synthetic move.

## Root repair

Fixture sessions now allocate one small bounded `SharedArrayBuffer` containing only synthetic corpus folder-state codes. The secured fixture config owns that buffer for the lifetime of the account session. Node Worker structured cloning preserves shared-memory identity, so desktop adapters and scan Worker adapters observe the same fixture mailbox state.

The fixture corpus maps each deterministic synthetic message slot to one byte: uninitialized, Inbox, Spam/Junk or Trash. The first adapter deterministically seeds unset slots from the existing fixture defaults/explicit overrides. A provider-confirmed fixture move atomically updates the shared byte as well as the legacy in-thread override object.

This state contains no real mailbox content, sender, subject, URL, credential, OAuth material, provider account identity or live message identifier. Live provider configurations do not receive this field and their adapter behavior is unchanged.

## Permanent protection

- `fixtureMailboxState.test.ts` proves ordinary adapter recreation still preserves fixture moves.
- The same suite creates a secured fixture config, `structuredClone`s it to reproduce the Worker boundary, moves a message through the cloned adapter and proves the owning desktop config sees that exact message in Trash.
- The shared state has a fixed 4 KiB bound and rejects invalid state/bounds rather than silently expanding.
- Full Worker, browser, package and Windows/macOS/Ubuntu Engineering Gates remain blocking.
- Final consumer acceptance must use the downloaded package to prove Report Scam current Trash plus later `LOCALLY_REPORTED_SCAM_CAMPAIGN` automatic Trash, and Block Sender current/future automatic Trash, before owner handoff.

Any future fixture implementation that lets a Worker-confirmed provider disposition disappear at the structured-clone boundary is a blocking acceptance regression.
