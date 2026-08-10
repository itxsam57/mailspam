# Community Scalable Ingestion and Retention Contract

## Root cause

The former aggregate store decrypted, parsed, rewrote and re-encrypted the complete community database for every accepted report. Its privacy and integrity properties were strong, but its work grew with total stored state and it could not truthfully satisfy the canonical 10,000-client acceptance gate.

## Production boundary

- Every report is strictly normalized and checked against submission age, schema, reporter proof, campaign identity, verdict, evidence and indicator bounds before persistence.
- Capacity is predicted against the exact encrypted snapshot budget before the report is durably accepted.
- The normalized report and server acceptance timestamp are AES-256-GCM encrypted as an individual append-journal event.
- Journal writes use a same-descriptor regular-file boundary with no-follow where supported, exact expected-size comparison and a fixed 16 MiB ceiling.
- In-memory reporter/campaign indexes make dedupe, per-reporter limits, status thresholds and capacity accounting independent of total aggregate size per request.
- A bounded interval compacts the journal into an atomically replaced encrypted version-2 snapshot. The accepted event remains recoverable from the journal if compaction fails.
- Snapshot version 2 attributes indicators and evidence codes to their reporter, enabling exact reporter expiry. Strictly valid version-1 snapshots are deterministically migrated in memory; invalid authenticated state remains fail-closed.
- Startup replays every complete authenticated journal event. Only an incomplete final crash-tail record—written before acceptance could return—is removed by validated descriptor truncation.
- Cached state is trusted only while descriptor-derived snapshot/journal identity (existence, device, inode, size and change timestamps) remains unchanged. External corruption after startup makes readiness fail closed without restoring whole-database work per request.
- Reporter records expire 90 days after server acceptance. Expired reporters stop contributing to thresholds, campaign counts and signed intelligence; empty campaigns are removed and the pruned state is compacted.
- Backup and restore treat the snapshot, journal and storage key as one aggregate set and validate the reconstructed feed path before cutover.

## Acceptance

`communityCapacityRetention.test.ts` exercises 10,000 independent reporter proofs through the production validation, encryption, journaling, dedupe, restart and signing path. It also locks duplicate non-inflation, crash-tail recovery and fixed retention. The existing community state, readiness, public-error, recovery and storage suites remain blocking.

This contract does not claim gateway/IP reputation, volumetric DDoS protection or completed public deployment; those remain external acceptance boundaries.
