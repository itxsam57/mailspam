# Community Aggregate State Integrity

## Root cause

The central community aggregate store authenticated `community-reports.enc.json` with AES-256-GCM, but after successful decryption it previously trusted almost all nested JSON as the TypeScript `CommunityDatabase` shape. Only the top-level database version and existence of a `campaigns` object were checked.

Cryptographic authenticity proves that the ciphertext was produced under the local storage key and has not been modified without that key. It does not prove that application code, a migration, a restore workflow, or other state-management logic wrote a structurally valid database before encryption.

A correctly authenticated but malformed nested state could therefore reach status calculation, feed generation, readiness checks, later report acceptance, or disaster-recovery validation.

## Accepted persisted-state contract

Every decrypted version-1 aggregate database must satisfy the exact state invariants emitted by the current writer before any consumer may use it.

### Database

- only `version` and `campaigns` fields are accepted;
- `version` must be `1`;
- `campaigns` must be an object;
- campaign count must not exceed the existing `MAX_CAMPAIGNS` production limit.

This brick does not create a lower campaign-growth limit.

### Campaign record

Each campaign key must remain the canonical 64-character lowercase hexadecimal campaign fingerprint.

Each campaign record contains only:

- `firstSeen`;
- `lastSeen`;
- `reporters`;
- `indicatorReporters`;
- `evidenceCodes`.

`firstSeen` and `lastSeen` must be canonical ISO timestamps and `firstSeen <= lastSeen`.

### Reporter records

A persisted campaign must contain at least one reporter.

Each reporter key must be a canonical 64-character lowercase hexadecimal reporter proof. Each record contains only:

- `reportedAt`;
- `evidenceScore`;
- `verdict`.

The timestamp must be canonical ISO and inside the campaign interval. At least one current reporter record must correspond to the campaign `lastSeen`, matching the writer's update behavior.

Persisted evidence score must be an integer from 0 through 20 and verdict must be one of the supported report verdicts.

### Indicator support

`indicatorReporters` must be an object with at least the canonical campaign indicator.

Each key must use a supported community indicator type and a non-empty normalized value no longer than the existing 512-character report boundary. Support arrays must:

- be non-empty;
- contain no more entries than the campaign reporter count;
- contain only canonical reporter proofs that exist in the campaign;
- contain no duplicates;
- remain in the writer's sorted form.

Any `campaign` indicator must refer to the enclosing campaign fingerprint. The canonical `campaign\0<fingerprint>` support list must contain every current reporter exactly once.

The parser intentionally preserves the current writer's first-NUL separator semantics; this validator does not invent a new incompatible indicator encoding rule.

### Evidence-code counters

`evidenceCodes` must be an object. Each key must match the existing uppercase evidence-code format and each value must be a positive integer no greater than the campaign's independent reporter count.

## Fail-closed behavior

A database that authenticates cryptographically but fails nested validation is unreadable state.

The same existing read failure then blocks:

- aggregate stats;
- signed-feed generation;
- new report acceptance that would otherwise build on corrupt state;
- readiness proof;
- disaster-recovery backup validation.

The state is preserved for diagnosis; it is not normalized, truncated, partially accepted, or silently rewritten.

## Security and compatibility boundary

This brick adds no:

- storage migration;
- new plaintext persistence;
- provider/mailbox permission;
- public report field;
- network request;
- lower campaign-count ceiling.

The validator accepts the exact nested form the current production writer emits and rejects states the writer could not legitimately produce.

## Live deployment boundary

No live mailbox or public deployment test is required for this brick. The validation path is deterministic and fully CI-testable.

GAP-004 remains open: an actual production backup/restore drill must still exercise the deployed storage, secret distribution, filesystem permissions and operator cutover path.

## Required regression coverage

Automation must prove at minimum:

- writer-produced encrypted state remains readable;
- valid AES-GCM envelopes with unknown top-level/campaign fields fail closed;
- invalid campaign fingerprints fail closed;
- invalid persisted reporter scores or out-of-interval timestamps fail closed;
- unknown indicator reporter references fail closed;
- incomplete canonical campaign support fails closed;
- impossible evidence-code counts fail closed;
- stats, feed generation and report acceptance all refuse the same corrupt state;
- disaster-recovery backup refuses structurally corrupt but cryptographically authentic state;
- strict type/build and the full Windows/macOS/Ubuntu Engineering Gate remain green.
