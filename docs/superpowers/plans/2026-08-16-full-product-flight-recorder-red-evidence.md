# Full-Product Flight Recorder RED Evidence

Frozen test-only head: `6313c02996192ba299f1dc1aa36b68b039cfdc93`.

Expected failures before production implementation:

- `tests/unit/runtimeTraceCheckpoint.test.ts` cannot resolve `server/src/diagnostics/runtimeTraceCheckpoint.ts`.
- `tests/unit/runtimeWorkflowTraceV2.test.ts` expects schema-v2 `workflowId`, `checkpointId`, and `buildId`; current recorder accepts only the v1 allowlist and writes `schemaVersion: 1`.

No production source is changed on this RED head.
