# Email Shield — Portable Protection Core Contract v1

Date: 2026-08-11
Status: Milestone 3 portable core implemented and used by desktop scan workflows; native shell/store acceptance remains open.

## Runtime contract

`server/src/core/portableCore.ts` accepts one JSON-compatible request:

- `schemaVersion: 1`;
- one provider-neutral `CanonicalEnvelope` after shell-only thread/history annotation has consumed raw thread references;
- one complete account-scoped personal-policy snapshot;
- verified signed-feed entries, or the explicit `unavailable` state.

The request is capped at 4 MiB. Runtime validation rejects version drift, unknown fields, oversized strings/arrays, invalid enums/counts/hashes, more than 20,000 verified entries and any unconsumed raw thread-reference field before evaluation.

The response contains only schema version, verdict, score, confirmed-rule state, recommended response policy, evidence and layer results. It never echoes the canonical envelope, account proof, provider-native/message identifiers, subject, body preview, attachment metadata or policy snapshot.

## Determinism and portability

- Desktop Quick, Full and Spam/Junk workflows all call `scanMessageThroughPortableCore`; the former pipeline remains the internal implementation and direct regression oracle.
- Campaign and exact-message fingerprints use the synchronous ECMAScript-only SHA-256 implementation in `server/src/core/sha256.ts`. It is byte-parity tested against the platform cryptographic implementation for empty, Unicode, block-boundary and bounded large inputs.
- Registrable-domain IP recognition uses the bundled `tldts` parser instead of Node `net`.
- A recursive source dependency gate starts at the portable-core entrypoint and rejects Node/host imports, platform globals, network calls, provider adapters, API, OAuth, credential, Worker or platform-shell dependencies. `tldts` is the only approved external module on that graph.
- The core has no filesystem, network, credential-vault, provider SDK, browser DOM or operating-system side effect. Provider acquisition, signed-feed verification, history HMAC annotation, scheduling, notifications and actions remain shell responsibilities.

## Cross-runtime vectors

`fixtures/core-conformance/v1/vectors.json` contains seven complete request/expected-response pairs:

1. the same credential-phishing fixture normalized for Gmail;
2. iCloud;
3. Outlook;
4. Yahoo;
5. generic IMAP;
6. verified intelligence unavailable;
7. personal-block precedence.

The bundle is deterministic, synthetic and under 128 KiB. The blocking compiled-engine check regenerates it in memory and fails on any unreviewed difference. Android/iOS/macOS/Windows bridges must replay this exact bundle before release; a native shell existing on disk is not acceptance by itself.
