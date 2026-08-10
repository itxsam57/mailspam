# Community Readiness Integrity

## Root cause

The dedicated public community service previously derived `/health` directly from `CommunityNetwork.serverEnabled`. That configuration bit proves only that server mode was requested; it does not prove that authoritative aggregate state is readable, that a current feed can be built, that the active signing identity can sign it, or that the resulting document verifies.

A load balancer or operator could therefore receive HTTP 200 with `ready: true` from an instance that could not safely serve the signed-feed path.

The first readiness gate also exposed a separate first-use race in file-managed signing-key initialization. Parallel processes could both observe an empty signing directory and generate keys; the loser of the private-key `wx` create received `EEXIST` and crashed even though another legitimate initializer was completing the same store.

## Accepted readiness contract

The public `/health` route is readiness, not mere process liveness.

A community instance is ready only when:

1. community server mode is enabled;
2. authoritative aggregate state can be read through the production store path;
3. the current feed payload can be built inside its existing resource limits;
4. the active Ed25519 signer can sign that payload; and
5. the resulting signed document verifies against the instance's current public key using the production feed verifier.

If any of those checks fail, `/health` returns HTTP 503 with only:

- `service: "email-shield-community"`;
- `ready: false`;
- `signedFeedAvailable: false`.

Healthy readiness returns HTTP 200 and both booleans true.

The response is `Cache-Control: no-store`. Internal exception text, paths, key material, storage details and diagnostic reasons are not part of the public health contract.

## Probe resource boundary

Building and signing a full community feed can approach the existing feed resource ceiling, so an unauthenticated health endpoint must not repeat that work for every probe.

Readiness is cached per process for a short bounded interval:

- a successful proof is reused for 15 seconds;
- a failed proof is reused for 2 seconds so recovery is detected quickly.

The cache stores only readiness booleans. It does not cache or expose a signed feed, aggregate payload, private key or internal exception.

## Race-safe first-use signing initialization

File-managed signing identity initialization now has one atomic winner:

1. if a complete stored pair exists, load and validate it;
2. if either key file exists, treat that as possible in-progress initialization and wait only for a bounded interval for the same pair to become complete and valid;
3. if neither exists, generate a candidate pair and atomically create the private key with `wx`;
4. the process that creates the private key is the initializer and writes the matching public key;
5. a contender that loses the private-key create with `EEXIST` never overwrites either file; it waits for and validates the winner's pair;
6. a pair that never becomes complete, or becomes complete but invalid, remains fail-closed and is preserved for diagnosis.

The implementation does not silently replace an unknown partial signing identity.

## Security and privacy boundary

This brick adds no:

- mailbox/provider permission;
- provider API request;
- mailbox content exposure;
- new community report field;
- public signing private key or storage path;
- external destination request from normal scans.

Readiness uses only the existing local community aggregate/sign/verify path.

## Live deployment boundary

This contract does **not** close GAP-004.

CI proves the application readiness semantics and race-safe local signing initialization. A real deployment must still prove that the reverse proxy/load balancer actually uses this endpoint correctly and that production monitoring, DNS/TLS, backups/restores and signing-key rotation operations are wired and exercised in the deployed environment.

No live mailbox test is required for this brick.

## Required regression coverage

Automation must prove at minimum:

- disabled community server mode returns HTTP 503;
- healthy aggregate/sign/verify state returns HTTP 200;
- corrupt authoritative aggregate state after startup returns HTTP 503;
- health failure does not expose internal paths, key wording or decryption details;
- a tampered returned document cannot satisfy readiness;
- repeated healthy health probes reuse the bounded process-local readiness proof;
- concurrent signing-key initialization can converge on the one atomically established pair;
- an abandoned incomplete signing pair still fails closed;
- compiled dedicated-community smoke checks `ready`, `signedFeedAvailable` and `Cache-Control: no-store`;
- strict type/build and the full Windows/macOS/Ubuntu Engineering Gate remain green.
