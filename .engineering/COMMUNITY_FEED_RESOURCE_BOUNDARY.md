# Community Feed Resource Boundary

## Root cause

The community client previously bounded request time and rejected redirects, but it consumed remote JSON with `response.json()` before applying any response-byte ceiling. A compromised, misconfigured, or unexpectedly large community endpoint could therefore force an oversized allocation before cryptographic feed validation ran.

The signed-feed verifier also authenticated signatures and freshness without first enforcing a bounded v1 entry schema. A validly signed but pathological document could contain excessive entries, large values, or extreme identity alias/domain fan-out and then drive avoidable CPU/memory work in downstream intelligence matching.

## Accepted resource boundary

The community protocol now has one shared local resource contract:

- report request body: at most 64 KiB;
- remote report receipt: at most 32 KiB;
- remote/cached signed feed document: at most 4 MiB;
- signed feed entries: at most 20,000;
- threat-entry value: at most 2,048 characters;
- rule ID: at most 128 characters;
- identity aliases: at most 32 entries, each at most 256 characters;
- identity domains: 1–32 entries, each at most 253 characters.

The client checks a declared Content-Length when present and also counts actual streamed bytes. Chunked, compressed, or otherwise unknown-length responses remain bounded by the bytes delivered to the decoded response stream. Crossing the limit cancels the reader and fails the refresh closed.

Cached feed files are size-checked before parsing.

## Signed document validation

A version-1 signed feed is accepted only when:

1. the document, payload, signature, and entry objects contain only the v1 fields understood by this client;
2. the payload entry count and every string/list field remain inside the shared bounds;
3. threat entries use a supported threat-indicator type;
4. identity entries remain non-threat identity metadata with bounded aliases/domains;
5. optional independent-report counts are bounded positive integers;
6. optional first/last-seen timestamps are parseable and ordered;
7. generated/expiry timestamps satisfy the existing freshness window;
8. the Ed25519 signature is canonical base64 decoding to exactly 64 bytes;
9. the signing key is trusted and the signature verifies;
10. the complete signed document remains inside the 4 MiB client acquisition limit.

Unknown extra v1 fields are rejected rather than recursively consumed or silently ignored. A future protocol extension requires a reviewed version change.

## Fail-closed behavior

An oversized, malformed, stale, untrusted, or incorrectly signed feed is unavailable intelligence. It is never interpreted as a clean feed.

The client never truncates a signed feed to make it fit because truncation would invalidate the signature and could preferentially remove threat indicators.

If a refresh fails, a previously verified feed may remain usable only while it still independently passes signature and freshness validation.

A central report that has already been durably accepted is not misreported as rejected merely because feed publication has reached the explicit resource ceiling. Publication is deferred/fails closed while the accepted report remains stored; this prevents clients from endlessly re-queuing an already accepted report.

The central signer refuses to emit a document that exceeds the client acquisition boundary.

## Security and privacy boundary

This brick adds no:

- mailbox/provider permission;
- provider API request;
- mailbox content field;
- browser-visible report payload;
- raw URL/path/query disclosure;
- plaintext community persistence;
- automatic external destination request from normal scans.

Existing encrypted aggregate storage, encrypted retry outbox, reporter thresholds, Ed25519 trust/freshness, and privacy-reduced indicator rules remain unchanged.

## Deployment boundary

This contract does **not** close public deployment or gateway abuse gaps.

GAP-004 still requires the actual production environment to prove DNS, TLS/HSTS, reverse proxy/gateway configuration, monitoring, backups/restores, least privilege, outbound restrictions, and operational signing-key rotation.

GAP-008 still requires production gateway/IP/device reputation and volumetric/DDoS controls.

Operators must monitor feed size and migrate the protocol to a reviewed pagination/delta/versioned distribution model before legitimate production growth approaches the signed-feed ceiling. Silent entry dropping is forbidden.

## Required regression coverage

At minimum, automation must prove:

- excessive entry count is rejected;
- oversized entry values and identity fan-out are rejected;
- malformed/wrong-length Ed25519 signatures are rejected;
- normal bounded feeds still sign and verify;
- the signer refuses an over-limit final document;
- declared oversized responses fail before unbounded body consumption;
- chunked/unknown-length responses stop at the byte ceiling;
- an independently still-valid cached feed survives a bad refresh;
- oversized report receipts fall back to the encrypted outbox;
- durable report acceptance is not reversed by a subsequent feed-capacity publication failure;
- full Windows/macOS/Ubuntu Engineering Gate remains green.
