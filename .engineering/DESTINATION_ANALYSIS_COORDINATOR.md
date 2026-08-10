# Email Shield — Destination Analysis Coordinator

Date: 2026-08-11  
Status: production coordinator and capacity boundary implemented; controlled public-destination acceptance remains open under GAP-005.

## Scope

Analyze Links remains an explicit per-message action. Quick, Full and Spam/Junk scans cannot import or invoke the destination network path. The coordinator is process-wide at the desktop API composition root and is the only production caller of the DNS-pinned Analyze Links fetcher.

## Worker and admission boundary

- At most **4** destination jobs execute concurrently.
- At most **256** additional distinct jobs wait in memory.
- When the queue is full, new distinct work fails closed with an explicit `error` classification. It is never treated as benign.
- Simultaneous requests for the same normalized destination share one in-flight job.
- Result ordering always matches canonical-envelope link ordering.
- The underlying fetch path still resolves, validates and pins each redirect hop independently, applies one total deadline, and bounds redirect count and response bytes.

The coordinator is an asynchronous bounded worker pool, not an automatic crawler. It neither expands provider permissions nor adds a scan-time network path.

## Cache and retention boundary

Completed classifications use an in-memory LRU cache with these fixed limits:

- maximum **512** entries;
- **5-minute** fixed retention for completed non-error classifications;
- **15-second** fixed retention for failed acquisition/classification;
- expiry is measured from insertion and is not extended by reads;
- least-recently-used eviction is applied at the entry ceiling;
- all cached state disappears on process exit and can be cleared immediately.

Cache keys are HMAC-SHA-256 tokens under a random 32-byte process key. Cached values contain classification booleans and generic detail only. They contain no requested URL, redirect URL, fetched body, mailbox identity, provider credential, cookie or authorization value. Complete redirect destinations are no longer copied into classification detail because paths and query strings may contain secrets.

The waiting queue necessarily holds the requested URL only while that explicit job is pending or active. It is bounded by admission limits and never persisted.

## Privacy-safe telemetry

The coordinator exposes aggregate counters only:

- active workers, queued jobs and in-flight destination count;
- cached destination count;
- cache hits/misses and coalesced request count;
- rejected job and eviction counts.

No telemetry field exposes a URL, hostname, message, account, fetched content or cache token.

## Automated evidence

`destinationAnalysisCoordinator.test.ts` locks:

- concurrent worker ceilings and stable output order;
- credential-trap escalation;
- in-flight coalescing and later cache hits;
- fixed, non-sliding retention and shorter error retention;
- fail-closed bounded-queue overflow;
- LRU entry bounds;
- a 10,000-client same-campaign burst producing one outbound acquisition without duplicate inflation;
- aggregate-only telemetry.

`hardenedFetchDnsPin.test.ts` and `analyzeLinksNetworkArchitecture.test.ts` continue to lock SSRF/DNS-rebinding protection, redirect revalidation, resource limits, production wiring and the automatic-scan prohibition.

## External acceptance boundary

GAP-005 remains open. CI does not contact arbitrary mail destinations. Closure requires deliberately managed public test infrastructure that proves DNS, redirects, certificates, timeout/body limits and observable egress behavior without using real malicious destinations or mailbox credentials.
