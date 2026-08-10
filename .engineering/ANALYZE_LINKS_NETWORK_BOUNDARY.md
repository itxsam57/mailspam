# Email Shield — Analyze Links Network Boundary

Date: 2026-08-09
Status: production network hardening implemented; controlled real-destination acceptance remains open under GAP-005.

## Purpose

Analyze Links is an explicit per-message action for inspecting destinations already extracted from an email. It must never become an automatic crawler during Quick, Full or Spam/Junk mailbox scans.

The destination is attacker-controlled input. The outbound fetch path is therefore treated as an SSRF/DNS-rebinding boundary rather than as an ordinary browser-style HTTP request.

## Production acquisition contract

For every initial destination and every redirect hop, Email Shield must:

1. accept only `http:` or `https:` URLs and reject URL userinfo;
2. resolve the hostname once for that hop;
3. reject the hop if the DNS answer is empty or if any returned address is non-public;
4. choose only from that validated answer and connect the socket directly to the chosen address;
5. never perform a second transport DNS lookup for the same hop;
6. preserve the original hostname in the HTTP `Host` header;
7. for HTTPS, preserve the original DNS hostname for SNI and certificate hostname verification while TCP remains pinned to the validated IP;
8. repeat the full resolve/validate/pin process after every redirect.

This prevents a destination from passing a public-address check and then rebinding the actual connection to loopback, private, link-local, metadata or another non-public network.

## Address policy

The Analyze Links transport fails closed for non-public and special-purpose destinations, including loopback, private RFC1918 space, link-local, carrier/shared address space, cloud metadata, documentation and benchmark ranges, multicast/reserved ranges, IPv4-mapped IPv6, NAT64/special translation ranges, 6to4/Teredo and non-public IPv6 scopes. Public IPv6 is conservatively limited to global unicast allocation space used by this outbound analyzer.

If one hostname returns a mixture of public and non-public addresses, the entire hop is rejected. The resolver does not pick the public answer and ignore the unsafe answer.

## Request privacy

Analyze Links sends no mailbox cookie, provider token, OAuth credential, local Email Shield session cookie, Authorization header or message content to the destination.

The production request is a GET with a dedicated Email Shield link-analyzer user agent, original Host header, bounded Accept types, `Accept-Encoding: identity`, and `Connection: close`. It does not submit forms, execute scripts, execute downloaded files, or forward browser/mailbox state.

## Resource limits

The production boundary is fixed to:

- maximum 3 redirects;
- maximum 5 seconds total across DNS, redirects and body acquisition;
- maximum 512 KiB text body;
- `text/html` and `text/plain` as inspectable body types;
- identity content encoding only.

The process-wide coordinator in `.engineering/DESTINATION_ANALYSIS_COORDINATOR.md` additionally limits active acquisitions to 4, waiting work to 256 distinct destinations and the in-memory classification cache to 512 fixed-expiry entries. Queue exhaustion fails closed and identical in-flight destinations are coalesced before egress.

A declared body larger than the cap, a streaming overflow, compressed content that was not explicitly requested/decoded, request failure or deadline expiry fails closed. Unsupported/binary content is not downloaded and is never classified as benign merely because Email Shield declined to inspect it.

## Classification boundary

The deterministic destination classifier receives only the bounded result returned by the hardened transport. Password forms may escalate to credential-trap/high-risk behavior; other supported deterministic page signals remain unchanged.

Failure to acquire or safely inspect a destination produces an error/unknown outcome rather than a clean verdict.

## Automatic-scan prohibition

`hardenedFetch` is wired only at the explicit Analyze Links API composition root. Quick, Full and Spam/Junk scan workflows and the scan Worker must not import or invoke the deep-link network resolver.

This separation is regression locked so adding a new scan path cannot silently turn Email Shield into an automatic link crawler.

## Coordinator privacy

Fetched bodies are transient and never enter the shared cache. Cache keys are process-random HMACs; cache values contain neither requested/final URLs nor page content. Successful classifications expire after five minutes, acquisition errors after fifteen seconds, and reads never extend retention. Only aggregate queue/cache counters are observable.

## Automated evidence

The blocking suite covers:

- socket pin receives the same validated DNS address;
- one resolution per hop;
- mixed public/private DNS rejection;
- redirect-to-private/metadata rejection;
- IPv4/IPv6 special-address rejection;
- URL credential and non-HTTP(S) rejection;
- declared and streamed body overflow;
- compressed-content refusal;
- unsupported binary content not treated as benign;
- redirect limit;
- absence of global `fetch()` in the production resolver;
- absence of Analyze Links network access from automatic scan paths;
- production API wiring to the hardened resolver.
- bounded concurrency, queue admission and fail-closed overload;
- in-flight coalescing, fixed TTL, LRU bounds and a 10,000-client shared-destination burst.

Primary tests: `destinationAnalysisCoordinator.test.ts`, `hardenedFetchDnsPin.test.ts` and `analyzeLinksNetworkArchitecture.test.ts`.

## Remaining live gap

This implementation does **not** close GAP-005. CI intentionally does not visit arbitrary real email destinations. Controlled real-destination validation still has to prove the production behavior against a deliberately managed public test destination and redirect chain without involving an uncontrolled or destructive target.

Until that external acceptance is performed, the register must continue to show GAP-005 as a known gap. The code-level DNS-pinning/network-hardening invariant is REG-052 / A-42; live destination acceptance is a separate claim.
