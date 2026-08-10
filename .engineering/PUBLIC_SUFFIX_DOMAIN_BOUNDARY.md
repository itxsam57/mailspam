# Public Suffix Domain Boundary

## Root cause

Email Shield previously implemented `organizationalDomain()` with a last-two-label rule plus a short handwritten list of common multi-label suffixes. That cannot define a universal registrable-domain boundary. Public suffix policy varies by registry and includes deep suffixes, wildcard rules, exception rules, and privately operated multi-tenant suffixes.

Because `organizationalDomain()` and `sameOrganizationalDomain()` are shared security helpers, an incorrect collapse can create false trust across otherwise unrelated registrants. Consumers include author-domain authentication alignment, authenticated sender identity, private-relay origin derivation, displayed-vs-actual link comparison, authenticated bulk-link context, and sensitive cross-domain action detection.

## Accepted boundary

The canonical local helper uses the locked `tldts` package and its bundled Public Suffix List snapshot to derive the registrable domain (public suffix plus one registrant-controlled label).

Rules:

1. ICANN Public Suffix List rules are enabled.
2. Private Public Suffix List rules are enabled. Distinct tenants below a private suffix such as `github.io` must not be treated as one organization.
3. Wildcard and exception rules are honored by the PSL implementation rather than reconstructed in Email Shield code.
4. Known bare public suffixes have no registrable organization and return an empty organizational boundary; they cannot satisfy `sameOrganizationalDomain()`.
5. IP addresses preserve their normalized literal value for callers that already handle IPs separately.
6. Single-label hostnames preserve existing compatibility but do not match a different single-label hostname.
7. Unknown but syntactically parseable suffixes retain the parser's conservative last-label behavior so reserved fixture/test domains continue to group their own subdomains.
8. Domain comparison stays local/offline. No scan-time DNS request, registry lookup, provider request, browser API, or external domain service is permitted.

## Dependency boundary

`tldts` is a production dependency and is pinned in `server/package.json`; the exact resolved dependency graph is locked in the repository root `package-lock.json` and must continue to pass `npm ci` on Windows, macOS, and Ubuntu.

The PSL snapshot changes when the dependency is deliberately upgraded. Such an upgrade is a security-boundary change and must run the full Engineering Gate plus the public-suffix regression corpus. Runtime downloading of a newer PSL is intentionally not part of this architecture.

## Security consumers

The shared helper must remain the single registrable-domain decision point for existing consumers. Do not add separate per-layer suffix lists or duplicate last-N-label logic to make an individual test pass.

At minimum, regression coverage must prove:

- ordinary two-label registrable domains remain stable;
- common multi-label domains such as `example.co.uk` resolve correctly;
- deep public suffixes do not merge separate registrants;
- PSL wildcard and exception rules are respected;
- private multi-tenant suffixes isolate tenants;
- bare public suffixes do not become authenticated organizations;
- SPF/DKIM fallback alignment cannot cross a PSL registrant boundary;
- same-registrant sibling subdomains can still align;
- displayed-link and actual-link comparison detects cross-registrant deception;
- sensitive authenticated actions leaving a private-suffix tenant remain cross-domain.

## Non-goals

This brick does not:

- change DMARC/SPF/DKIM mechanism parsing;
- solve Authentication-Results `authserv-id` provenance;
- perform DNS-based organizational-domain discovery;
- add sender allowlists or brand mappings;
- add network activity to mailbox scans;
- change provider permissions;
- add persistence fields;
- add browser-visible raw domain intelligence;
- change community-report schema;
- claim controlled live-provider or public-deployment acceptance.

## Standards/data basis

The Public Suffix List defines suffixes under which Internet users or tenants may register names and exists because registry policy cannot be inferred reliably from a fixed label-count algorithm. The locked parser consumes that data locally so Email Shield has one deterministic registrable-domain boundary across providers and operating systems.
