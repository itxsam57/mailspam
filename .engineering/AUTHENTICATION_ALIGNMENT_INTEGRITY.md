# Authentication Alignment Integrity

## Accepted security boundary

Email Shield must distinguish **authentication mechanism success** from **authentication of the visible RFC5322.From author domain**.

This alignment contract applies only **after** the Authentication-Results producer/path provenance has been explicitly established as trusted under `.engineering/AUTHENTICATION_RESULTS_PROVENANCE.md`. Missing, unknown or suspicious provenance makes SPF/DKIM/DMARC/ARC non-authoritative and none of the pass/fail semantics below may be used as facts.

SPF authenticates an SMTP identity (`smtp.mailfrom` or, in limited cases, HELO). DKIM authenticates the signing domain reported as `header.d`. Either mechanism may pass for a domain unrelated to the visible author. A bare `spf=pass` or `dkim=pass` therefore MUST NOT create organizational sender trust, suppress phishing evidence, establish relay-origin trust, or unlock bounded-content Safe eligibility.

After provenance is trusted, DMARC pass is sufficient for this local author-domain alignment decision because DMARC pass requires at least one successful authenticated identifier aligned with RFC5322.From. An explicit trusted `dmarc=fail` is authoritative negative evidence for this decision and MUST NOT be overridden by locally reinterpreting an apparently aligned SPF/DKIM property.

Only when trusted DMARC is unavailable or reports `none` may Email Shield recover author alignment from the already-present canonical `authentication.rawHeader`:

- `spf=pass` is author-aligned only when the `smtp.mailfrom` identity in that same result segment shares the From organizational domain;
- `dkim=pass` is author-aligned only when the `header.d` identity in that same result segment shares the From organizational domain;
- an aligned property attached to a failed or different result must never be borrowed by a passing mechanism;
- a pass without its relevant reported identifier is not author-domain authentication.

## Resource and privacy boundary

This brick is metadata-only. It must not add:

- DNS lookups;
- provider API calls;
- mailbox permissions;
- remote authentication services;
- persistent authentication-identity storage;
- browser-visible raw Authentication-Results data;
- community-report fields.

The transport-auth layer may report SPF/DKIM/DMARC mechanism outcomes only when the same provenance boundary is trusted. Untrusted results make authentication inspection incomplete rather than positive or negative evidence.

## Provenance dependency

RFC 8601 requires Authentication-Results consumers to understand which upstream authentication service is inside their trust boundary. That dependency is now enforced by `.engineering/AUTHENTICATION_RESULTS_PROVENANCE.md`:

- live raw-MIME Gmail, Outlook and IMAP-family acquisition remains non-authoritative unless a later provider-specific acquisition contract proves the exact trusted producer boundary;
- authenticated mailbox/API access alone is not sufficient;
- guessed provider hostnames/authserv IDs are not sufficient;
- ARC does not bypass the provenance or author-alignment boundaries.

A future provider-specific change that marks live Authentication-Results trusted must receive its own reviewed producer proof, regression contract, full gate and live acceptance where applicable.

## Regression expectations

Automated tests must prove at minimum:

1. trusted DMARC pass authenticates the From organizational domain.
2. trusted explicit DMARC failure cannot be overridden by apparently aligned underlying mechanism metadata.
3. trusted but unrelated SPF MAIL FROM pass does not authenticate From.
4. trusted but unrelated DKIM `header.d` pass does not authenticate From.
5. trusted aligned SPF/DKIM identities remain usable when DMARC status is unavailable.
6. a passing result cannot borrow an aligned identity from another failed result.
7. unrelated mechanism success cannot suppress credential-phishing evidence.
8. unrelated mechanism success cannot unlock bounded-partial Safe.
9. legitimate trusted aligned authentication still preserves the bounded-content Safe path.
10. untrusted Authentication-Results cannot enter these alignment semantics at all.
11. no network, persistence, browser, provider-permission or community-report expansion is introduced.

Primary standards basis: RFC 7489 Section 3.1 (Identifier Alignment) and RFC 8601 Authentication-Results trust/provenance plus SPF `smtp.mailfrom` and DKIM `header.d` properties.
