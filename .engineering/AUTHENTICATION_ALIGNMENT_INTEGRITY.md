# Authentication Alignment Integrity

## Accepted security boundary

Email Shield must distinguish **authentication mechanism success** from **authentication of the visible RFC5322.From author domain**.

SPF authenticates an SMTP identity (`smtp.mailfrom` or, in limited cases, HELO). DKIM authenticates the signing domain reported as `header.d`. Either mechanism may pass for a domain unrelated to the visible author. A bare `spf=pass` or `dkim=pass` therefore MUST NOT create organizational sender trust, suppress phishing evidence, establish relay-origin trust, or unlock bounded-content Safe eligibility.

DMARC pass is sufficient for this local author-domain alignment decision because DMARC pass requires at least one successful authenticated identifier aligned with RFC5322.From. An explicit `dmarc=fail` is authoritative negative evidence for this decision and MUST NOT be overridden by locally reinterpreting an apparently aligned SPF/DKIM property.

Only when DMARC is unavailable or reports `none` may Email Shield recover author alignment from the already-present canonical `authentication.rawHeader`:

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

The existing transport-auth layer may continue to report SPF/DKIM/DMARC mechanism outcomes independently. This contract only governs places where Email Shield treats a sender organization as authenticated or uses authentication as a prerequisite for Safe.

## Trust-domain limitation

RFC 8601 also requires Authentication-Results consumers to understand which upstream authentication service is inside their trust boundary. This brick does **not** claim a universal cross-provider `authserv-id` trust solution. It removes the existing false inference that any bare SPF/DKIM pass authenticates RFC5322.From while preserving the current provider-local Authentication-Results acquisition boundary. A future change to Authentication-Results provenance must receive its own reviewed regression contract.

## Regression expectations

Automated tests must prove at minimum:

1. DMARC pass authenticates the From organizational domain.
2. Explicit DMARC failure cannot be overridden by apparently aligned underlying mechanism metadata.
3. Unrelated SPF MAIL FROM pass does not authenticate From.
4. Unrelated DKIM `header.d` pass does not authenticate From.
5. Aligned SPF/DKIM identities remain usable when DMARC status is unavailable.
6. A passing result cannot borrow an aligned identity from another failed result.
7. Unrelated mechanism success cannot suppress credential-phishing evidence.
8. Unrelated mechanism success cannot unlock bounded-partial Safe.
9. Legitimate aligned authentication still preserves the bounded-content Safe path.
10. No network, persistence, browser, provider-permission or community-report expansion is introduced.

Primary standards basis: RFC 7489 Section 3.1 (Identifier Alignment) and RFC 8601 Authentication-Results properties for SPF `smtp.mailfrom` and DKIM `header.d`.