# RFC 8058 One-Click Unsubscribe Integrity

Status: **blocking security contract**

## Root cause

Email Shield previously offered automatic one-click unsubscribe whenever a message declared `List-Unsubscribe-Post: List-Unsubscribe=One-Click` and exposed an HTTPS `List-Unsubscribe` target.

That is not sufficient authorization for an automatic network action. RFC 8058 requires the one-click list headers to be protected by a valid DKIM signature. A header declaration without proven DKIM coverage can be injected or altered and must not authorize a POST.

## Accepted authorization boundary

Automatic RFC 8058 POST is available only when **all** of the following hold:

1. bounded raw MIME contains exactly one `List-Unsubscribe` field;
2. bounded raw MIME contains exactly one `List-Unsubscribe-Post` field;
3. the post field declares `List-Unsubscribe=One-Click`;
4. `List-Unsubscribe` contains an HTTPS target;
5. REG-066 Authentication-Results provenance is explicitly trusted;
6. trusted Authentication-Results contains `dkim=pass` with both `header.d` and `header.s`;
7. bounded raw MIME contains exactly one DKIM-Signature candidate with that normalized `d=` + `s=` identity;
8. that exact raw signature's `h=` list covers both `List-Unsubscribe` and `List-Unsubscribe-Post`.

If any condition is missing, ambiguous, malformed, or uninspectable, Email Shield must not issue an automatic one-click POST. It may still expose the already-existing manual HTTPS/mailto/footer unsubscribe action after normal target validation.

## Lossless list-header normalization

Security decisions and user-visible unsubscribe choices must not depend on a lossy structured-mail parser representation.

The bounded raw MIME header section is the authoritative source for RFC 8058 list-action metadata. All `List-Unsubscribe` URIs are preserved in canonical order so a leading `mailto:` URI cannot disappear merely because a parser retains only the HTTPS alternative.

Multiple raw fields remain available for manual action discovery but make the automatic one-click header set ambiguous and therefore unauthorized.

## DKIM correlation metadata

Email Shield does not perform a new DKIM DNS verification in this workflow. Cryptographic pass/fail validity comes only from the already-trusted REG-066 Authentication-Results boundary.

Raw MIME contributes only the minimum metadata required to identify the exact signature and prove header coverage:

- normalized `d=` domain;
- normalized `s=` selector;
- boolean indicating whether `h=` covers both required RFC 8058 headers.

The application must not retain or expose:

- `b=` signature values;
- `bh=` body hashes;
- the full `h=` signed-header list;
- raw DKIM signature text.

All parseable bounded DKIM candidates are retained for correlation, including non-covering signatures, so a duplicate `d=` + `s=` identity cannot be hidden merely because only one copy covers the required headers.

## Ambiguity and resource limits

Automatic authorization fails closed when:

- two or more raw DKIM signatures share the trusted passing `d=` + `s=` identity;
- the trusted passing result omits `header.d` or `header.s`;
- trusted identity and raw signature identity differ;
- either required header is absent from `h=`;
- raw list-header fields are duplicated;
- the bounded raw header section cannot be fully located;
- more than 16 DKIM-Signature fields are present;
- any DKIM-Signature exceeds the 16 KiB unfolded inspection limit;
- the raw header section exceeds the 128 KiB inspection boundary before the header/body terminator.

A partially inspected DKIM set is never sufficient for automatic action. Manual unsubscribe remains the safe fallback.

## Existing action protections remain mandatory

This authorization gate is additional to, not a replacement for, the existing unsubscribe action controls:

- the browser requires explicit user confirmation before the POST request;
- one-click targets require credential-free standard-port HTTPS;
- local/private/link-local/reserved destinations are rejected;
- DNS resolution is pinned to a validated public address for the request;
- no mailbox cookies or authorization context are sent;
- the request body is exactly `List-Unsubscribe=One-Click`;
- only 2xx responses are considered success;
- redirects are not silently followed as success;
- the request has a bounded deadline;
- browser output never receives the internal DKIM correlation metadata.

## Provider boundary

This brick does not mark any live Gmail, Outlook, iCloud, Yahoo, or generic IMAP Authentication-Results as trusted. REG-066 still governs that decision.

Therefore a live provider path cannot offer cryptographically authorized one-click solely because the message contains DKIM/List-Unsubscribe headers. A future provider-specific provenance implementation must first prove the exact receiver-controlled Authentication-Results producer boundary.

## Regression requirements

Automated tests must prove at minimum:

1. trusted exact DKIM `d=` + `s=` correlation with both headers covered enables one-click;
2. missing coverage of either required header falls back to manual;
3. untrusted Authentication-Results falls back to manual;
4. mismatched domain or missing selector falls back to manual;
5. ARC pass cannot substitute for DKIM pass;
6. duplicate same-identity signatures fail closed, including one covering and one non-covering copy;
7. DKIM count/size/header-section limit exhaustion fails closed;
8. multi-URI `List-Unsubscribe` values are preserved losslessly;
9. duplicate raw list-header fields disable automatic action while preserving manual targets;
10. signature/body-hash/full-h metadata never enters canonical/browser output;
11. existing browser confirmation and hardened POST behavior remain locked;
12. full Windows/macOS/Ubuntu engineering gates remain green.

## Non-goals

This change does not:

- add DNS/provider API calls for DKIM verification;
- widen mailbox or OAuth permissions;
- change provider authentication provenance;
- change mailbox state outside the existing unsubscribe workflow;
- persist raw DKIM data;
- change community-report schemas;
- claim live Outlook acceptance;
- close deployment/live GAP-001/002/004/005/008.
