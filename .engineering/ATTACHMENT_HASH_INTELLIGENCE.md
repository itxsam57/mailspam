# Email Shield — Bounded Attachment Hash Intelligence

Status: Milestone 2 structural detection brick.

## Root cause

Email Shield already had an `attachment_hash` signed/community indicator type, matched signed feed entries against `CanonicalEnvelope.attachments[].sha256`, and allowed privacy-reduced attachment hashes in community reporting. Production normalization, however, populated every attachment hash as `null`. The intelligence type therefore existed in the protocol and scoring layer without a real production observation path.

This brick activates that existing capability without turning normal mailbox scans into unrestricted attachment processing or downloads.

## Exact-hash rule

An attachment hash is valid only when Email Shield has the complete decoded attachment bytes. The value is SHA-256 over those decoded bytes.

Email Shield must never:

- hash a truncated prefix and present it as the attachment hash;
- infer a hash from filename, MIME type, provider metadata or size;
- treat missing hash coverage as proof that no signed attachment rule matches;
- upload or persist attachment bytes merely to calculate the hash.

## Provider-neutral resource bounds

The exact-hash workload is bounded the same way regardless of provider:

- maximum 4 attachment hash inspections per message;
- maximum 2 MiB decoded attachment bytes per inspected attachment.

An attachment beyond either bound remains unhashed. The bound is about deterministic local resource use as well as network privacy, so Gmail/Outlook/raw-MIME providers do not receive an unlimited exception merely because their bytes are already local.

## Gmail, Outlook and fixture/raw MIME providers

These providers already supply the complete raw RFC message to the existing MIME normalizer. `mailparser` therefore already materializes decoded attachment bytes as part of the accepted provider path, including MIME parts represented as inline attachments.

For the first four attachments whose complete decoded bytes are at most 2 MiB each, Email Shield hashes the bytes already present locally. Hashing introduces no additional provider request and no external network lookup. Excess-count or oversized attachments remain unhashed and are represented only through privacy-reduced incomplete coverage.

## iCloud, Yahoo and generic IMAP

The existing IMAP architecture deliberately avoids full-message downloads and selects MIME parts. Exact attachment hashing is therefore a separate bounded acquisition path, not an excuse to fetch the complete RFC message.

IMAP attachment classification must stay aligned with the raw-MIME path: non-text leaf MIME parts, explicit attachments, and named inline text parts are canonical attachment candidates. A MIME node classified as an attachment cannot simultaneously become the selected readable body. This prevents provider-specific hash blind spots and prevents inline attachment text from being mistaken for the email body.

In addition to the provider-neutral 4-attachment / 2 MiB decoded limits, live IMAP applies:

- a bounded encoded MIME-part fetch sized for transfer-encoding overhead;
- one 20-second attachment-hash MIME-part acquisition deadline per message;
- no full-message/raw-source fallback;
- no retry that converts an oversized, truncated or undecodable part into a guessed hash.

If the body structure does not expose an addressable attachment MIME part, the attachment remains unhashed.

If a declared or decoded attachment exceeds the bound, the attachment remains unhashed.

If the bounded provider response reaches its encoded cap, fails to decode completely or is not returned, the attachment remains unhashed.

If the provider returns fewer MIME-part octets than BODYSTRUCTURE declared, the response is treated as incomplete and is never hashed as though it were the complete attachment.

## QR byte reuse

PNG/JPEG attachments may already have been fetched under the independent bounded local QR-inspection path. When that exact MIME part has already yielded complete local image bytes within the attachment-hash limit, Email Shield hashes those same bytes instead of downloading the attachment a second time.

QR parsing and exact attachment hashing remain separate capabilities. Reuse is only an acquisition optimization; the SHA-256 is still computed over the complete decoded attachment bytes.

## Privacy boundary

Attachment bytes are transient process memory only for this capability.

The canonical envelope may retain:

- attachment metadata already permitted by the current-message model;
- the SHA-256 value when complete eligible bytes were available;
- privacy-reduced coverage counts and generic incomplete reasons.

The hash coverage diagnostic must never include attachment names, raw attachment bytes, message bodies, provider credentials or provider-native identifiers.

Community report context may contain the SHA-256 indicator because the existing privacy contract explicitly permits attachment hashes. It must not contain the attachment name or attachment content.

Relationship history, scan history and personal-policy persistence must not acquire attachment bytes through this capability.

## Signed-feed behavior

A matching verified signed `attachment_hash` rule uses the existing Global Intelligence warning/confirmed-threat semantics.

If the verified feed contains one or more attachment-hash rules and a message contains an attachment that could not be completely hashed within the accepted local bounds, Global Intelligence is marked incomplete and blocks an automatic Safe verdict. This is a fail-closed coverage decision, not positive threat evidence.

If the verified feed contains no attachment-hash rules, incomplete hash coverage does not independently make Global Intelligence incomplete. The unavailable capability is irrelevant to the current signed rule set in that case.

## Regression requirements

The engineering gate must continue proving:

- complete eligible raw-MIME attachment bytes produce the expected SHA-256;
- raw-MIME providers obey the same 4-attachment and 2 MiB decoded-byte exact-hash limits;
- an exact verified confirmed attachment-hash rule can produce a confirmed global match;
- community reporting includes only the permitted hash, not attachment names or bytes;
- missing hash coverage blocks automatic Safe only when verified attachment-hash intelligence is actually present;
- live IMAP requests only selected attachment MIME parts for hashing;
- IMAP inline attachment classification remains aligned with raw-MIME attachment behavior and does not steal named inline text into readable-body selection;
- live IMAP never uses full RFC822/raw-source fallback for attachment hashing;
- a part that reaches the bounded encoded fetch cap is not hashed as though complete;
- a provider-returned MIME part shorter than its BODYSTRUCTURE declaration is not hashed as a complete attachment;
- QR image bytes already acquired locally are reused instead of fetched twice;
- malformed or undecodable attachment parts remain unhashed rather than crashing the scan or manufacturing a hash;
- privacy-reduced diagnostics contain counts/generic reasons only.
