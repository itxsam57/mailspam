# Email Shield — Attachment Type Integrity

Status: Milestone 2 structural detection brick.

## Root cause

Every canonical attachment already carried both its filename/extension and provider-declared MIME type. The attachment-risk layer, however, classified executable, macro-enabled and archive risk from the filename extension only.

That left a provider-neutral false-negative path: active content could be named with a harmless-looking extension such as `invoice.pdf` while the same canonical attachment still declared an executable or script media type. Gmail/Outlook/raw MIME and iCloud/Yahoo/generic IMAP already preserved that media type, but the detector ignored it.

This brick activates the existing canonical signal. It does not claim that sender-supplied MIME metadata proves the underlying bytes.

## Classification rule

Filename extension remains a primary local structural signal.

The declared MIME type is used as independent risk evidence only when the filename extension does not already express the same category.

Supported categories are:

- directly executable or active/script content;
- macro-enabled Microsoft Office content;
- archive/container content already treated as low-weight archive risk by the filename path.

A matching dangerous extension and dangerous MIME type for the same category must not create duplicate risk evidence. The MIME path closes a rename/missing-extension blind spot; it is not a second score multiplier.

`application/vnd.microsoft.portable-executable` is an IANA-registered media type and is one of the standards-backed executable declarations recognized by this layer. Compatibility/legacy executable and script media types used by real mail senders/parsers may also be recognized locally.

## Filename integrity

Risk classification uses a local normalized filename view only. The canonical attachment name is not rewritten or persisted differently by this brick.

Before extension classification, the local view:

- applies Unicode NFKC compatibility normalization;
- removes Unicode bidirectional formatting/isolate controls;
- trims surrounding whitespace.

This closes simple extension-disguise variants such as compatibility full-width dots and trailing whitespace.

The presence of bidirectional filename controls is also explicit local risk evidence because those controls can visually reorder the apparent extension.

Evidence descriptions must not render attacker-controlled bidi/control characters back to the user. The filename copy used only in evidence text strips bidi/C0 controls, collapses whitespace and is bounded to 256 characters.

## Provider parity

No provider-specific attachment type detector is allowed.

Gmail/Outlook/raw-MIME paths already populate `AttachmentInfo.mimeType` from parsed MIME content.

iCloud/Yahoo/generic IMAP already populate the same canonical field from BODYSTRUCTURE.

The attachment-risk layer consumes only that canonical metadata, so the same filename/MIME pair must produce the same evidence regardless of provider.

## Network and byte boundary

This brick performs metadata-only classification.

It must not:

- fetch an attachment body solely to determine MIME/extension risk;
- introduce a full-message IMAP fallback;
- expand the QR-image fetch path;
- expand the exact attachment-hash fetch path;
- perform cloud malware scanning;
- add a provider permission;
- persist additional attachment bytes or content.

Existing bounded QR and exact-hash acquisition remain governed by their own contracts.

## Scoring boundary

A dangerous executable/script media type is scored equivalently to the existing directly executable extension signal because both represent active-content attachment risk.

A macro-enabled media type is scored equivalently to the existing macro-enabled extension signal.

An archive media type remains low-weight archive evidence, matching the existing archive-extension policy.

MIME metadata is sender supplied and therefore does not create a signed/confirmed threat by itself. Confirmed Threat remains reserved for the existing trusted signed/global rule path.

## Privacy boundary

This brick does not change the community-report schema.

Attachment MIME type and filename remain local message metadata and are not added to community indicators. Existing community reporting may still carry an exact SHA-256 attachment indicator when that separate bounded hash capability is available.

No attachment filename, MIME type, body, raw HTML or attachment content is uploaded by this feature.

## Regression requirements

The engineering gate must continue proving:

- a harmless-looking filename with a dangerous PE/executable media type produces dangerous attachment evidence;
- a renamed script media type produces the same active-content protection;
- macro-enabled and archive MIME types preserve their existing category risk when the filename extension is misleading;
- matching dangerous extension + MIME type is not double-counted for the same category;
- Unicode compatibility dots/trailing whitespace cannot bypass extension classification;
- bidi filename controls produce explicit disguise evidence;
- evidence text strips bidi/control characters instead of visually replaying the spoof;
- an ordinary `application/pdf` + `.pdf` attachment remains a negative control;
- raw MIME normalization carries the declared media type into the canonical attachment;
- IMAP BODYSTRUCTURE carries the same declared media type into the canonical attachment;
- no additional provider fetch, permission, persistence path or community field is introduced.
