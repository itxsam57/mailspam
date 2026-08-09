# Email Shield — Production QR Decoder Security Contract

Status: Milestone 2 / GAP-006 implementation contract.

## Scope

Email Shield performs QR inspection locally and offline. The production decoder supports PNG and JPEG image content. This closes the former missing-decoder gap; it does not claim universal image-format support.

Supported image content is inspected only when it is already locally available through a provider's bounded message path:

- Gmail, Outlook and fixture MIME parsing inspect supported image attachments already present in the local MIME parser output.
- iCloud, Yahoo and generic IMAP inspect BODYSTRUCTURE and fetch only selected bounded PNG/JPEG body parts in a separate provider request.

No QR image or QR payload is sent to an external image, OCR, redirect or QR-decoding service.

## Hard resource bounds

The decoder must preserve all current limits unless a reviewed change adds stronger protection:

- maximum 4 supported QR-capable images inspected per message;
- maximum 2 MiB encoded image content per image;
- maximum 4096 pixels on either image dimension;
- maximum 4,000,000 decoded pixels;
- maximum 4096 characters of decoded QR payload text.

PNG dimensions are checked from the IHDR header before decompression. JPEG dimensions are checked from a Start-of-Frame marker before pixel decoding. Malformed images and invalid dimensions must fail without crashing the scan process.

## Accepted QR destinations

A QR payload becomes canonical link evidence only when it parses as an HTTP or HTTPS URL. URLs containing embedded username/password credentials are rejected. Non-URL QR payloads remain non-link data and are not promoted into canonical URL evidence.

A decoded QR URL uses the existing canonical `LinkInfo` contract with `source: "qr"`. It then passes through the same deterministic link/destination evidence layers as a normal URL. QR presence itself contributes local attachment risk because the visible destination is obscured from the user, but it does not by itself claim the destination is globally confirmed malicious.

## Privacy boundary

Raw image bytes are transient decoder input only. They must never be added to:

- `CanonicalEnvelope.attachments`;
- browser/SSE scan payloads;
- scan history or resumable checkpoints;
- relationship history;
- personal policy persistence;
- community report payloads or outbox entries;
- logs or error responses.

The canonical message may retain only normal attachment metadata, decoded URL evidence and privacy-reduced QR inspection diagnostics.

## IMAP acquisition boundary

IMAP/iCloud/Yahoo continue to avoid generic attachment-body downloads. QR inspection may fetch only selected PNG/JPEG MIME body parts and only under the encoded-size/count/time limits. PDF, archive, executable and unsupported image bodies are not downloaded by this path.

Transfer encoding is decoded locally after the bounded provider part is returned. The complete RFC822 message source is never fetched merely for QR analysis.

## Incomplete inspection

A supported PNG/JPEG image that should be inspected but is malformed, exceeds a local image/decode limit, is not returned by the provider, or cannot be MIME-decoded marks QR inspection incomplete. The attachment/QR layer then blocks an otherwise automatic Safe verdict rather than silently treating the supported image as clean.

The current production format scope is PNG/JPEG. Other image formats are not represented as successfully QR-inspected and are not claimed by GAP-006 closure. Adding another supported format requires a bounded local decoder, adversarial resource tests and an update to this contract.

## Provider permissions

QR decoding must not add mailbox permissions. It reuses content already authorized by the existing Gmail/Outlook mailbox scopes or bounded IMAP access. No QR-specific cloud service credential is permitted.

## Regression requirements

The engineering gate must continue proving:

- real PNG QR URL decoding;
- real JPEG QR URL decoding;
- non-URL QR content does not become link evidence;
- credential-bearing QR URLs are rejected;
- encoded-size, dimension, pixel and per-message count limits;
- malformed image input does not crash the process;
- supported image decode failure blocks an automatic Safe verdict;
- canonical/browser contracts never contain raw image bytes;
- IMAP selects/fetches only bounded supported image parts and not PDF/full-message content;
- no external network call exists in the QR decoder;
- provider OAuth/API permission contracts are unchanged;
- the full five-provider corpus and compiled Worker/server gates remain green.
