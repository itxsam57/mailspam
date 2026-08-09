# Email Shield — Bounded HTML Interaction Normalization

Status: Milestone 2 structural detection brick.

## Root cause

Email Shield previously discovered HTML destinations with a quoted-anchor regular expression. That meant the canonical message envelope could miss browser-relevant destinations expressed through valid unquoted attributes, security-relevant HTML entities, BASE-relative links, form/formaction submissions and META refresh redirects. Plain-text URLs could also be missed when the same MIME message contained an HTML alternative.

The downstream Link Structure, signed Global Intelligence and privacy-reduced community fingerprint/report paths all consume `CanonicalEnvelope.links`. Missing the destination at canonical normalization therefore created a shared structural false-negative path rather than an isolated scoring defect.

`htmlSignals.hasForm` and `htmlSignals.hasPasswordField` were also observed but had no production scoring consequence.

This brick fixes the observation boundary once and keeps every provider on the existing canonical pipeline.

## Non-executing parser boundary

HTML interaction analysis is local and deterministic. Email Shield must never execute or render attacker HTML as part of detection.

The normalizer must not:

- execute JavaScript or other active content;
- submit a form;
- follow an HTML redirect;
- load images, frames, stylesheets, fonts, scripts or other remote resources;
- send cookies, mailbox authorization, provider credentials or browser state;
- infer a destination origin for a relative URL when no accepted HTTP(S) BASE exists;
- turn a malformed/uninspected destination into positive clean evidence.

SCRIPT and STYLE contents are raw-text regions for this inspection. Markup-looking strings inside them are inert and must not be reinterpreted as anchors, forms or redirects.

Remote-resource attributes such as image/frame/script `src` are intentionally outside this brick. They are common tracking/rendering resources rather than explicit user-action destinations and broadening automatic mailbox scanning to them would add noise and privacy/network pressure without a reviewed product requirement.

## Canonical destination forms

The bounded normalizer recognizes browser-relevant interaction destinations from:

- `<a href>`;
- `<area href>`;
- `<form action>`;
- `<button formaction>`;
- `<input formaction>`;
- `<meta http-equiv="refresh" content="...;url=...">`;
- visible plain-text `http://`, `https://` and `www.` URLs, including a text MIME alternative that accompanies HTML.

Attributes may be quoted or unquoted. Numeric entities and a deliberately bounded set of security-relevant named entities are decoded before URL normalization so entity obfuscation cannot trivially bypass the canonical link path.

A relative destination may be resolved only against the first structurally valid HTTP(S) `<base href>` without URL userinfo. Without such a BASE, Email Shield preserves the relative value as unresolved/malformed evidence rather than inventing a provider, mailbox or webmail origin.

Protocol-relative destinations are normalized to HTTPS for deterministic host extraction. This does not perform a network request.

## Interaction provenance

Body links may carry one of these canonical interaction values:

- `navigation` — ordinary anchor/area/plain-text navigation;
- `form_action` — a form or form-control submission target;
- `automatic_redirect` — a META refresh destination.

QR destinations remain separately identified by `source: "qr"` and do not become HTML form/redirect evidence.

The interaction marker is structural provenance only. It does not by itself confirm maliciousness.

## Resource bounds

The same normalization rules apply regardless of provider because Gmail, Outlook, fixture/raw-MIME and bounded IMAP synthetic MIME converge on the canonical MIME normalizer.

Accepted inspection limits are:

- maximum 512 KiB of decoded HTML for interaction parsing;
- maximum 512 KiB of decoded plain text for companion URL discovery;
- maximum 4096 parsed HTML tags;
- maximum 256 unique canonical message interaction destinations;
- maximum 512 characters of visible anchor text retained for link comparison.

If any accepted content/tag/destination bound prevents complete interaction inspection, canonical normalization must mark the message `partial`, record only generic privacy-safe reasons and set content coverage to `insufficient`. The verdict engine must therefore block an automatic Safe result rather than silently treating the uninspected tail as clean.

Reaching exactly a limit is not incomplete when no additional unique interaction exists. Discovering an additional unique destination beyond the accepted maximum is incomplete even though that destination is not retained.

## Structural scoring

This brick does not add brand-specific keyword rules or lower confirmation thresholds.

An embedded password form is local structural evidence:

- password form with no captured submission target: score contribution 2;
- password form with a canonical submission target: score contribution 3.

This is Review-weight evidence and cannot by itself produce Confirmed Threat.

A META refresh destination adds low-weight `AUTOMATIC_HTML_REDIRECT` evidence. Form-action and automatic-redirect destinations are considered sensitive interactions by the existing authenticated cross-domain link rule, so a submission/redirect that leaves the authenticated sender organization can combine with existing structural evidence.

Existing raw-IP, punycode, unsafe-scheme, shortener, unusual-port and displayed-vs-actual-domain checks continue to apply to the canonical destinations.

## Signed intelligence and community privacy

No new threat-feed or reporting protocol is introduced.

The existing Global Intelligence layer consumes every canonical link, so a verified signed exact-URL or destination-domain indicator naturally applies to anchor, form-action and META-refresh destinations.

The existing community fingerprint/report path continues to reduce canonical destinations to permitted domain indicators. It must not upload or persist:

- raw message HTML;
- form field values;
- URL paths, query strings or fragments;
- passwords or other submitted values;
- subject/body content merely because a form exists;
- provider credentials, provider-native identifiers or mailbox identity.

A form destination such as `https://example.test/private/login?token=secret` may contribute only the already-permitted privacy-reduced destination domain to community reporting.

## Provider and persistence boundary

This brick requires no new mailbox permission, provider endpoint, remote request, database, encryption migration or background service.

No HTML body or interaction parser state is added to scan history, relationship history or personal-policy persistence. Canonical current-message link evidence keeps the same lifetime as existing body/QR link evidence.

Live IMAP keeps its existing selected-part/full-message restrictions; this brick analyzes only the bounded readable text/HTML already admitted through the canonical MIME path.

## Regression requirements

The blocking engineering gate must continue proving:

- unquoted anchor destinations reach canonical link analysis;
- numeric/security-relevant entity obfuscation is normalized before structural comparison;
- relative links resolve only through an accepted HTTP(S) BASE;
- plain-text URLs remain visible when an HTML MIME alternative also exists;
- form/formaction destinations enter the canonical link path with `form_action` provenance;
- embedded password forms produce only bounded structural evidence;
- META refresh destinations enter the canonical link path with `automatic_redirect` provenance without being followed;
- unsafe schemes carried through HTML attributes remain visible to the existing unsafe-scheme detector;
- signed destination intelligence can match form/redirect destinations through the existing Global Intelligence path;
- community reports remain destination-domain reduced and exclude raw form URL path/query data;
- SCRIPT/STYLE raw text cannot manufacture active link/form evidence;
- 512 KiB HTML, 512 KiB plain-text, 4096-tag and 256-destination limits are enforced and incomplete coverage blocks automatic Safe;
- a 257th plain-text or HTML interaction cannot disappear silently at the exact destination bound;
- ordinary authenticated same-organization HTML does not gain interaction warnings merely for containing a normal link;
- MIME/link normalization remains free of compiled brand/domain mappings;
- the full provider corpus, Worker runtime, browser checks and server/community smoke continue to pass on Windows, macOS and Ubuntu.
