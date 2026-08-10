# Authentication-Results Provenance Boundary

Status: **blocking security contract**

## Root cause

Email Shield already required RFC5322.From alignment before treating SPF/DKIM as author authentication, but the canonical authentication object could still be populated from an arbitrary MIME `Authentication-Results` header without proving that the header came from the receiving system's trusted authentication service.

That is unsafe in both directions:

- forged `pass` results can manufacture authenticated identity, suppress phishing evidence, unlock bounded-content Safe prerequisites, or create trusted relationship history;
- forged `fail` results can manufacture transport-auth threat evidence or relationship authentication downgrades.

Authenticated mailbox/API acquisition proves access to the mailbox. It does **not** by itself prove which `Authentication-Results` instance was generated inside the receiver's trusted administrative boundary.

## Accepted boundary

The only application-level provenance predicate is:

```ts
authenticationResultsTrusted(envelope) ===
  envelope.authentication.providerTrust === "trusted"
```

Anything else — missing, `unknown`, or `suspicious` — is non-authoritative.

When provenance is non-authoritative:

1. DMARC pass does not authenticate RFC5322.From.
2. SPF/DKIM pass does not authenticate the visible author, even when the identities appear aligned.
3. DMARC/SPF/DKIM fail does not create transport-auth threat evidence.
4. ARC does not create sender authentication and does not bypass provenance.
5. authenticated organizational identity and private-relay identity are unavailable.
6. authentication-derived message-intent/link suppressions and bounded-content Safe prerequisites are unavailable.
7. relationship history does not record the message as authenticated.
8. relationship history does not create an authentication-downgrade signal.
9. the transport-auth layer reports authentication inspection incomplete rather than converting untrusted results into facts.

This boundary does not make authentication mandatory for every Safe verdict. A fully inspected message may still resolve from the rest of the deterministic evidence pipeline; untrusted authentication simply cannot grant or remove trust.

## Who may establish `trusted`

Trust belongs to the acquisition/normalization boundary, never to arbitrary MIME content and never to a downstream detector.

A production adapter may set `providerTrust: "trusted"` only when its implementation can prove that the exact Authentication-Results data being consumed was produced by a receiver-controlled authentication service inside a documented and regression-locked trust boundary.

The following are **not sufficient** on their own:

- successful Gmail API authentication;
- successful Microsoft Graph authentication;
- successful IMAP authentication;
- the presence of an `Authentication-Results` header;
- a guessed provider hostname or guessed `authserv-id`;
- an ARC pass;
- provider branding or sender domain heuristics.

Therefore current live Gmail, Outlook, iCloud, Yahoo and generic IMAP raw-MIME paths remain non-authoritative for Authentication-Results unless a later provider-specific acquisition contract proves otherwise.

## Controlled fixtures

Synthetic fixture messages may explicitly set provenance because the fixture generator itself acts as the controlled receiving system.

The generated scam corpus stores `authenticationTrust` in its manifest. Every consumer — integration corpus, demo mailbox and compiled developer suite — must consume that exact field. Consumers may not infer fixture trust from provider, category, malicious/legitimate kind, verdict, or header contents.

Ad-hoc fixture messages default to `unknown` unless the test explicitly opts into trusted synthetic authentication.

## Centralized consumers

The provenance predicate is shared by:

- `identitySignals.ts` for positive author/organizational/relay authentication;
- `transportAuth.ts` for negative authentication evidence;
- `relationshipHistory.ts` for authenticated history and downgrade detection;
- downstream identity/message/link layers through those shared helpers.

New authentication consumers must reuse the same predicate/helper boundary rather than inspecting raw SPF/DKIM/DMARC values directly to grant or remove trust.

## Regression requirements

The suite must prove at minimum:

- untrusted DMARC pass cannot authenticate the author;
- untrusted aligned SPF/DKIM cannot authenticate or unlock bounded-content Safe;
- untrusted failures cannot create transport evidence;
- untrusted failures cannot create relationship downgrade;
- untrusted passes cannot create authenticated relationship history;
- trusted pass/fail semantics still work;
- ARC cannot bypass provenance/alignment;
- missing provenance remains non-authoritative;
- fixture trust is explicit per message;
- all generated-corpus consumers use the manifest provenance field;
- the full multi-provider corpus and compiled developer suite preserve zero false positives/false negatives under their existing acceptance contract.

## Non-goals

This change does not:

- discover trusted Gmail/Microsoft/Yahoo/iCloud authserv IDs;
- add DNS, provider API or network lookups;
- widen mailbox permissions;
- change OAuth scope/custody;
- change persistence/community schemas;
- claim live Outlook acceptance;
- claim production Gmail consent acceptance;
- treat ARC as DMARC/sender authentication.

A later provider-specific provenance implementation is a security-boundary change and requires its own documented producer proof, focused regressions, full three-platform gate and live acceptance where applicable.
