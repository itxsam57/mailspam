# Email Shield — Milestone 1

Local-first email scam detection engine. Runs entirely on your machine; no
message content is ever sent anywhere.

## Run it

```bash
npm install
npm run test          # full test suite (22 tests, includes 56-fixture scam corpus x 5 providers)
npm run dev            # starts the server + dashboard at http://localhost:4173
```

Open http://localhost:4173, click **Connect** with "Fixture demo mailbox"
selected (no credentials needed) — this loads the synthetic scam corpus so
you can see the whole engine working immediately. Click **Quick Scan** to
see it flag the malicious fixtures live.

## Connecting your real inbox

Select "Live account" and the provider. Credentials needed:

- **Gmail**: OAuth `clientId` / `clientSecret` / `refreshToken` with
  `gmail.readonly` (+ `gmail.modify` if you want the Trash action) scopes.
- **Outlook**: Azure app registration `clientId` / `clientSecret` /
  `tenantId` / `refreshToken` with `Mail.ReadWrite` scope.
- **iCloud / Yahoo**: your email address + an **app-specific password**
  (not your account password — both providers require this for IMAP).
- **Generic IMAP**: host/port/user/app-password for any other provider.

This sandbox couldn't test these against real mailboxes (no live
credentials, and network egress here is locked to package registries) — the
adapters are fully implemented and type-checked, but exercising them
against your actual inbox is the first real-world test.

## What's built (Milestone 1)

- 9 of 11 detection layers (destination classification is correctly gated
  to the explicit "Analyze Links" action only, never automatic — see
  `server/src/engine/layers/destinationClassification.ts`)
- Shared canonical MIME normalizer used identically by all 5 providers
- Quick / Full Mailbox / Spam scans with real cancellation, cursors, dedup
- Block sender/domain, batched Trash moves, RFC 8058 one-click unsubscribe
- Developer Testing Suite (`GET /api/dev/test-suite`, also a dashboard button)
- 56-fixture synthetic scam corpus, all 16 categories from spec Section 6

## Known limitations to flag before Milestone 2

- Live adapters are untested against real mailboxes (see above)
- Destination classification's hardened resolver (`hardenedFetch.ts`) is
  implemented but untested against real URLs for the same reason
- QR code decoding is stubbed behind an injectable `decodeQr` function —
  no real image/QR library is wired in yet
- Community reporting aggregation (Layer 10) is explicitly Milestone 2 scope
