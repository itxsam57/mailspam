# Rebuild status

This package is the first transport-architecture rebuild after the repeated lag/zero-message/failed-stop failures.

## Implemented

- Dedicated killable Worker thread per scan
- Cooperative cancellation plus forced termination after one second
- Operation-scoped provider adapters; no shared connected adapter lifecycle
- Actual IMAP UID search and UIDVALIDITY-aware cursors
- Bounded 32 KiB IMAP message prefix instead of unrestricted full source/attachments
- Partial verdict protection for bounded/truncated messages
- Stable encoded IMAP action identifiers
- Gmail fetch concurrency limited to four
- Opaque Microsoft Graph continuation URLs retained unchanged
- Localhost-only server binding by default
- Live iCloud, Yahoo and generic IMAP connection forms
- Evidence-description HTML escaping
- Build/start/verify scripts
- Architecture regression tests

## Deliberately not claimed complete

- Gmail and Outlook browser OAuth onboarding is not yet exposed in the normal UI.
- Full dependency installation and Vitest execution could not be completed in the build environment because npm downloads timed out.
- Real provider behavior must be hard-tested using the included guide.

Run `npm install`, then `npm run verify`, then `npm run dev` on the test PC.
