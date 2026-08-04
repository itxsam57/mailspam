# Email Shield Milestone 1 – transport rebuild

This build replaces the failed shared-process scan design.

## Core decisions

- Every scan runs in a dedicated Worker thread. The Express/UI process does not connect to mail providers or parse MIME during scans.
- Stop sends cooperative cancellation and terminates the worker after one second if provider cleanup does not finish.
- Account connection validates credentials through a temporary adapter, then closes it. Scans and actions create fresh operation-scoped adapters.
- IMAP uses ImapFlow only. No hand-written IMAP response/literal parser exists.
- IMAP pagination uses actual searched UIDs and stores UIDVALIDITY in the cursor. It does not assume UIDs are continuous.
- Normal IMAP scans fetch a maximum 32 KiB RFC822 prefix per message. Large/truncated messages become Partial, never Safe.
- IMAP message action IDs are base64url JSON values, avoiding folder-name delimiter bugs.
- Gmail message downloads are bounded to four concurrent requests.
- Outlook stores and reuses the complete opaque @odata.nextLink URL.
- Server binds to 127.0.0.1 by default.

## Hard-test boundary

This package exposes real iCloud, Yahoo and generic IMAP credential forms. Gmail and Outlook OAuth browser setup remains a documented next gate; raw secrets are not requested through the ordinary UI.

## Known limitation

The 32 KiB IMAP prefix prevents large attachments from entering memory, but attachment metadata after the prefix can be incomplete. Such messages are explicitly marked Partial. A later metadata/body-structure pass can extract complete attachment metadata without downloading binary bodies.
