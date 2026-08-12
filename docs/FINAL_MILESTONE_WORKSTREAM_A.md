# Workstream A — Near-Real-Time Inbound Protection

The first implementation workstream converts provider arrival/change signals into one replay-safe canonical event stream that feeds existing Email Shield protection semantics. It must not fork the scanner or verdict engine.

Acceptance requires provider-neutral event types, bounded dedupe/replay state, restart recovery, a fixture event source, focused tests, and adapters that can later bind Gmail push, Microsoft Graph notifications, IMAP IDLE and bounded polling without changing the coordinator contract.
