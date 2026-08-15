# REG-085 — Report Scam / Provider Disposal Separation

Status: **LOCKED**

Historical disposal rule: **SUPERSEDED BY REG-089**

## Historical contract

REG-085 previously required **Report Scam to Email Shield** to save local/community threat learning while leaving the current provider message in place. Trash and Spam/Junk were separate explicit disposal actions.

That historical disposal rule was intentionally changed by the product owner for the consumer desktop release. REG-085 remains locked as historical governance and must not be used to revert the newer account-local disposal behavior.

## Preserved boundaries

The parts of REG-085 that protected scope and privacy remain mandatory under REG-089:

- a report is still account-local authority first;
- one user's report still cannot publish a global Confirmed Threat;
- community thresholds, independent-reporter requirements, time-spread corroboration and trusted human review remain unchanged;
- Family Shield and community submissions remain privacy-reduced;
- Spam/Junk remains a distinct provider action and does not become a community report;
- provider failure must never roll back the saved local campaign rule.

## Superseding behavior

REG-089 makes an explicit user Report Scam decision also own **reversible Trash disposal for that user's mailbox**: the reported current message is moved to Trash, and later messages matching the locally reported campaign are eligible for the existing durable account-local automatic Trash path. Exact sender/domain blocks retain their existing current-message and future-match Trash behavior.

See `.engineering/REG-089_CONSUMER_REPORT_BLOCK_AUTO_TRASH.md`.
