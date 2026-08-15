# REG-089 — Consumer Report / Block Account-Local Auto-Trash

Status: **LOCKED**

## Consumer contract

An explicit user **Report Scam to Email Shield** decision is authoritative for that connected mailbox account. Email Shield must first persist the account-local reported-campaign rule and then request a reversible provider Trash move for the currently reported message. Later messages that match the locally reported campaign must remain eligible for the existing durable automatic Trash path for that same account.

An explicit **Block Sender** or permitted **Block Domain** decision keeps its existing behavior: save the account-local personal block, move the current selected message to Trash, and make later matching messages eligible for durable automatic Trash for that account.

## Scope boundary

This local disposal authority must never be confused with Global Shield publication authority.

- One user report cannot create a network Confirmed Threat for other users.
- Global candidate/warning/confirmed thresholds remain unchanged.
- Independent-reporter, time-spread and trusted human-review requirements remain unchanged.
- A Global/Family warning never inherits local Trash authority.
- Privacy-reduced Family/community reporting remains separate from provider disposal.
- Spam/Junk remains a separate explicit provider action and never silently creates a scam report.

## Failure behavior

The personal policy transaction is committed before the provider move. If the provider cannot move the current message, the route must report the partial result truthfully and must not roll back the local campaign/block rule. Future matching messages therefore remain protected and the current message can be retried through normal provider disposal controls.

## Permanent protection

- `tests/unit/protectionActions.test.ts` proves Report Scam persists local protection and moves exactly the selected provider message, including Family failure and provider-move failure cases.
- `tests/unit/reportScamActionSeparation.test.ts` locks policy-before-provider ordering, the account-local Trash response contract and the unchanged Global Shield threshold disclosure.
- `tests/unit/durableProtection.test.ts` proves `BLOCKED_SENDER`, `BLOCKED_DOMAIN` and `LOCALLY_REPORTED_SCAM_CAMPAIGN` are durable automatic Trash authority while warning/heuristic verdicts are not.
- Browser review-action tests and the full Windows/macOS/Ubuntu Engineering Gate remain release blockers.

Any future change that leaves a successfully reported current message in Inbox by design, stops locally reported campaign/block matches from durable account-local Trash, or lets one user's report bypass Global Shield thresholds is a blocking regression.
