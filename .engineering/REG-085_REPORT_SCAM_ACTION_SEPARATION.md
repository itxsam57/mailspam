# REG-085 — Report Scam / Provider Disposal Separation

Status: **LOCKED**

## Defect

The Report Scam route had accumulated a second responsibility: after committing local campaign protection it also invoked the provider Trash mutation. That made the visible Report Scam, Trash and Spam/Junk controls look separate while the server silently coupled reporting to disposal. It also contradicted the owner acceptance contract that a controlled report leaves the current provider message unchanged unless disposal is separately requested.

## Root repair

Report Scam now owns only the threat-learning transaction:

- persist the account-local reported-campaign rule;
- optionally persist the exact-sender block when the user explicitly chooses it;
- submit the privacy-reduced Family Shield campaign signal when applicable; and
- submit/queue privacy-reduced community evidence.

It does **not** call the provider Trash or Spam/Junk mutation. The response explicitly reports `movedCurrent: false` and `providerAction: "none"`. The browser tells the user before and after reporting that the current message stays in place and that disposal requires the separate Trash or Move to Spam/Junk action.

The existing protection capability is preserved: the durable local campaign rule still classifies later matching campaign mail as locally Confirmed Threat according to the personal-policy engine. Global auto-disposition authority remains governed independently by the existing durable-protection rules and signed Global Shield review boundary.

## Permanent protection

- `tests/unit/protectionActions.test.ts` proves Report Scam persists protection/family/community outcomes without invoking the adapter Trash operation, including Family Shield failure.
- `tests/unit/reportScamActionSeparation.test.ts` slices the canonical Report Scam route and rejects any future `moveCurrentMessageToTrash()` ownership; it also locks the browser disclosure that Report Scam does not move mail.
- Existing Block, Trash and Spam/Junk tests continue to prove that their provider mutations still work, so this regression lock cannot be satisfied by removing disposal capability from the product.

Any future implementation that couples Report Scam to a provider move, disguises a move inside another reporting side effect, or removes the separate disposal capabilities is a blocking regression.
