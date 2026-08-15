# REG-084 — Global Shield Retained Review Reputation

Status: **LOCKED**

## Defect

Reporter-history confidence was stored as increment-only review counters. Expired reviewed campaigns removed their report evidence after the fixed retention window, but their historical reputation could survive indefinitely as long as the same pseudonymous reporter proof remained active in any newer retained campaign. A reporter arriving after a human decision could also be incorrectly treated as if that older decision had reviewed its later evidence if reputation were reconstructed from the current campaign membership alone.

That violated the intended Global Shield privacy and confidence contract: reporter history must be bounded to retained reviewed evidence and a human review may judge only evidence that actually existed when the decision was made.

## Root repair

Reporter reputation is now a derived cache of the still-retained campaigns whose review status is `approved` or `rejected`.

A reporter contributes to that derived history only when its retained report timestamp is no later than the review resolution timestamp. Therefore:

- expired reviewed evidence disappears from reputation even if the reporter remains active elsewhere;
- a reporter arriving after a review never inherits that earlier approval/rejection;
- replacing a report after the human decision cannot preserve the old reviewed contribution;
- reopening a rejected campaign to a new candidate removes the stale rejected-review contribution; and
- reputation remains bounded by retained reviewed evidence instead of becoming an independent permanent pseudonymous history ledger.

Any reputation change rebuilds the in-memory campaign metrics before status/feed decisions. Reporter reputation can modify escalation weight only. It cannot create a `Confirmed Threat`; confirmation still requires the independently corroborated temporal threshold plus an explicit trusted human approval.

## Permanent protection

- `tests/unit/globalThreatConfidence.test.ts` proves expired reviewed history is forgotten even while the same reporter proofs remain retained in newer unresolved evidence, and proves post-review arrival cannot inherit an older decision.
- `tests/unit/globalThreatReputationReviewBoundary.test.ts` uses a deliberately narrow weight threshold to distinguish the correct review-time history from the buggy retroactive-history score.
- Community retention, persistence/replay, human-review, signed-feed and capacity regressions continue to run in the full gate.

Any future implementation that keeps reputation after its retained reviewed evidence disappears, attributes a decision to evidence that arrived later, or lets reputation bypass human confirmation is a blocking regression.