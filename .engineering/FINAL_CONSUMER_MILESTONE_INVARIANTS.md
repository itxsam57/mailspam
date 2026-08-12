# Final Consumer Milestone Invariants

These invariants govern PR #69 and survive native application wrapping.

1. Existing mailbox scanning, community intelligence, personal policy, Family Shield, background protection and release lifecycle behavior may not be weakened to add consumer convenience.
2. Raw mailbox bodies, private conversations, credentials, relationship history and device secrets remain local by default.
3. Any new cross-channel analysis path must normalize into bounded evidence and reuse the same authoritative security semantics instead of creating a second independent verdict engine.
4. AI/ML modules may contribute bounded evidence or explanations but may not silently override hard deterministic threat states.
5. Hard threat states cannot be downgraded by user sensitivity profiles.
6. Family protection shares only privacy-reduced threat intelligence by default; explicit item sharing requires user consent.
7. Remote/community/account services receive only their minimum documented schemas; no feature may add a generic telemetry escape hatch.
8. New network analysis must use hardened fetch/DNS/redirect/resource boundaries and privacy-safe caching.
9. New destructive mailbox actions must be explicit, idempotent and reversible when the provider supports safe reversal.
10. Unsupported provider/platform capabilities must be reported as unavailable, never inferred as safe or complete.
11. Every workstream requires focused regression coverage followed by the unchanged complete Engineering Gate.
12. Native/store/external acceptance cannot be replaced by mocks or simulation in final milestone closure claims.
