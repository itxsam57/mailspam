# Community Feed Rollback Integrity

## Threat

Ed25519 verification proves who signed a feed and freshness proves it has not expired. Neither property alone stops a compromised cache, proxy or feed origin from replaying an older but still-fresh correctly signed document after a client has already accepted a newer generation.

## Contract

- Signature, trusted key, schema, byte/resource limits and freshness are verified before rollback state is consulted.
- The client stores only the accepted feed generation timestamp, canonical SHA-256 payload digest and bounded signing-key identities. No rules, indicators, reports or mailbox data enter the checkpoint.
- The checkpoint is AES-256-GCM encrypted with a separate owner-only installation key and replaced atomically.
- A generation older than the accepted checkpoint is rejected.
- A different payload at the same generation timestamp is rejected as signer/origin equivocation.
- The exact same payload at the same generation may be signed by more than one already-trusted key, preserving the reviewed overlap-key rotation sequence.
- A newer valid generation advances the checkpoint. Legitimate rule additions and removals therefore require a strictly newer signed generation.
- The guard runs when loading the verified offline cache and on every remote refresh, so rollback protection survives process restart.
- On rejection, the last still-fresh verified cache remains active. If the checkpoint is unreadable, acceptance fails closed.

This protects against remote/cache replay. It does not claim resistance to an attacker who can fully replace the user account's protected local files and keys.
