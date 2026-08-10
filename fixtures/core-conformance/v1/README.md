# Email Shield portable-core conformance vectors v1

`vectors.json` is a deterministic, versioned bridge contract for desktop, Android and iOS shells. Every vector contains the complete bounded request accepted by `evaluatePortableCore` and the exact expected response. The five provider cases prove provider-tag parity for one adversarial message; the two extra cases lock verified-feed-unavailable behavior and personal-block precedence.

Run `npm run generate:core-vectors` after an intentional engine/contract change. `npm run check:core-vectors` regenerates the bundle in memory from the compiled production engine and fails when the committed JSON differs. Review decision changes rather than blindly accepting a regenerated file.

The vectors contain synthetic corpus identities only. They contain no real mailbox, credential, provider token, user policy or community report data.
