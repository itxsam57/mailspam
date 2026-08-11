# Regression Vault v1

Only sanitized samples approved through `npm run vault -- approve` belong here. Intake is two-stage: `intake` removes routing/contact/destination identifiers into a private local candidate directory, then a reviewer compares the exact SHA-256 digest and approves with a fixed reviewer role. Approval re-runs the expected verdict through all five fixture adapters before writing a deduplicated manifest entry.

The release gate verifies strict schema, provenance, sorting, SHA-256, placeholder-only addresses/destinations and cross-provider verdict parity. Original messages and candidate directories are never copied into this repository.
