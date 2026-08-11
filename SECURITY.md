# Email Shield Security Policy

## Supported release

Security fixes are applied to the current supported release line. Repository commits and development artifacts are not a promise of a production-signed release. The signed update envelope, native package signature and published release provenance must all be verified for production distribution.

## Reporting a vulnerability

Use the repository’s private GitHub Security Advisory workflow: `https://github.com/itxsam57/mailspam/security/advisories/new`. Include affected version/commit, platform, impact, reproducible steps and the smallest safe proof. Do not include real mailbox credentials, OAuth tokens, recovery codes, private keys, private message bodies or personal data. If the private advisory workflow is unavailable, open a minimal non-sensitive issue asking the maintainer to establish a private channel; do not publish exploit details.

The project targets acknowledgement within three business days and an initial severity/next-step decision within seven business days. These are response targets, not guaranteed resolution dates. Coordinated disclosure timing depends on exploitability, affected users, provider/deployment coordination and availability of a verified update. The maintainer will credit reporters when requested and legally/safely possible.

## Release and supply-chain requirements

- Node.js 22, lockfile v3 and the exact dependency graph are gated; high/critical production advisories block release.
- The Engineering Gate runs strict type/build, portable-core dependency checks, versioned vectors/provider contracts/Regression Vault/capacity budgets, unit/integration/browser/privacy tests, compiled smokes, reproducible package verification, signed lifecycle smoke and audits.
- The portable manifest binds every file path, size, mode and SHA-256 to the commit/target/runtime/release ID. The separate Ed25519 envelope binds that manifest to a pinned one-to-four-key trust store.
- Updates must be same-target and strictly newer; every byte is verified before and after staging. Rollback re-verifies the recorded prior signed release. Torn activation fails closed.
- Production release signing keys, Authenticode/Developer ID identities and notarization/store credentials must stay outside source, build logs and CI artifacts.

## Security boundaries

The local HTTP service binds to loopback, rejects forwarded/DNS-rebinding requests, uses an HttpOnly SameSite session, CSRF proof, same-origin checks, expiring single-use mutation nonces, route limits, response redaction, CSP and anti-framing headers. These controls do not make a compromised endpoint trustworthy.

Mailbox content is normalized locally into one canonical envelope and scanned by one portable deterministic core. Unknown, partial, malformed or unavailable content cannot silently become Safe. Provider mutations and Analyze Links are explicit actions. Community intelligence must be bounded, schema-valid, fresh, trusted and Ed25519 verified; unavailable intelligence remains unavailable, not clean.

Public community operation additionally requires TLS, gateway reputation/rate/DDoS controls, secret management, monitoring, backup/restore and key-rotation ceremonies. Those deployed controls are not supplied by an application test suite.

See [THREAT_MODEL.md](THREAT_MODEL.md), [PRIVACY.md](PRIVACY.md) and [INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md) for the full model and response process.
