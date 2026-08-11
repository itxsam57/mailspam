# Email Shield Threat Model

Version: 1.0 — 2026-08-11

## Security objectives

Email Shield aims to keep mailbox secrets/content local, make every decision deterministic and explainable, prevent incomplete evidence from becoming Safe, separate user/provider/community actions, preserve account isolation, accept only authenticated signed releases/intelligence and bound attacker-controlled work and storage.

Protected assets include provider refresh tokens/app passwords; local encryption/reporter keys; personal policies, scan checkpoints and relationship aggregates; community aggregate/storage/signing state; release signing keys; update trust roots; and the integrity/availability of verdicts, actions and user safety guidance.

## Trust boundaries

1. **Email provider → adapter.** Gmail API, Microsoft Graph and IMAP/TLS data are untrusted input until bounded normalization. Authentication-Results is authoritative only with explicit trusted provider provenance.
2. **Canonical envelope → portable core.** Exact schema v1 and a 4 MiB request ceiling reject field drift, raw thread state and pathological collections. The core has no host/I/O/network/OAuth/vault/Worker dependency.
3. **Browser → loopback service.** Browser content is less trusted than the local server. Reads need session+CSRF; mutations also need origin and one-time nonce; scan SSE has its own source boundary.
4. **Client → community service.** Only a strict 64 KiB privacy-reduced report crosses this boundary. The gateway/network can observe connection metadata even though the application schema does not retain it.
5. **Community service → client.** Feed data is attacker-controlled until exact schema/resource/freshness/Ed25519/anti-rollback verification succeeds.
6. **Analyze Links → public destination.** A destination may be malicious. Each hop requires public DNS validation and socket pinning; redirects/time/body/concurrency/queue/cache are bounded; no mailbox cookie/credential is sent.
7. **Build → installed release.** A repository commit is not trusted merely because it builds. Exact package inventory, signed envelope, pinned key, target/version and post-copy verification precede activation.
8. **Process → native vault/filesystem.** Native vaults protect keys/secrets at rest. Encrypted files are descriptor-bound, bounded and authenticated before nested state is used.

## Threats and controls

| Threat | Primary controls | Residual risk |
|---|---|---|
| Crafted MIME/HTML/QR/attachments consume resources or evade inspection | selected bounded MIME parts, parser/collection ceilings, non-executing HTML normalization, bounded PNG/JPEG/QR/hash work, incomplete coverage blocks Safe | novel formats or provider truncation may remain Unknown; broader malware execution analysis is out of scope |
| Forged authentication or brand identity manufactures trust | trusted-producer provenance, DMARC/author alignment, PSL-backed domain boundaries, structural/relationship evidence never becomes an allowlist | a compromised provider/account can supply apparently authentic malicious mail |
| Malicious local webpage calls mailbox APIs | loopback binding, Host/forwarded rejection, HttpOnly SameSite session, CSRF, origin, nonce, rate limits, CSP | malware running as the same OS user or browser compromise may act with user authority |
| Credential/key theft | native credential custody, owner-only files, secrets excluded from argv/log/browser/storage/artifacts, fail-closed missing vault | unlocked endpoint compromise, provider compromise or operator secret-manager compromise |
| Community brigading/Sybil attack | reporter-proof dedupe, evidence/independent thresholds, daily limits, generic-carrier suppression, 90-day attribution, fixed errors/metrics | reinstall/device Sybil resistance and volumetric defence require production gateway enrollment/reputation |
| Feed tamper/replay/equivocation | Ed25519, bounded exact schema, trusted overlap keys, freshness, encrypted monotonic generation+digest checkpoint, verified cache | signing-key compromise requires incident response and trust-root rollout |
| SSRF/DNS rebinding through Analyze Links | public-address resolution, per-hop DNS/socket pin, redirect revalidation, no auth/cookies, bounded coordinator | controlled public acceptance and egress monitoring remain deployment gates |
| Cross-account data/action confusion | opaque account/action tokens, account-keyed policies/history/schedules, one active scan per account, disconnect cleanup | owner-visible multi-account review remains required |
| Malicious/partial update or rollback | clean reproducible package, complete hashes, pinned Ed25519 envelope, target/newer checks, atomic activation, signed one-step rollback | production signing identity/distribution and native package-signing compromise remain external risks |
| Sensitive operational logging | closed metric/event enums, aggregate-only snapshots, generic public errors, redaction, no request bodies/attacker labels | reverse proxies/providers may log metadata unless operators configure them correctly |

## Adversaries considered

The model includes malicious senders, crafted remote servers, abusive reporters, network attackers unable to break TLS/modern cryptography, compromised community storage, untrusted browser pages, accidental operators, corrupt local files and supply-chain/package tampering. It assumes the operating system, native vault, trusted release public keys and correctly provisioned production signing keys are not already fully compromised.

## Out of scope / external controls

Endpoint malware with same-user control, provider infrastructure compromise, guaranteed scam detection, message/attachment detonation, public gateway DDoS/reputation, DNS/TLS operation, professional translation, production signing/notarization/store approval and legal/compliance determinations require separate controls. Android/iOS full mailbox shells are not implemented by the current repository and must not inherit desktop trust assumptions without a reviewed mobile model.

Any new provider, telemetry field, cloud classifier, attachment upload, platform shell, trust key or data store must update this model and add blocking regressions before release.
