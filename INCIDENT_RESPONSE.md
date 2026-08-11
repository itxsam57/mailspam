# Email Shield Incident Response Plan

Version: 1.0 — 2026-08-11

This plan applies to maintainers of the software and operators of a deployed community service. A self-hosted operator must assign named incident commander, security, operations, communications and privacy/legal roles before production use; the repository cannot assign people for them.

## Severity

- **SEV-1:** active release/signing compromise, exposed mailbox credentials/private keys, confirmed community data disclosure, malicious signed feed/update, or widespread unsafe action.
- **SEV-2:** exploitable security defect with material confidentiality/integrity/availability impact, bounded service compromise, or persistent incorrect threat publication.
- **SEV-3:** lower-impact weakness, attempted abuse contained by controls, or operational degradation without confirmed sensitive exposure.

## Response sequence

1. **Receive and record privately.** Capture time, affected version/commit/deployment, reporter channel and minimal reproduction. Never copy live credentials/message bodies into tickets or chat.
2. **Triage and contain.** Assign severity/commander; preserve read-only evidence; stop affected publication/ingestion/update channels when continued operation raises impact; do not delete suspected corrupt state first.
3. **Determine scope.** Identify affected keys, versions, providers, data classes, time range, installations and whether confidentiality, integrity or availability was lost. Treat logs/gateway metadata under the operator’s policy.
4. **Eradicate and recover.** Fix root cause with a regression, run the exact-head gate, rotate/revoke scoped secrets, restore only authenticated matched state, publish a strictly newer verified release/feed, and exercise rollback/repair where relevant.
5. **Communicate.** Coordinate private reporters/providers/operators; give users specific verification/revocation/update steps; meet applicable contractual/legal notice duties. Do not overstate certainty or expose exploit details before mitigation.
6. **Close and learn.** Confirm monitoring, update the incident timeline/threat model/runbooks/tests, document residual risk and conduct a blameless review.

## Playbooks

### Release signing key or distribution compromise

Pause signing/publication; preserve suspect artifacts; remove the compromised key from future trust bundles only through an authenticated trusted release path; provision a new protected Ed25519 identity; rebuild from a known commit; run every release/vault/provider/capacity gate; apply native platform signatures/notarization; publish hashes/key IDs/provenance and user remediation. A compromised currently trusted key cannot safely authorize its own removal without an independent trusted channel.

### Community feed signing key compromise or bad signed rule

Stop feed publication, retain aggregate evidence, disable/remove the affected rule at the authoritative source, prepare key overlap/replacement through the documented ceremony, publish a newer signed generation and verify anti-rollback clients accept it. Notify operators/users of the affected generation/time and whether mailbox actions could have been influenced. Feed intelligence never performs automatic provider mutation, limiting direct impact.

### Aggregate storage/key disclosure or corruption

Isolate service/storage, preserve matched encrypted snapshot+journal+keys, revoke access, determine whether reporter proofs/indicators were exposed, restore into a new path from an authenticated recovery bundle, validate signer/store/readiness before cutover, rotate storage and signing material as scoped, and complete required privacy notifications. Never pair a database with an unrelated key or silently reset corrupt state.

### Provider token/app-password exposure

Disconnect/revoke at the provider, delete the affected native-vault reference only after provider revocation semantics are satisfied, invalidate local sessions/actions, review provider audit activity and reconnect with new authorization. Do not ask a user to send the secret for diagnosis.

### Public abuse, DDoS or brigading

Apply gateway rate/reputation/enrollment controls, isolate offending traffic using gateway metadata under policy, preserve aggregate metrics rather than report bodies, temporarily reduce/disable ingestion if integrity or availability is at risk, verify signed-feed thresholds, and do not globally block a shared carrier from an unauthenticated surge.

### Privacy leak in logs/metrics/report schema

Stop the leaking sink/path; preserve access-controlled evidence; determine data fields/subjects/recipients/retention; remove or quarantine copies according to legal/evidence duties; rotate exposed tokens/keys; fix the schema/redaction/cardinality boundary and add a negative privacy regression; notify affected operators/users/regulators as required.

## Recovery exit criteria

Containment is stable; keys/tokens are scoped and rotated/revoked; restored data passes authentication and nested validation; health/metrics show normal bounded operation; the fixed commit passes the unchanged Engineering Gate on required platforms; distribution/feed provenance is verified independently; communications and remaining external acceptance are recorded. A green fixture test alone is not incident closure.
