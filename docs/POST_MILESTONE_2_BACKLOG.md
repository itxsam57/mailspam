# Email Shield — Post-Milestone 2 Backlog

This document deliberately separates **Milestone 2 acceptance work** from **future product expansion**. A live/deployment acceptance item is not a missing code feature merely because it still requires owner evidence.

## Must finish before Milestone 2 can be formally closed

These are the registered open acceptance gaps:

- **GAP-001 — Google production OAuth publication/consent verification.** Guided Gmail OAuth is implemented; public production publication/verification must be accepted in the real Google environment.
- **GAP-002 — real Outlook owner acceptance.** Guided Microsoft public-client PKCE is implemented; the owner must complete the real connect/scan/action/disconnect/reconnect sequence.
- **GAP-004 — public community deployment/operations.** Deploy DNS/TLS/gateway/monitoring/persistent storage and execute backup/restore plus signing-key rotation acceptance.
- **GAP-005 — controlled public Analyze Links validation.** Exercise the production DNS validation/socket-pinning transport against deliberately managed public infrastructure.
- **GAP-008 — gateway reporter reputation and volumetric protection.** Add/accept edge controls that cannot be truthfully proven by the application repository alone.
- Required visible/manual items in `.engineering/REGRESSION_REGISTER.md`.

These should be completed using `docs/MILESTONE_2_LIVE_ACCEPTANCE.md`. Any defect found during them returns to the normal root-fix + regression + exact-head gate workflow.

## Candidate Milestone 3 / later engineering features

These are future expansions, not hidden Milestone 2 closure requirements unless the product plan later promotes them:

1. **Native production distribution acceptance** — wrap the verified portable lifecycle in native installers, provision production signing identities, complete Authenticode/Developer ID/notarization, publish through immutable distribution and execute owned upgrade/rollback/uninstall acceptance.
2. **Android/iOS mailbox applications** — build real provider acquisition, native vault, schedule/notification, explicit action and accessible UI shells that consume the locked portable core vectors without inheriting desktop loopback assumptions.
3. **Broader attachment malware analysis** — optional local/static or privacy-reviewed sandbox integration beyond the current MIME/type/hash/QR checks. Any cloud analysis would require a new privacy and consent architecture.
4. **Broader QR/image format support** — additional formats beyond the currently locked bounded PNG/JPEG decoder when there is a demonstrated need.
5. **Provider-specific trusted Authentication-Results enablement** — only for providers where Email Shield can prove the exact receiver-controlled authentication-result producer boundary. Do not hardcode guessed authserv IDs or infer trust merely from API access.
6. **Enterprise/organization policy controls** — centrally managed policy templates, admin governance, policy distribution and organization-level audit controls while preserving per-mailbox privacy boundaries.
7. **Operational diagnostics package** — owner-exportable privacy-reviewed support bundle containing versions, generic error codes, gate/build state and non-secret health data, never credentials or mailbox content.
8. **Threat-intelligence expansion** — additional signed/reviewed intelligence sources, stronger campaign correlation and key transparency/rotation mechanisms without weakening local-first privacy.
9. **Community service scale architecture** — horizontal aggregation, replicated durable state, multi-region recovery and more advanced abuse/reputation systems after the single-service production deployment is accepted.
10. **Additional clients/surfaces** — browser extension, mobile or managed enterprise clients only as separate architectures; do not stretch the desktop-local trust assumptions across them without a new security model.
11. **Accessibility/internationalization polish** — structured keyboard/screen-reader acceptance, translated UI/copy and locale-safe formatting after the security/live baseline is stable.
12. **Advanced user controls** — richer policy explanations, history visualization and administrative/export workflows that do not turn relationship history into an allowlist.

## Design rule for future work

Future features must preserve the locked Milestone 1/2 invariants: provider neutrality, local-first content handling, explicit action confirmation, fail-closed trust boundaries, privacy-reduced community data, native secret custody, bounded resources, deterministic behavior and exact-head cross-platform gating.
