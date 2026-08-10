# Email Shield — Shared Protection Core and Platform Plan

Date: 2026-08-11
Status: Milestone 3 portable core contract and desktop routing implemented; platform-client/store acceptance remains.

## Boundary to preserve

The provider-neutral core already begins at `CanonicalEnvelope` and produces deterministic layer evidence, verdict and recommended response policy. Provider adapters, OAuth/IMAP acquisition, native secret custody, scheduling, notifications, UI, destination egress and mailbox mutations stay outside that deterministic decision boundary.

Milestone 3 has made this boundary explicit as a versioned runtime contract:

1. a bounded versioned request containing one canonical envelope, an account-scoped personal-policy snapshot and verified signed-feed entries or explicit feed-unavailable state;
2. a deterministic response containing only scored evidence, verdict, response recommendation and generic incompleteness diagnostics;
3. strict runtime validation and resource ceilings before core evaluation;
4. canonical JSON conformance vectors shared by desktop, Android and iOS shells;
5. no filesystem, network, credential-vault, provider SDK, browser or operating-system import inside the portable core package.

## Platform shells

| Platform | Shell responsibilities | Platform constraints |
|---|---|---|
| Windows | Installer/updater, loopback desktop UI, Credential Manager, background task/service integration, notifications, provider OAuth/IMAP adapters | Authenticode/installer identity and background execution acceptance are external. |
| macOS | Signed/notarized app shell, Keychain, background task, notifications, loopback or native UI, provider adapters | Developer ID, notarization, login/background policy and sandbox acceptance are external. |
| Android | Kotlin shell, Keystore, WorkManager, account/provider acquisition allowed by provider policy, notifications, core bridge | Background quotas, OAuth redirect/app-link policy and store acceptance limit continuous work. |
| iOS | Swift shell, Keychain, BGTask scheduling, notifications, core bridge, provider acquisition allowed by platform/provider policy | No claim of continuous daemon execution; BGTask quotas, entitlements, OAuth redirects and App Store review govern behavior. |

## Data and action separation

- Raw credentials and refresh tokens never enter the shared core.
- Raw mailbox bodies exist only long enough for the platform adapter to construct the bounded canonical envelope.
- The core never executes provider actions. A shell may offer an action only from the existing explicit capability/action contracts and must preserve confirmation, idempotency and provider-native targeting.
- Community reports remain privacy-reduced and are constructed from canonical evidence through the existing shared path.
- Destination analysis remains explicit and outside automatic scanning on every platform.
- Per-account policy/history/schedule state uses each platform’s protected storage and never becomes a cross-account global allowlist.

## Milestone 3 implementation order

1. **Implemented:** extract and regression-lock the versioned portable core request/response module without changing verdict behavior.
2. **Implemented:** produce cross-runtime conformance fixtures for all five providers and adversarial precedence/unavailable-feed cases.
3. **Implemented:** move desktop scanning through that contract and prove byte-for-byte verdict parity.
4. Build Windows/macOS shells and release/update lifecycle.
5. Build Android/iOS shells within background/provider/store constraints.
6. Run accessibility, localization, multi-account, schedule, update/rollback and platform-store acceptance gates.

No mobile or signed-platform completion is claimed by this plan alone.
