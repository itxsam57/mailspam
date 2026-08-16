import { initializeDefaultPersonalPolicyRepository } from "./api/defaultPolicyRepository.js";
import { initializeDefaultScanStateRepository } from "./api/defaultScanStateRepository.js";
import { initializeDefaultRelationshipHistoryRepository } from "./api/defaultRelationshipHistoryRepository.js";
import { initializeDefaultBackgroundProtectionRepository } from "./api/defaultBackgroundProtectionRepository.js";
import { initializeDefaultConsumerStateRepository } from "./api/defaultConsumerStateRepository.js";
import {
  BackgroundProtectionCoordinator,
  WorkerBackgroundProtectionExecutor,
} from "./api/backgroundProtection.js";
import { createConsumerDesktopServer } from "./api/consumerDesktopServer.js";
import { createDefaultLiveConnectionPersistence } from "./api/liveConnectionPersistence.js";
import { communityNetwork } from "./community/network.js";
import { initializeRuntimeWorkflowTrace } from "./diagnostics/runtimeWorkflowTrace.js";
import { ensureManagedDataDirectory } from "./security/managedDataDirectory.js";
import { getRuntimeCredentialVault } from "./security/credentialVaultFactory.js";
import { defaultEmailShieldDataDirectory } from "./security/dataDirectory.js";
import { FileFixtureConnectionPersistence } from "./api/fixtureConnectionPersistence.js";
import { sessionStore } from "./api/sessionStore.js";
import {
  getAccountLifecycleService,
  getAccountPlatformService,
  getDesktopDeviceIdentity,
  initializeDefaultAccountPlatform,
} from "./platform/defaultAccountPlatform.js";
import { createDefaultInboundEventStateRepository } from "./realtime/inboundEventPersistence.js";
import { RealtimeProtectionProcessor } from "./realtime/realtimeProtectionProcessor.js";
import { RealtimeProtectionService } from "./realtime/realtimeProtectionService.js";
import { SerialProtectionExecutor } from "./realtime/serialProtectionExecutor.js";
import { createTechnicalTelemetryFromEnvironment } from "./telemetry/technicalTelemetry.js";

const PORT = Number(process.env.PORT ?? 4173);
const HOST = process.env.HOST ?? "127.0.0.1";

if (!["127.0.0.1", "localhost", "::1"].includes(HOST)) {
  throw new Error("The Email Shield desktop server may bind only to a loopback host.");
}

// Technical telemetry is a separate, opt-in boundary. It receives only fixed
// startup-health events and anonymous platform/version metadata. Mailbox data,
// account identity, device identity, credentials and raw errors never cross it.
const telemetry = createTechnicalTelemetryFromEnvironment({
  appVersion: process.env.EMAIL_SHIELD_RELEASE_VERSION ?? "0.2.0",
});
void telemetry.capture("email_shield_app_started");

const dataDirectory = defaultEmailShieldDataDirectory();
ensureManagedDataDirectory(dataDirectory);

// Source/live owner acceptance gets a separate local diagnostic trace. It is
// automatically enabled by the source development launchers, bounded on disk,
// and accepts only the fixed privacy-safe workflow schema. Normal packaged
// consumer startup remains unaffected unless the diagnostic environment flag is
// explicitly enabled.
const workflowTrace = initializeRuntimeWorkflowTrace({ dataDirectory });
if (workflowTrace.enabled) {
  workflowTrace.record({
    traceId: workflowTrace.runId,
    stage: "app",
    actionId: "application.start",
    expectedWorkflow: "desktop_runtime",
    component: "desktop_server",
    step: "started",
    outcome: "started",
  });
  console.log(`Email Shield runtime workflow trace active for run ${workflowTrace.runId}.`);
}

// Resolve or migrate protected local encryption keys before the desktop API
// becomes reachable. One native runtime vault is shared across every protected
// repository and provider session so Windows initializes its trusted helper
// once instead of recompiling it for each credential operation. Independent
// repositories start together; the vault itself remains the serialization
// boundary for sensitive native operations.
const credentialVault = getRuntimeCredentialVault();
const protectedStateStartedAt = Date.now();
let protectedStateFailureReported = false;
async function reportProtectedStateFailure<T>(operation: Promise<T>): Promise<T> {
  try {
    return await operation;
  } catch (error) {
    if (!protectedStateFailureReported) {
      protectedStateFailureReported = true;
      void telemetry.capture("email_shield_protected_state_failed", {
        failure_kind: "initialization_error",
      });
    }
    throw error;
  }
}

console.log("Email Shield initializing protected local state...");
const initialized = await Promise.all([
  reportProtectedStateFailure(initializeDefaultPersonalPolicyRepository({ credentialVault })),
  reportProtectedStateFailure(initializeDefaultScanStateRepository({ credentialVault })),
  reportProtectedStateFailure(initializeDefaultRelationshipHistoryRepository({ credentialVault })),
  reportProtectedStateFailure(initializeDefaultBackgroundProtectionRepository({ credentialVault })),
  reportProtectedStateFailure(initializeDefaultConsumerStateRepository({ credentialVault, dataDirectory })),
  reportProtectedStateFailure(initializeDefaultAccountPlatform({ credentialVault, dataDirectory })),
  reportProtectedStateFailure(createDefaultInboundEventStateRepository({ credentialVault, dataDirectory })),
  reportProtectedStateFailure(createDefaultLiveConnectionPersistence({ credentialVault, dataDirectory })),
] as const);
const inboundEventRepository = initialized[6];
const liveConnections = initialized[7];
const protectedStateDurationMs = Date.now() - protectedStateStartedAt;
console.log(`Email Shield protected local state ready in ${protectedStateDurationMs}ms.`);
void telemetry.capture("email_shield_protected_state_ready", {
  duration_ms: protectedStateDurationMs,
});

const accountPlatform = getAccountPlatformService();
const accountLifecycle = getAccountLifecycleService();
const deviceIdentity = getDesktopDeviceIdentity();

// Consumer mailbox authorization is one-time by default. The encrypted local
// registry contains only provider identity/config metadata and OS-vault handles;
// refresh tokens/app passwords remain in the native vault. Restore live sessions
// before either scheduled or realtime protection starts so restart does not
// create an unprotected gap. If the platform cannot persist vault-backed state,
// Email Shield still starts for Scam Check but refuses new durable live connects.
sessionStore.configureLiveConnectionPersistence(liveConnections, { required: true });
sessionStore.restoreLiveConnections();

const fixtureConnections = new FileFixtureConnectionPersistence(dataDirectory);
fixtureConnections.restore(sessionStore);

// Scheduled and realtime protection deliberately share both one underlying
// Worker implementation and one fail-fast execution gate. This keeps bounded
// Quick scanning, relationship history, personal policy, Family Shield and
// verified community intelligence on one path without creating a hidden queue.
const workerProtectionExecutor = new WorkerBackgroundProtectionExecutor(communityNetwork, accountPlatform);
const protectionExecutor = new SerialProtectionExecutor(workerProtectionExecutor);
const backgroundProtection = new BackgroundProtectionCoordinator({
  sessions: sessionStore,
  executor: protectionExecutor,
});
backgroundProtection.start();

const realtimeProcessor = new RealtimeProtectionProcessor(sessionStore, protectionExecutor);
const realtimeProtection = new RealtimeProtectionService({
  sessions: sessionStore,
  repository: inboundEventRepository,
  processor: realtimeProcessor,
});
realtimeProtection.start();

const app = createConsumerDesktopServer({
  backgroundProtection,
  fixtureConnections,
  accountPlatform,
  accountLifecycle,
  deviceIdentity,
  developmentEntitlementsEnabled: process.env.EMAIL_SHIELD_ENABLE_DEVELOPMENT_ENTITLEMENTS === "1",
});
app.listen(PORT, HOST, () => {
  console.log(`Email Shield listening on http://${HOST}:${PORT}`);
  void telemetry.capture("email_shield_server_listening");
  if (workflowTrace.enabled) {
    workflowTrace.record({
      traceId: workflowTrace.runId,
      stage: "app",
      actionId: "application.listen",
      expectedWorkflow: "desktop_runtime",
      component: "desktop_server",
      step: "listening",
      outcome: "success",
    });
  }
});
