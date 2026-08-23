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
import { AdapterMailboxCheckpointProbe } from "./realtime/mailboxCheckpointProbe.js";
import { RealtimeProtectionProcessor } from "./realtime/realtimeProtectionProcessor.js";
import { RealtimeProtectionService } from "./realtime/realtimeProtectionService.js";
import { SerialProtectionExecutor } from "./realtime/serialProtectionExecutor.js";
import { createTechnicalTelemetryFromEnvironment } from "./telemetry/technicalTelemetry.js";

const PORT = Number(process.env.PORT ?? 4173);
const HOST = process.env.HOST ?? "127.0.0.1";

if (!["127.0.0.1", "localhost", "::1"].includes(HOST)) {
  throw new Error("The Email Shield desktop server may bind only to a loopback host.");
}

const telemetry = createTechnicalTelemetryFromEnvironment({
  appVersion: process.env.EMAIL_SHIELD_RELEASE_VERSION ?? "0.2.0",
});
void telemetry.capture("email_shield_app_started");

const dataDirectory = defaultEmailShieldDataDirectory();
ensureManagedDataDirectory(dataDirectory);

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

sessionStore.configureLiveConnectionPersistence(liveConnections, { required: true });
sessionStore.restoreLiveConnections();

const fixtureConnections = new FileFixtureConnectionPersistence(dataDirectory);
fixtureConnections.restore(sessionStore);

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
  pollProbe: new AdapterMailboxCheckpointProbe(credentialVault),
  protectionEnabled: (accountKey) => backgroundProtection.status(accountKey).enabled === true,
});
realtimeProtection.start();

const app = createConsumerDesktopServer({
  accountReachability: (session) => realtimeProtection.mailboxReachability(session),
  accountAutomaticProtection: (session) => realtimeProtection.accountStatus(session),
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
