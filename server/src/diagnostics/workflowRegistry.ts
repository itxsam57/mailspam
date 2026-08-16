import type { WorkflowDefinition } from "./workflowDiagnosis.js";

function linearWorkflow(
  workflowId: string,
  actionIds: string[] = [workflowId],
  internalOnly = false,
): WorkflowDefinition {
  const requested = `${workflowId}.requested`;
  const backendCompleted = `${workflowId}.backend_completed`;
  const uiConfirmed = `${workflowId}.ui_confirmed`;
  return {
    workflowId,
    actionIds,
    requiredCheckpoints: [requested, backendCompleted, uiConfirmed],
    terminalCheckpoints: {
      success: [uiConfirmed],
      failed: [],
      rejected: [],
      cancelled: [],
      partial: [],
    },
    ...(internalOnly ? { internalOnly: true } : {}),
  };
}

function uiWorkflow(
  workflowId: string,
  actionIds: string[] = [workflowId],
  internalOnly = false,
): WorkflowDefinition {
  const requested = `${workflowId}.requested`;
  const uiConfirmed = `${workflowId}.ui_confirmed`;
  return {
    workflowId,
    actionIds,
    requiredCheckpoints: [requested, uiConfirmed],
    terminalCheckpoints: {
      success: [uiConfirmed],
      failed: [],
      rejected: [],
      cancelled: [],
      partial: [],
    },
    ...(internalOnly ? { internalOnly: true } : {}),
  };
}

function automaticWorkflow(workflowId: string): WorkflowDefinition {
  const started = `${workflowId}.started`;
  const completed = `${workflowId}.completed`;
  return {
    workflowId,
    actionIds: [`system.${workflowId}`],
    requiredCheckpoints: [started, completed],
    terminalCheckpoints: {
      success: [completed],
      failed: [],
      rejected: [],
      cancelled: [],
      partial: [],
    },
  };
}

function scanWorkflow(type: "quick" | "full" | "spam"): WorkflowDefinition {
  const workflowId = `mailbox.scan.${type}`;
  const requiredCheckpoints = [
    `${workflowId}.requested`,
    `${workflowId}.request_validated`,
    `${workflowId}.provider_enumeration`,
    `${workflowId}.provider_page_read`,
    `${workflowId}.message_normalized`,
    `${workflowId}.verdict_evaluated`,
    `${workflowId}.checkpoint_persisted`,
    `${workflowId}.stream_completed`,
    `${workflowId}.ui_confirmed`,
  ];
  return {
    workflowId,
    actionIds: [workflowId],
    requiredCheckpoints,
    terminalCheckpoints: {
      success: [`${workflowId}.ui_confirmed`],
      failed: [],
      rejected: [],
      cancelled: [],
      partial: [],
    },
  };
}

const DEFINITIONS: WorkflowDefinition[] = [
  automaticWorkflow("application.startup"),
  automaticWorkflow("protected_state.initialize"),
  automaticWorkflow("provider.restore_sessions"),
  automaticWorkflow("protection.background.run"),
  automaticWorkflow("protection.realtime.run"),
  automaticWorkflow("community.feed.refresh"),

  linearWorkflow("provider.connect.gmail", ["provider.connect.gmail", "account.connect"]),
  linearWorkflow("provider.connect.icloud", ["provider.connect.icloud", "account.connect"]),
  linearWorkflow("provider.connect.yahoo", ["provider.connect.yahoo", "account.connect"]),
  linearWorkflow("provider.connect.imap", ["provider.connect.imap", "account.connect"]),
  linearWorkflow("provider.connect.outlook", ["provider.connect.outlook"], true),
  linearWorkflow("account.select"),
  linearWorkflow("account.disconnect"),
  linearWorkflow("account.mailbox.link"),
  linearWorkflow("account.sign_out"),
  linearWorkflow("account.profile.snapshot"),
  uiWorkflow("account.recovery.open"),
  linearWorkflow("workspace.restore"),

  scanWorkflow("quick"),
  scanWorkflow("full"),
  scanWorkflow("spam"),
  linearWorkflow("mailbox.scan.stop"),
  linearWorkflow("mailbox.scan.resume"),
  linearWorkflow("mailbox.scan.history"),

  linearWorkflow("message.block_sender"),
  linearWorkflow("message.block_domain"),
  linearWorkflow("message.trash"),
  linearWorkflow("message.report_scam"),
  linearWorkflow("message.move_spam"),
  linearWorkflow("message.mark_safe"),
  linearWorkflow("message.trust_sender"),
  linearWorkflow("message.unsubscribe"),
  linearWorkflow("message.analyze_links"),
  linearWorkflow("message.undo"),
  linearWorkflow("mailbox.cleanup"),

  linearWorkflow("protection.background.toggle"),
  linearWorkflow("protection.background.interval"),
  linearWorkflow("protection.sensitivity.save"),
  linearWorkflow("settings.save"),
  linearWorkflow("policy.load"),
  linearWorkflow("policy.revoke"),
  linearWorkflow("policy.bulk_revoke"),
  linearWorkflow("policy.clear"),
  linearWorkflow("policy.reset"),
  linearWorkflow("policy.import"),
  linearWorkflow("policy.export"),
  uiWorkflow("policy.selection.toggle"),
  linearWorkflow("activity.load"),
  linearWorkflow("activity.clear"),
  linearWorkflow("mailbox.health.run"),
  linearWorkflow("mailbox.health.load"),
  linearWorkflow("account.footprint.load"),
  linearWorkflow("browser_destination.check"),
  linearWorkflow("intervention.check"),
  linearWorkflow("exposure.email.check"),
  linearWorkflow("support.bundle.export"),

  linearWorkflow("scam_check.run"),
  uiWorkflow("scam_check.mode"),
  uiWorkflow("scam_check.clear"),
  linearWorkflow("shopping_safety.run"),
  linearWorkflow("media_authenticity.run"),

  linearWorkflow("family.load"),
  linearWorkflow("family.create"),
  linearWorkflow("family.join"),
  linearWorkflow("family.invite"),
  linearWorkflow("family.strict"),
  linearWorkflow("family.leave"),
  linearWorkflow("family.remove_member"),
  linearWorkflow("family.guardian_preferences"),
  linearWorkflow("family.transfer"),

  linearWorkflow("community.operations.load"),
  linearWorkflow("community.campaign_radar.load"),

  linearWorkflow("account.profile.register"),
  linearWorkflow("account.profile.sign_in"),
  linearWorkflow("account.recovery.use"),
  linearWorkflow("account.recovery.rotate"),
  linearWorkflow("account.devices.revoke"),
  linearWorkflow("account.devices.revoke_others"),
  linearWorkflow("account.sign_out_everywhere"),
  linearWorkflow("account.metadata.export"),
  linearWorkflow("account.family.delete"),
  linearWorkflow("account.delete"),
  linearWorkflow("billing.plan.load"),
  linearWorkflow("billing.subscription.verify"),
  linearWorkflow("billing.purchase.individual"),
  linearWorkflow("billing.purchase.family"),
  linearWorkflow("billing.purchase.restore"),

  linearWorkflow("onboarding.start"),
  linearWorkflow("onboarding.complete"),
  uiWorkflow("navigation.home"),
  uiWorkflow("navigation.scan"),
  uiWorkflow("navigation.protection"),
  uiWorkflow("navigation.family"),
  uiWorkflow("navigation.community"),
  uiWorkflow("navigation.history"),
  uiWorkflow("navigation.account"),
  uiWorkflow("navigation.settings"),
  uiWorkflow("navigation.activity"),
  uiWorkflow("navigation.check"),

  linearWorkflow("developer.test_suite", ["developer.test_suite"], true),
];

export const WORKFLOW_REGISTRY: Readonly<Record<string, WorkflowDefinition>> = Object.freeze(
  Object.fromEntries(DEFINITIONS.map((definition) => [definition.workflowId, Object.freeze(definition)])),
);

export function runtimeWorkflowDefinition(workflowId: string): WorkflowDefinition | null {
  return WORKFLOW_REGISTRY[workflowId] ?? null;
}

export function consumerRuntimeWorkflows(): WorkflowDefinition[] {
  return Object.values(WORKFLOW_REGISTRY).filter((definition) => definition.internalOnly !== true);
}
