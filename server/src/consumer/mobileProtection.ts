import {
  evaluateConsumerScamCheck,
  type ConsumerScamCheckDependencies,
  type ConsumerScamCheckResponseV1,
} from "./scamCheck.js";
import { assessScamIntervention, type ScamInterventionAssessment } from "./intervention.js";

export type MobileScamChannel = "sms" | "notification" | "share_sheet" | "calendar_invite" | "clipboard_explicit" | "qr_scan";

export interface MobileScamInputV1 {
  schemaVersion: 1;
  channel: MobileScamChannel;
  text?: string;
  url?: string;
  senderLabel?: string;
  calendarOrganizer?: string;
  permissionContext: {
    userInitiated: boolean;
    notificationAccessGranted?: boolean;
    calendarAccessGranted?: boolean;
  };
}

export interface MobileScamAnalysisV1 {
  schemaVersion: 1;
  channel: MobileScamChannel;
  result: ConsumerScamCheckResponseV1;
  intervention: ScamInterventionAssessment;
  privacy: "ephemeral_user_or_platform_selected_input";
  notificationPayloadPolicy: "generic_no_private_body_by_default";
}

function bounded(value: unknown, max: number): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.length > max) throw new Error("Mobile scam input exceeds its local bound.");
  return value;
}

export function assertMobileScamInput(input: unknown): asserts input is MobileScamInputV1 {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("Mobile scam input is invalid.");
  const value = input as Record<string, unknown>;
  const allowed = new Set(["schemaVersion", "channel", "text", "url", "senderLabel", "calendarOrganizer", "permissionContext"]);
  if (Object.keys(value).some((key) => !allowed.has(key)) || value.schemaVersion !== 1) throw new Error("Mobile scam input is invalid.");
  const channels: MobileScamChannel[] = ["sms", "notification", "share_sheet", "calendar_invite", "clipboard_explicit", "qr_scan"];
  if (!channels.includes(value.channel as MobileScamChannel)) throw new Error("Mobile scam channel is invalid.");
  bounded(value.text, 32_000);
  bounded(value.url, 8_192);
  bounded(value.senderLabel, 512);
  bounded(value.calendarOrganizer, 512);
  if (!value.permissionContext || typeof value.permissionContext !== "object" || Array.isArray(value.permissionContext)) {
    throw new Error("Mobile scam permission context is required.");
  }
  const permissions = value.permissionContext as Record<string, unknown>;
  if (Object.keys(permissions).some((key) => !["userInitiated", "notificationAccessGranted", "calendarAccessGranted"].includes(key))
    || typeof permissions.userInitiated !== "boolean") {
    throw new Error("Mobile scam permission context is invalid.");
  }
  if (value.channel === "notification" && permissions.notificationAccessGranted !== true) {
    throw new Error("Notification analysis requires explicit notification access permission.");
  }
  if (value.channel === "calendar_invite" && permissions.calendarAccessGranted !== true) {
    throw new Error("Calendar invite analysis requires explicit calendar permission.");
  }
  if (["share_sheet", "clipboard_explicit", "qr_scan"].includes(value.channel as string) && permissions.userInitiated !== true) {
    throw new Error("This mobile analysis channel must be explicitly initiated by the user.");
  }
  if (!(typeof value.text === "string" && value.text.trim()) && !(typeof value.url === "string" && value.url.trim())) {
    throw new Error("Mobile scam analysis requires text or a URL.");
  }
}

/**
 * Portable mobile analysis. This function is real today and can be called by a
 * future native bridge, but it must never be used as evidence that an iOS or
 * Android hook has already been integrated into the shipping desktop build.
 */
export function analyzeMobileScamInput(
  input: unknown,
  deps: ConsumerScamCheckDependencies = {},
): MobileScamAnalysisV1 {
  assertMobileScamInput(input);
  const text = [input.senderLabel, input.calendarOrganizer, input.text].filter(Boolean).join("\n");
  const kind = input.url?.trim() && !input.text?.trim() ? "url" : "message";
  const result = evaluateConsumerScamCheck({
    schemaVersion: 1,
    kind,
    text: kind === "message" ? text : undefined,
    url: input.url,
    sender: input.senderLabel ? { displayName: input.senderLabel, address: null } : undefined,
  }, deps);
  return {
    schemaVersion: 1,
    channel: input.channel,
    result,
    intervention: assessScamIntervention(`${text}\n${input.url ?? ""}`),
    privacy: "ephemeral_user_or_platform_selected_input",
    notificationPayloadPolicy: "generic_no_private_body_by_default",
  };
}

export type NativeBridgeCapabilityState =
  | "portable_engine_ready_native_bridge_required"
  | "permission_and_native_bridge_required"
  | "platform_restricted"
  | "not_applicable"
  | "implemented_in_desktop";

export interface NativeProtectionBridgeV1 {
  schemaVersion: 1;
  platform: "windows" | "macos" | "android" | "ios";
  /**
   * Explicit release truth. Android/iOS currently have a portable analysis
   * engine contract, not a shipping native interception/share/notification
   * bridge. Packaging code must not translate this field into "protected".
   */
  implementationStatus:
    | "portable_analysis_ready_native_bridge_not_built"
    | "desktop_mailbox_protection_only";
  capabilities: {
    sms: NativeBridgeCapabilityState;
    notificationText: NativeBridgeCapabilityState;
    shareSheet: NativeBridgeCapabilityState;
    clipboardExplicit: NativeBridgeCapabilityState;
    calendarInvite: NativeBridgeCapabilityState;
    qrCameraOrImage: NativeBridgeCapabilityState;
    backgroundMailboxProtection: NativeBridgeCapabilityState;
  };
}

/**
 * Describes integration readiness, not current device protection. The return
 * value intentionally refuses the word "supported" for native hooks that do
 * not exist yet, preventing a portable engine from being mistaken for a built
 * Android/iOS feature during wrapping.
 */
export function nativeProtectionBridgeContract(platform: NativeProtectionBridgeV1["platform"]): NativeProtectionBridgeV1 {
  if (platform === "android") return {
    schemaVersion: 1,
    platform,
    implementationStatus: "portable_analysis_ready_native_bridge_not_built",
    capabilities: {
      sms: "portable_engine_ready_native_bridge_required",
      notificationText: "permission_and_native_bridge_required",
      shareSheet: "portable_engine_ready_native_bridge_required",
      clipboardExplicit: "portable_engine_ready_native_bridge_required",
      calendarInvite: "permission_and_native_bridge_required",
      qrCameraOrImage: "portable_engine_ready_native_bridge_required",
      backgroundMailboxProtection: "permission_and_native_bridge_required",
    },
  };
  if (platform === "ios") return {
    schemaVersion: 1,
    platform,
    implementationStatus: "portable_analysis_ready_native_bridge_not_built",
    capabilities: {
      sms: "platform_restricted",
      notificationText: "platform_restricted",
      shareSheet: "portable_engine_ready_native_bridge_required",
      clipboardExplicit: "portable_engine_ready_native_bridge_required",
      calendarInvite: "permission_and_native_bridge_required",
      qrCameraOrImage: "portable_engine_ready_native_bridge_required",
      backgroundMailboxProtection: "permission_and_native_bridge_required",
    },
  };
  return {
    schemaVersion: 1,
    platform,
    implementationStatus: "desktop_mailbox_protection_only",
    capabilities: {
      sms: "not_applicable",
      notificationText: "not_applicable",
      shareSheet: "portable_engine_ready_native_bridge_required",
      clipboardExplicit: "portable_engine_ready_native_bridge_required",
      calendarInvite: "permission_and_native_bridge_required",
      qrCameraOrImage: "portable_engine_ready_native_bridge_required",
      backgroundMailboxProtection: "implemented_in_desktop",
    },
  };
}
