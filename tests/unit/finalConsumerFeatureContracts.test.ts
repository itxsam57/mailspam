import { afterEach, describe, expect, it } from "vitest";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { createConsumerDesktopServer } from "../../server/src/api/consumerDesktopServer.js";
import { LocalSecurityManager } from "../../server/src/api/localSecurity.js";
import {
  campaignRadar,
  createTrustedAssistancePacket,
} from "../../server/src/consumer/familyGuardian.js";
import {
  analyzeMobileScamInput,
  nativeProtectionBridgeContract,
} from "../../server/src/consumer/mobileProtection.js";
import { assessScamIntervention } from "../../server/src/consumer/intervention.js";
import {
  checkEmailExposure,
  checkPasswordExposure,
  familyExposureSummary,
  type ExposureLookupPort,
} from "../../server/src/consumer/identityExposure.js";
import { analyzeShoppingSafety } from "../../server/src/consumer/shoppingSafety.js";
import { analyzeMediaAuthenticity } from "../../server/src/consumer/mediaAuthenticity.js";
import { assertBrowserProtectionRequest } from "../../server/src/consumer/browserProtection.js";

const servers: Server[] = [];

const FORBIDDEN_SUPPORT_KEYS = new Set([
  "accesstoken",
  "refreshtoken",
  "apppassword",
  "subject",
  "body",
  "bodytext",
  "rawbody",
  "senderaddress",
  "mailboxaddress",
  "recipientaddress",
  "mailboxaccountkey",
  "providernativeid",
  "messageid",
  "rawurl",
  "deviceprivatekey",
  "publickeyspki",
  "recoverycode",
  "recoverycodehash",
]);

function objectKeys(value: unknown, keys = new Set<string>()): Set<string> {
  if (Array.isArray(value)) {
    for (const item of value) objectKeys(item, keys);
    return keys;
  }
  if (!value || typeof value !== "object") return keys;
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    keys.add(key.toLowerCase());
    objectKeys(child, keys);
  }
  return keys;
}

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

async function startDesktop(): Promise<string> {
  const app = createConsumerDesktopServer({ security: new LocalSecurityManager() });
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

describe("final consumer feature contracts", () => {
  it("keeps trusted-person sharing explicit and campaign radar privacy-reduced", () => {
    const hidden = createTrustedAssistancePacket({
      verdict: "high_risk",
      textForCategory: "Urgent bank transfer requested by support agent",
      strongestSignals: ["BANK_TRANSFER", "CALLBACK_NUMBER"],
      safeNextAction: "Verify through the bank's official app.",
      excerpt: "private suspicious message excerpt",
      shareExcerpt: false,
      now: Date.parse("2026-08-13T00:00:00.000Z"),
    });
    expect(hidden.consentedExcerpt).toBeNull();
    expect(hidden.categories).toContain("banking");
    expect(hidden.itemFingerprint).toMatch(/^[a-f0-9]{64}$/);
    expect(hidden.privacy).toBe("explicit_single_item_share_not_mailbox_access");

    const shared = createTrustedAssistancePacket({
      verdict: "review",
      textForCategory: "Unexpected crypto investment request",
      strongestSignals: ["CRYPTO_REQUEST"],
      safeNextAction: "Verify independently.",
      excerpt: "user-approved excerpt",
      shareExcerpt: true,
      now: Date.parse("2026-08-13T00:00:00.000Z"),
    });
    expect(shared.consentedExcerpt).toBe("user-approved excerpt");

    expect(campaignRadar(null)).toMatchObject({ available: false, advisories: [] });
    const radar = campaignRadar([
      {
        type: "campaign",
        value: "a".repeat(64),
        confirmedThreat: false,
        ruleId: "campaign-watch",
        independentReports: 1,
        firstSeen: "2026-08-13T00:00:00.000Z",
        lastSeen: "2026-08-13T00:10:00.000Z",
      },
      {
        type: "campaign",
        value: "b".repeat(64),
        confirmedThreat: true,
        ruleId: "campaign-confirmed",
        independentReports: 4,
        firstSeen: "2026-08-13T00:00:00.000Z",
        lastSeen: "2026-08-13T00:20:00.000Z",
      },
    ]);
    expect(radar.scope).toBe("network_wide");
    expect(radar.advisories).toHaveLength(1);
    expect(radar.advisories[0]).toMatchObject({ ruleId: "campaign-confirmed", severity: "confirmed", independentReports: 4 });
    expect(JSON.stringify(radar)).not.toMatch(/mailbox|message body|reporter identity/i);
  });

  it("enforces mobile permission boundaries and never mislabels an unbuilt native bridge as supported", () => {
    expect(() => analyzeMobileScamInput({
      schemaVersion: 1,
      channel: "notification",
      text: "Urgent bank transfer now",
      permissionContext: { userInitiated: false },
    })).toThrow(/notification access permission/i);

    expect(() => analyzeMobileScamInput({
      schemaVersion: 1,
      channel: "clipboard_explicit",
      text: "verify account now",
      permissionContext: { userInitiated: false },
    })).toThrow(/explicitly initiated/i);

    const result = analyzeMobileScamInput({
      schemaVersion: 1,
      channel: "share_sheet",
      text: "Support says install AnyDesk and send a bank transfer immediately",
      permissionContext: { userInitiated: true },
    });
    expect(result.privacy).toBe("ephemeral_user_or_platform_selected_input");
    expect(result.notificationPayloadPolicy).toBe("generic_no_private_body_by_default");
    expect(result.intervention.officialVerificationRequired).toBe(true);

    const ios = nativeProtectionBridgeContract("ios");
    const android = nativeProtectionBridgeContract("android");
    expect(ios.implementationStatus).toBe("portable_analysis_ready_native_bridge_not_built");
    expect(android.implementationStatus).toBe("portable_analysis_ready_native_bridge_not_built");
    expect(ios.capabilities.sms).toBe("platform_restricted");
    expect(ios.capabilities.shareSheet).toBe("portable_engine_ready_native_bridge_required");
    expect(ios.capabilities.backgroundMailboxProtection).toBe("permission_and_native_bridge_required");
    expect(android.capabilities.sms).toBe("portable_engine_ready_native_bridge_required");
    expect(android.capabilities.notificationText).toBe("permission_and_native_bridge_required");
    expect(JSON.stringify([ios, android])).not.toContain('"supported"');
  });

  it("treats remote-access plus irreversible payment pressure as a critical intervention", () => {
    const result = assessScamIntervention(
      "Refund department: call +1 (202) 555-0199 now, install AnyDesk, then send the bank transfer immediately.",
    );
    expect(result.phoneNumbers).toContain("+12025550199");
    expect(result.remoteAccessTools).toContain("anydesk");
    expect(result.requestedPaymentMethods).toContain("bank transfer");
    expect(result.signals.some((signal) => signal.severity === "critical")).toBe(true);
    expect(result.officialVerificationRequired).toBe(true);
    expect(result.recommendedAction).toMatch(/independently contact/i);
  });

  it("sends only hash prefixes to exposure providers and never treats unavailable as clean", async () => {
    const calls: Array<{ kind: string; prefix: string }> = [];
    const lookup: ExposureLookupPort = {
      async lookup(kind, prefix) {
        calls.push({ kind, prefix });
        return [];
      },
    };

    const email = "private.user@example.test";
    const password = "correct horse battery staple";
    const emailResult = await checkEmailExposure(email, lookup);
    const passwordResult = await checkPasswordExposure(password, lookup);
    expect(emailResult.lookupPrivacy).toBe("hash_prefix_only");
    expect(passwordResult.lookupPrivacy).toBe("hash_prefix_only");
    expect(calls).toHaveLength(2);
    expect(calls[0]).toMatchObject({ kind: "email_sha256" });
    expect(calls[0]!.prefix).toMatch(/^[A-F0-9]{10}$/);
    expect(calls[1]).toMatchObject({ kind: "password_sha1" });
    expect(calls[1]!.prefix).toMatch(/^[A-F0-9]{5}$/);
    expect(JSON.stringify(calls)).not.toContain(email);
    expect(JSON.stringify(calls)).not.toContain(password);

    const unavailable = await checkEmailExposure(email, {
      async lookup() { return null; },
    });
    expect(unavailable.state).toBe("unavailable");
    expect(unavailable.limitations.join(" ")).toMatch(/did not treat this as a clean/i);

    expect(familyExposureSummary([emailResult, passwordResult, unavailable])).toEqual({
      checkedMembers: 3,
      exposedMembers: 0,
      unavailableMembers: 1,
      privacy: "counts_only_no_breach_detail",
    });
  });

  it("warns on irreversible shopping payment signals without inventing merchant reputation", () => {
    const result = analyzeShoppingSafety({
      schemaVersion: 1,
      url: "https://shop.example.test/deal",
      pageText: "Only today. Contact us on WhatsApp to complete the order.",
      sellerName: "Example Shop",
      advertisedPriceText: "$99",
      paymentText: "Pay by bank transfer now",
    });
    expect(result.verdict).toBe("high_risk");
    expect(result.signals.some((signal) => signal.code === "SHOPPING_IRREVERSIBLE_PAYMENT")).toBe(true);
    expect(result.limitations.join(" ")).toMatch(/does not invent merchant age/i);
    expect(result.privacy).toBe("explicit_storefront_input_only");
  });

  it("fails media authenticity safely when no vetted detector is configured", async () => {
    const result = await analyzeMediaAuthenticity({
      kind: "image",
      bytes: new Uint8Array([0x89, 0x50, 0x4e, 0x47]),
      mimeType: "image/png",
    });
    expect(result.state).toBe("unavailable");
    expect(result.confidenceBand).toBeNull();
    expect(result.reasons.join(" ")).toMatch(/will not fabricate a deepfake verdict/i);
    expect(result.privacy).toBe("explicit_user_submitted_media");
  });

  it("rejects browser-history-style or non-HTTP browser inputs at the contract boundary", () => {
    expect(() => assertBrowserProtectionRequest({
      schemaVersion: 1,
      url: "file:///private/path",
      context: "navigation",
    })).toThrow(/HTTP\(S\)/i);

    expect(() => assertBrowserProtectionRequest({
      schemaVersion: 1,
      url: "https://example.test",
      context: "navigation",
      history: ["https://private.example.test"],
    })).toThrow(/invalid/i);
  });

  it("serves a no-store privacy-safe support bundle through the real desktop composition", async () => {
    const baseUrl = await startDesktop();
    const home = await fetch(baseUrl);
    const html = await home.text();
    const cookie = home.headers.get("set-cookie")?.split(";", 1)[0] ?? "";
    const sessionSecret = cookie.split("=", 2)[1] ?? "";
    const csrf = html.match(/<meta name="email-shield-csrf" content="([^"]+)"/)?.[1] ?? "";
    expect(home.status).toBe(200);
    expect(cookie).toMatch(/^email_shield_local_session=/);
    expect(sessionSecret.length).toBeGreaterThanOrEqual(32);
    expect(csrf.length).toBeGreaterThanOrEqual(32);
    const response = await fetch(`${baseUrl}/api/consumer/v1/support-bundle`, {
      headers: {
        Cookie: cookie,
        Origin: baseUrl,
        Referer: `${baseUrl}/`,
        "X-Email-Shield-CSRF": csrf,
      },
    });
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toContain("no-store");
    const body = await response.json() as Record<string, unknown>;
    expect(body.schemaVersion).toBe(1);
    expect(body.privacy).toBe("no_credentials_tokens_mail_content_subject_sender_url_family_private_data_or_device_keys");

    const keys = objectKeys(body);
    expect([...keys].filter((key) => FORBIDDEN_SUPPORT_KEYS.has(key))).toEqual([]);
    const serialized = JSON.stringify(body);
    expect(serialized).not.toContain(sessionSecret);
    expect(serialized).not.toContain(csrf);
  });
});
