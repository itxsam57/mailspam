import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { createTechnicalTelemetryFromEnvironment } from "../../server/src/telemetry/technicalTelemetry.js";

const enabledEnvironment = {
  EMAIL_SHIELD_TELEMETRY: "1",
  EMAIL_SHIELD_POSTHOG_PROJECT_TOKEN: "test-project-token",
  EMAIL_SHIELD_POSTHOG_HOST: "https://us.i.posthog.com",
};

describe("technical telemetry", () => {
  it("is disabled unless the user explicitly opts in", async () => {
    const requests: Array<{ url: string; init?: RequestInit }> = [];
    const telemetry = createTechnicalTelemetryFromEnvironment({
      environment: {},
      platform: "win32",
      appVersion: "0.2.0",
      fetchImpl: async (input, init) => {
        requests.push({ url: String(input), init });
        return new Response(null, { status: 200 });
      },
    });

    expect(await telemetry.capture("email_shield_app_started")).toBe(false);
    expect(requests).toHaveLength(0);
  });

  it("sends only anonymous allowlisted technical properties", async () => {
    const requests: Array<{ url: string; init?: RequestInit }> = [];
    const telemetry = createTechnicalTelemetryFromEnvironment({
      environment: enabledEnvironment,
      platform: "win32",
      appVersion: "0.2.0",
      fetchImpl: async (input, init) => {
        requests.push({ url: String(input), init });
        return new Response(null, { status: 200 });
      },
    });

    expect(
      await telemetry.capture("email_shield_protected_state_ready", {
        duration_ms: 321,
      }),
    ).toBe(true);
    expect(requests).toHaveLength(1);
    expect(requests[0]?.url).toBe("https://us.i.posthog.com/capture/");

    const body = JSON.parse(String(requests[0]?.init?.body)) as {
      api_key: string;
      distinct_id: string;
      event: string;
      properties: Record<string, unknown>;
    };
    expect(body.api_key).toBe("test-project-token");
    expect(body.distinct_id).toBe("email-shield-desktop-runtime");
    expect(body.event).toBe("email_shield_protected_state_ready");
    expect(body.properties).toEqual({
      $process_person_profile: false,
      $geoip_disable: true,
      component: "desktop_server",
      app_version: "0.2.0",
      platform: "win32",
      duration_ms: 321,
    });
    expect(JSON.stringify(body.properties)).not.toContain("test-project-token");
  });

  it("refuses unknown events or properties instead of risking sensitive-data capture", async () => {
    const requests: Array<{ url: string; init?: RequestInit }> = [];
    const telemetry = createTechnicalTelemetryFromEnvironment({
      environment: enabledEnvironment,
      platform: "linux",
      appVersion: "0.2.0",
      fetchImpl: async (input, init) => {
        requests.push({ url: String(input), init });
        return new Response(null, { status: 200 });
      },
    });

    expect(
      await (telemetry.capture as (event: string, properties?: Record<string, unknown>) => Promise<boolean>)(
        "email_shield_protected_state_ready",
        { email_body: "must never leave the device" },
      ),
    ).toBe(false);
    expect(
      await (telemetry.capture as (event: string, properties?: Record<string, unknown>) => Promise<boolean>)(
        "arbitrary_event",
      ),
    ).toBe(false);
    expect(requests).toHaveLength(0);
  });

  it("fails closed without affecting the application when PostHog is unreachable", async () => {
    const telemetry = createTechnicalTelemetryFromEnvironment({
      environment: enabledEnvironment,
      platform: "darwin",
      appVersion: "0.2.0",
      fetchImpl: async () => {
        throw new Error("network unavailable");
      },
    });

    await expect(telemetry.capture("email_shield_app_started")).resolves.toBe(false);
  });

  it("wires only privacy-safe desktop startup lifecycle events", () => {
    const root = join(import.meta.dirname, "../..");
    const source = readFileSync(join(root, "server/src/index.ts"), "utf8");

    expect(source).toContain('createTechnicalTelemetryFromEnvironment');
    expect(source).toContain('telemetry.capture("email_shield_app_started")');
    expect(source).toContain('telemetry.capture("email_shield_protected_state_ready"');
    expect(source).toContain('telemetry.capture("email_shield_protected_state_failed"');
    expect(source).toContain('failure_kind: "initialization_error"');
    expect(source).toContain('telemetry.capture("email_shield_server_listening")');
    expect(source).not.toContain('telemetry.capture("mailbox_');
    expect(source).not.toContain('telemetry.capture("message_');
    expect(source).not.toContain('email_body:');
  });
});
