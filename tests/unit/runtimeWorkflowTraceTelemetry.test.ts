import { describe, expect, it, vi } from "vitest";
import { createTechnicalTelemetryFromEnvironment } from "../../server/src/telemetry/technicalTelemetry.js";

describe("runtime workflow trace telemetry mirror", () => {
  it("stays disabled unless the existing technical telemetry opt-in is enabled", async () => {
    const fetchImpl = vi.fn<typeof fetch>();
    const telemetry = createTechnicalTelemetryFromEnvironment({
      environment: {},
      fetchImpl,
    });
    expect(await telemetry.captureWorkflowTrace({})).toBe(false);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("mirrors only fixed privacy-safe workflow fields", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(new Response(null, { status: 200 }));
    const telemetry = createTechnicalTelemetryFromEnvironment({
      environment: {
        EMAIL_SHIELD_TELEMETRY: "1",
        EMAIL_SHIELD_POSTHOG_PROJECT_TOKEN: "phc_test",
        EMAIL_SHIELD_POSTHOG_HOST: "https://us.i.posthog.com",
      },
      platform: "win32",
      appVersion: "test",
      fetchImpl,
    });

    const accepted = await telemetry.captureWorkflowTrace({
      schemaVersion: 1,
      timestamp: "2026-08-16T00:00:00.000Z",
      runId: "11111111-1111-4111-8111-111111111111",
      traceId: "22222222-2222-4222-8222-222222222222",
      stage: "worker",
      actionId: "mailbox.scan.full",
      expectedWorkflow: "full_mailbox_audit",
      provider: "icloud",
      scanType: "full",
      component: "scan_stream",
      step: "bounded_batches",
      outcome: "started",
      pageSize: 2,
    });
    expect(accepted).toBe(true);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const body = JSON.parse(String((fetchImpl.mock.calls[0]?.[1] as RequestInit)?.body));
    expect(body.event).toBe("email_shield_workflow_trace");
    expect(body.properties).toMatchObject({
      run_id: "11111111-1111-4111-8111-111111111111",
      trace_id: "22222222-2222-4222-8222-222222222222",
      stage: "worker",
      action_id: "mailbox.scan.full",
      expected_workflow: "full_mailbox_audit",
      provider: "icloud",
      scan_type: "full",
      step: "bounded_batches",
      page_size: 2,
    });
    expect(JSON.stringify(body)).not.toContain("account_id");
  });

  it("rejects unknown fields before any remote call", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(new Response(null, { status: 200 }));
    const telemetry = createTechnicalTelemetryFromEnvironment({
      environment: {
        EMAIL_SHIELD_TELEMETRY: "1",
        EMAIL_SHIELD_POSTHOG_PROJECT_TOKEN: "phc_test",
      },
      fetchImpl,
    });
    expect(await telemetry.captureWorkflowTrace({
      schemaVersion: 1,
      timestamp: "2026-08-16T00:00:00.000Z",
      runId: "11111111-1111-4111-8111-111111111111",
      traceId: "22222222-2222-4222-8222-222222222222",
      stage: "workflow",
      actionId: "mailbox.scan.full",
      expectedWorkflow: "full_mailbox_audit",
      outcome: "failed",
      accountId: "must-not-leave-device",
    })).toBe(false);
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});
