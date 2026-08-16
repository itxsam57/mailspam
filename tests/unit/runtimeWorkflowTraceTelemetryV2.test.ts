import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "../..");
const telemetry = readFileSync(join(root, "server/src/telemetry/technicalTelemetry.ts"), "utf8");

describe("workflow trace telemetry v2 architecture", () => {
  it("mirrors workflow/checkpoint/build correlation through the existing opt-in event", () => {
    expect(telemetry).toContain("email_shield_workflow_trace");
    expect(telemetry).toContain("workflow_id");
    expect(telemetry).toContain("checkpoint_id");
    expect(telemetry).toContain("build_id");
  });

  it("keeps optional source diagnosis identifiers bounded instead of sending raw errors", () => {
    expect(telemetry).toContain("error_location_id");
    expect(telemetry).not.toContain("session replay");
    expect(telemetry).not.toContain("raw_error");
    expect(telemetry).not.toContain("email_body");
  });
});
