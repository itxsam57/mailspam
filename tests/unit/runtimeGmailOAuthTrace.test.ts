import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "../..");
const onboarding = readFileSync(join(root, "web/consumer-provider-onboarding.js"), "utf8");

describe("Gmail OAuth final-testing trace", () => {
  it("records authenticated and persisted milestones before visible confirmation", () => {
    const authenticated = onboarding.indexOf("provider.connect.gmail.provider_authenticated");
    const persisted = onboarding.indexOf("provider.connect.gmail.connection_persisted");
    const visible = onboarding.indexOf("provider.connect.gmail.ui_confirmed");
    expect(authenticated).toBeGreaterThanOrEqual(0);
    expect(persisted).toBeGreaterThan(authenticated);
    expect(visible).toBeGreaterThan(persisted);
  });
});
