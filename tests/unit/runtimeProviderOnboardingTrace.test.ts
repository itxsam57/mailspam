import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "../..");
const source = readFileSync(join(root, "web/consumer-provider-onboarding.js"), "utf8");

describe("consumer provider onboarding runtime trace", () => {
  it("confirms Gmail/iCloud/Yahoo/IMAP only after visible account-list growth", () => {
    expect(source).toContain("provider.connect.gmail.ui_confirmed");
    expect(source).toContain("provider.connect.icloud.ui_confirmed");
    expect(source).toContain("provider.connect.yahoo.ui_confirmed");
    expect(source).toContain("provider.connect.imap.ui_confirmed");
    expect(source).toContain("childElementCount");
    expect(source).toContain("MutationObserver");
  });

  it("does not expose Outlook through the normal consumer onboarding trace", () => {
    expect(source).not.toContain("provider.connect.outlook.ui_confirmed");
  });
});
