import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

describe("detached resumable scan contract", () => {
  it("commits the protected checkpoint before skipping browser-only action-token registration", () => {
    const source = readFileSync(resolve(process.cwd(), "src/api/scanStream.ts"), "utf8");
    const progressBranch = source.indexOf('} else if (message.type === "progress")');
    const checkpointSave = source.indexOf('if (!saveRecord())', progressBranch);
    const detachedGuard = source.indexOf('if (res.writableEnded || res.destroyed) return;', checkpointSave);
    const actionRegistration = source.indexOf('const actionsByNativeId = new Map', detachedGuard);

    expect(progressBranch).toBeGreaterThanOrEqual(0);
    expect(checkpointSave).toBeGreaterThan(progressBranch);
    expect(detachedGuard).toBeGreaterThan(checkpointSave);
    expect(actionRegistration).toBeGreaterThan(detachedGuard);
  });
});
