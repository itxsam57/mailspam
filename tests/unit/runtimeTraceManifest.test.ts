import { describe, expect, it } from "vitest";
import {
  validateCheckpointManifest,
  type RuntimeTraceCheckpointManifest,
} from "../../server/src/diagnostics/checkpointManifest.js";

const buildId = "c00b15d8701aae9eee8ccb428e5efe1789ffa2dd";

function manifest(entries: RuntimeTraceCheckpointManifest["checkpoints"]): RuntimeTraceCheckpointManifest {
  return {
    schemaVersion: 1,
    buildId,
    checkpoints: entries,
  };
}

describe("runtime trace checkpoint source manifest", () => {
  it("accepts deterministic exact-build ownership metadata", () => {
    const value = manifest([
      {
        checkpointId: "family.create.state_persisted",
        workflowId: "family.create",
        component: "family_service",
        sourcePath: "server/src/account/accountLifecycleService.ts",
        owner: "createFamily",
        line: 214,
      },
      {
        checkpointId: "family.create.ui_confirmed",
        workflowId: "family.create",
        component: "family_shield_browser",
        sourcePath: "web/family-shield.js",
        owner: "createFamily",
        line: 181,
      },
    ]);

    expect(validateCheckpointManifest(value, { buildId })).toEqual(value);
  });

  it("rejects duplicate checkpoint ids instead of making source ownership ambiguous", () => {
    const duplicate = manifest([
      {
        checkpointId: "family.create.state_persisted",
        workflowId: "family.create",
        component: "family_service",
        sourcePath: "server/src/a.ts",
        owner: "createFamily",
        line: 10,
      },
      {
        checkpointId: "family.create.state_persisted",
        workflowId: "family.create",
        component: "family_service",
        sourcePath: "server/src/b.ts",
        owner: "otherOwner",
        line: 20,
      },
    ]);

    expect(validateCheckpointManifest(duplicate, { buildId })).toBeNull();
  });

  it("rejects stale build identity, absolute paths, invalid line numbers, and dynamic-looking ownership", () => {
    const unsafeCases: RuntimeTraceCheckpointManifest[] = [
      { ...manifest([]), buildId: "af48ed7d2b70b9233aba9595d08aa337cc6b7fbf" },
      manifest([{ checkpointId: "x.step", workflowId: "x", component: "x", sourcePath: "/tmp/x.ts", owner: "x", line: 1 }]),
      manifest([{ checkpointId: "x.step", workflowId: "x", component: "x", sourcePath: "server/src/x.ts", owner: "x", line: 0 }]),
      manifest([{ checkpointId: "x.${dynamic}", workflowId: "x", component: "x", sourcePath: "server/src/x.ts", owner: "x", line: 1 }]),
    ];

    for (const value of unsafeCases) {
      expect(validateCheckpointManifest(value, { buildId })).toBeNull();
    }
  });
});
