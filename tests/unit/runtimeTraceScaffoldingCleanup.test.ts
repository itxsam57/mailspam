import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "../..");

describe("flight recorder release-head hygiene", () => {
  it("does not ship one-shot or branch-mutating implementation workflows", () => {
    const workflows = readdirSync(join(root, ".github/workflows"));
    const forbidden = workflows.filter((name) =>
      /flight-recorder|trace-finalize|finalizer|consolidat|qualification/i.test(name),
    );
    expect(forbidden).toEqual([]);
  });

  it("does not ship branch-local codemod/reconciliation helpers", () => {
    const engineering = readdirSync(join(root, "scripts/engineering"));
    expect(engineering.filter((name) => /^apply-flight-recorder-|^reconcile-flight-recorder-/.test(name))).toEqual([]);
  });

  it("does not ship temporary flight-recorder/controller trigger or marker files", () => {
    const plans = readdirSync(join(root, "docs/superpowers/plans"));
    const forbidden = plans.filter((name) =>
      name.startsWith(".flight-recorder-")
      || name.startsWith(".keep-flight-recorder-red")
      || /trace-trigger|finalizer-trigger|qualification-trigger|consolidate-trigger/i.test(name),
    );
    expect(forbidden).toEqual([]);
    expect(existsSync(join(root, "docs/superpowers/plans/.flight-recorder-precleanup-green"))).toBe(false);
  });
});
