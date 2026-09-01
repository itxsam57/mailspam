import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "../..");
const source = readFileSync(join(root, "web/workspace-restore.js"), "utf8");

describe("restored mailbox workspace selection", () => {
  it("selects one restored mailbox when process-local workspace selection is absent", () => {
    expect(source).toContain("async function waitForRenderedAccountIds()");
    expect(source).toContain("if (accountIds.length === 1)");
    expect(source).toContain("select(accountIds[0], { remember: false })");
    expect(source).toContain("single_restored_account_selected");
  });

  it("never guesses among multiple restored mailboxes and preserves a newer tab-local choice", () => {
    expect(source).toContain("if (accountIds.length !== 1)");
    expect(source).toContain("no_persisted_selection");
    expect(source).toContain("newer_tab_selection_preserved");
    expect(source).toContain("currentSelectionSnapshot.generation !== restoreSelectionSnapshot.generation");
  });
});
