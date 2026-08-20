import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const source = readFileSync(resolve(process.cwd(), "web/consumer-product.js"), "utf8");

describe("EMA-40 Health request presentation ordering", () => {
  it("gives only the newest same-mailbox Health request authority to mutate presentation state", () => {
    expect(source).toContain("let healthRequestGeneration = 0");
    expect(source).toMatch(/async function runHealth\(\)[\s\S]*?const healthRequestGenerationAtStart = \+\+healthRequestGeneration;/);
    expect(source).toMatch(/const result = await post\([\s\S]*?health[\s\S]*?if \(healthRequestGenerationAtStart !== healthRequestGeneration \|\| !selectionMatches\(selection\)\) return;[\s\S]*?state\.health = result;[\s\S]*?renderHealth\(\);/);
  });

  it("prevents a stale Health request from clearing or replacing UI state owned by a newer request", () => {
    expect(source).toMatch(/catch \(error\) \{[\s\S]*?healthRequestGenerationAtStart === healthRequestGeneration[\s\S]*?selectionMatches\(selection\)[\s\S]*?setStatus/);
    expect(source).toMatch(/finally \{[\s\S]*?healthRequestGenerationAtStart === healthRequestGeneration[\s\S]*?selectionMatches\(selection\)[\s\S]*?healthRun\.disabled = false/);
  });
});
