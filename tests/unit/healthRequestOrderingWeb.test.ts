import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const source = readFileSync(resolve(process.cwd(), "../web/consumer-product.js"), "utf8");

describe("EMA-40 Health request presentation ordering", () => {
  it("gives only the newest same-mailbox Health success authority to render", () => {
    expect(source).toContain("let healthRequestGeneration = 0");
    expect(source).toMatch(/async function runHealth\(\)[\s\S]*?const healthRequestGenerationAtStart = \+\+healthRequestGeneration;/);
    expect(source).toMatch(/const result = await post\([\s\S]*?health[\s\S]*?if \(healthRequestGenerationAtStart !== healthRequestGeneration \|\| !stillSelected\(id\)\) return;[\s\S]*?renderHealth\(result, id\);/);
  });

  it("prevents a stale Health failure from replacing newer same-mailbox status", () => {
    expect(source).toMatch(/catch \(error\) \{[\s\S]*?if \(healthRequestGenerationAtStart !== healthRequestGeneration\) return;[\s\S]*?if \(!id \|\| stillSelected\(id\)\) setHealthStatus/);
  });
});
