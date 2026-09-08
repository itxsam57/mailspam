import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "../..");
const readJson = (path: string) => JSON.parse(readFileSync(join(root, path), "utf8"));

describe("current production dependency security floor", () => {
  it("forces qs to the patched 6.16.0 line across transitive consumers", () => {
    const packageJson = readJson("package.json");
    const lock = readJson("package-lock.json");
    const register = readFileSync(join(root, ".engineering/REGRESSION_REGISTER.md"), "utf8");

    expect(packageJson.overrides?.qs).toBe("6.16.0");
    expect(lock.packages?.["node_modules/qs"]?.version).toBe("6.16.0");
    expect(register).toContain("REG-090");
    expect(register).toContain("GHSA-4mjr-xmp4-gh2g");
    expect(register).toContain("GHSA-x5fp-wj9c-mxmx");
  });
});
