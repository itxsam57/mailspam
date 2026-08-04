import { describe, expect, it } from "vitest";
import { normalizeHeaderText, parseAuthResultsHeader } from "../../server/src/util/mimeNormalize.js";

describe("provider header normalization", () => {
  it("accepts string, Buffer, array, and structured header values", () => {
    expect(normalizeHeaderText("spf=pass")).toBe("spf=pass");
    expect(normalizeHeaderText(Buffer.from("dkim=fail", "utf8"))).toBe("dkim=fail");
    expect(normalizeHeaderText(["spf=pass", Buffer.from("dmarc=pass")])).toBe("spf=pass; dmarc=pass");
    expect(normalizeHeaderText({ value: "arc=pass" })).toBe("arc=pass");
    expect(normalizeHeaderText({ text: "spf=neutral" })).toBe("spf=neutral");
  });

  it("never calls string methods on a non-string authentication header", () => {
    const fromBuffer = parseAuthResultsHeader(Buffer.from("spf=pass; dkim=fail; dmarc=pass; arc=none"));
    expect(fromBuffer).toMatchObject({ spf: "pass", dkim: "fail", dmarc: "pass", arc: "none" });

    const fromArray = parseAuthResultsHeader(["spf=softfail", { value: "dkim=pass; dmarc=fail" }]);
    expect(fromArray).toMatchObject({ spf: "softfail", dkim: "pass", dmarc: "fail" });
  });

  it("returns unknown authentication signals for unusable values", () => {
    expect(parseAuthResultsHeader({})).toEqual({
      spf: "unknown",
      dkim: "unknown",
      dmarc: "unknown",
      arc: "unknown",
    });
  });
});
