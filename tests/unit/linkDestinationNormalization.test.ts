import { describe, expect, it } from "vitest";
import {
  analyzeHtmlInteractions,
  canonicalizeWebDestination,
} from "../../server/src/util/htmlInteraction.js";

describe("link destination canonicalization", () => {
  it("decodes one whole-percent-encoded absolute HTTPS destination while preserving raw evidence", () => {
    const raw = "https%3A%2F%2Fshop.example%2Faccount%3Fmode%3Dreview";
    const result = analyzeHtmlInteractions(`<a href="${raw}">Review account</a>`, null);

    expect(result.links).toHaveLength(1);
    expect(result.links[0]?.rawUrl).toBe(raw);
    expect(result.links[0]?.normalizedUrl).toBe("https://shop.example/account?mode=review");
  });

  it("does not recursively decode a double-encoded destination", () => {
    const raw = "https%253A%252F%252Fshop.example%252Faccount";
    expect(canonicalizeWebDestination(raw, null)).toBe(raw);
  });

  it("does not decode a mixed partially encoded URL where decoding could change query semantics", () => {
    const raw = "https%3A%2F%2Fshop.example/path?next=https%3A%2F%2Fsupport.example";
    expect(canonicalizeWebDestination(raw, null)).toBe(raw);
  });

  it.each([
    "javascript%3Aalert%281%29",
    "data%3Atext%2Fhtml%2Ctest",
    "file%3A%2F%2F%2Fetc%2Fpasswd",
  ])("does not turn encoded non-web scheme %s into an executable URL", (raw) => {
    expect(canonicalizeWebDestination(raw, null)).toBe(raw);
  });

  it("rejects encoded HTTP credentials instead of canonicalizing them", () => {
    const raw = "https%3A%2F%2Fuser%3Asecret%40shop.example%2F";
    expect(canonicalizeWebDestination(raw, null)).toBe(raw);
  });

  it("canonicalizes encoded loopback only as an HTTP target so downstream SSRF blocking still owns the denial", () => {
    expect(canonicalizeWebDestination("http%3A%2F%2F127.0.0.1%2Fadmin", null)).toBe("http://127.0.0.1/admin");
  });

  it("leaves malformed percent escapes as malformed bounded evidence", () => {
    const raw = "https%3A%2F%2Fshop.example%2";
    expect(canonicalizeWebDestination(raw, null)).toBe(raw);
  });
});
