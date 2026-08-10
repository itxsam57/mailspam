import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { sha256Hex } from "../../server/src/core/sha256.js";

describe("portable synchronous SHA-256", () => {
  it.each([
    "",
    "abc",
    "email-shield-message-exception-v1\0account\0gmail\0message\0sender@example.test",
    "Unicode: café — 安全 — 🛡️",
    "x".repeat(55),
    "x".repeat(56),
    "x".repeat(64),
    "x".repeat(65),
    "bounded".repeat(10_000),
  ])("matches the platform cryptographic implementation", (value) => {
    expect(sha256Hex(value)).toBe(createHash("sha256").update(value, "utf8").digest("hex"));
  });
});
