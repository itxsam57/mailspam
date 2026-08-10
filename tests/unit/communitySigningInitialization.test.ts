import { spawn } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { CommunityFeedSigner } from "../../server/src/community/signing.js";

const directories: string[] = [];

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "email-shield-community-signing-init-"));
  directories.push(directory);
  return directory;
}

describe("community signing-key initialization integrity", () => {
  it("waits for a competing initializer to complete the same key pair", async () => {
    const directory = temporaryDirectory();
    const privatePath = join(directory, "community-feed-private.pem");
    const publicPath = join(directory, "community-feed-public.pem");
    const pair = generateKeyPairSync("ed25519");
    const privatePem = pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const publicPem = pair.publicKey.export({ type: "spki", format: "pem" }).toString();
    writeFileSync(privatePath, privatePem, { flag: "wx", mode: 0o600 });

    const child = spawn(process.execPath, [
      "-e",
      "setTimeout(() => require('node:fs').writeFileSync(process.env.PUBLIC_PATH, Buffer.from(process.env.PUBLIC_PEM, 'base64'), { flag: 'wx', mode: 0o644 }), 75)",
    ], {
      env: {
        ...process.env,
        PUBLIC_PATH: publicPath,
        PUBLIC_PEM: Buffer.from(publicPem, "utf8").toString("base64"),
      },
      stdio: ["ignore", "pipe", "pipe"],
    });

    const signer = new CommunityFeedSigner(directory);
    const exitCode = await new Promise<number | null>((resolve, reject) => {
      child.once("error", reject);
      child.once("exit", resolve);
    });
    expect(exitCode).toBe(0);
    expect(signer.publicPem).toBe(publicPem);
  });

  it("still fails closed for an abandoned incomplete key pair", () => {
    const directory = temporaryDirectory();
    const pair = generateKeyPairSync("ed25519");
    writeFileSync(
      join(directory, "community-feed-private.pem"),
      pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
      { flag: "wx", mode: 0o600 },
    );

    expect(() => new CommunityFeedSigner(directory)).toThrow("key storage is incomplete");
  });
});
