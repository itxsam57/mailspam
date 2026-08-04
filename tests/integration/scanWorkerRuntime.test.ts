import { describe, expect, it } from "vitest";
import { Worker } from "node:worker_threads";

describe("scan worker runtime", () => {
  it("starts the real TypeScript worker in development and returns fixture progress", async () => {
    const workerUrl = new URL("../../server/src/workers/scanWorker.ts", import.meta.url);
    const messages: Array<Record<string, unknown>> = [];
    const worker = new Worker(workerUrl, {
      workerData: {
        config: { provider: "gmail", mode: "fixture" },
        type: "quick",
        pageSize: 2,
        personalPolicy: {},
      },
      execArgv: ["--import", "tsx"],
    });

    await new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => {
        void worker.terminate();
        reject(new Error("scan worker did not complete within 10 seconds"));
      }, 10_000);

      worker.on("message", (message) => {
        messages.push(message as Record<string, unknown>);
        if ((message as { type?: string }).type === "complete") {
          clearTimeout(timeout);
          resolve();
        }
        if ((message as { type?: string }).type === "error") {
          clearTimeout(timeout);
          reject(new Error(String((message as { message?: string }).message ?? "worker error")));
        }
      });
      worker.on("error", (error) => {
        clearTimeout(timeout);
        reject(error);
      });
    });

    expect(messages.some((message) => message.type === "status")).toBe(true);
    expect(messages.some((message) => message.type === "progress")).toBe(true);
    expect(messages.some((message) => message.type === "complete")).toBe(true);
    await worker.terminate();
  });
});
