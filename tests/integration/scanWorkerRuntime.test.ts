import { describe, expect, it } from "vitest";
import { Worker } from "node:worker_threads";

describe("scan worker runtime", () => {
  it("starts the compiled worker and returns fixture progress on every platform", async () => {
    const workerUrl = new URL("../../server/dist/workers/scanWorker.js", import.meta.url);
    const messages: Array<Record<string, unknown>> = [];
    const worker = new Worker(workerUrl, {
      workerData: {
        config: { provider: "gmail", mode: "fixture" },
        type: "quick",
        pageSize: 2,
        personalPolicy: {},
      },
    });

    await new Promise<void>((resolve, reject) => {
      let receivedStatus = false;
      const startupTimeout = setTimeout(() => {
        void worker.terminate();
        reject(new Error("compiled scan worker did not report startup within 10 seconds"));
      }, 10_000);
      const completionTimeout = setTimeout(() => {
        void worker.terminate();
        reject(new Error("compiled scan worker did not complete within 30 seconds"));
      }, 30_000);

      const clearTimers = () => {
        clearTimeout(startupTimeout);
        clearTimeout(completionTimeout);
      };

      worker.on("message", (message) => {
        messages.push(message as Record<string, unknown>);
        const type = (message as { type?: string }).type;
        if (type === "status" && !receivedStatus) {
          receivedStatus = true;
          clearTimeout(startupTimeout);
        }
        if (type === "complete") {
          clearTimers();
          resolve();
        }
        if (type === "error") {
          clearTimers();
          reject(new Error(String((message as { message?: string }).message ?? "worker error")));
        }
      });
      worker.on("error", (error) => {
        clearTimers();
        reject(error);
      });
      worker.on("exit", (code) => {
        if (code !== 0 && !messages.some((message) => message.type === "complete")) {
          clearTimers();
          reject(new Error(`compiled scan worker exited with code ${code}`));
        }
      });
    });

    expect(messages.some((message) => message.type === "status")).toBe(true);
    expect(messages.some((message) => message.type === "progress")).toBe(true);
    expect(messages.some((message) => message.type === "complete")).toBe(true);
    await worker.terminate();
  }, 35_000);
});
