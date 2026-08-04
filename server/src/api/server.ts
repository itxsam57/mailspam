import express from "express";
import type { Request, Response } from "express";
import { dirname, join } from "node:path";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { sessionStore } from "./sessionStore.js";
import { createAdapter, type AdapterConfig } from "./adapterConfig.js";
import { Worker } from "node:worker_threads";
import { blockSender, blockDomain, moveMessagesToTrash } from "../workflows/blockAndCleanup.js";
import { executeOneClickUnsubscribe } from "../workflows/unsubscribe.js";
import { analyzeLinks } from "../workflows/analyzeLinks.js";
import { hardenedFetch } from "../util/hardenedFetch.js";
import type { Provider } from "../canonical/envelope.js";
import { runDeveloperTestSuite } from "../devtools/testSuiteRunner.js";

export function createServer() {
  const app = express();
  app.use(express.json());

  const __dirname = dirname(fileURLToPath(import.meta.url));
  const webDir = join(__dirname, "../../../web");
  const dashboardHtml = readFileSync(join(webDir, "index.html"), "utf8").replace(
    "</body>",
    '<script src="/scan-monitor.js"></script></body>',
  );
  app.get("/", (_req, res) => res.type("html").send(dashboardHtml));
  app.use(express.static(webDir));

  app.post("/api/accounts/connect", async (req: Request, res: Response) => {
    const { provider, mode, credentials = {}, label } = req.body as {
      provider: Provider;
      mode: "fixture" | "live";
      credentials?: Record<string, string>;
      label?: string;
    };
    try {
      let config: AdapterConfig;
      if (mode === "fixture") config = { provider, mode };
      else if (provider === "gmail") config = { provider, mode, credentials: { clientId: credentials.clientId ?? "", clientSecret: credentials.clientSecret ?? "", refreshToken: credentials.refreshToken ?? "" } };
      else if (provider === "outlook") config = { provider, mode, credentials: { clientId: credentials.clientId ?? "", clientSecret: credentials.clientSecret ?? "", tenantId: credentials.tenantId ?? "common", refreshToken: credentials.refreshToken ?? "" } };
      else if (provider === "icloud" || provider === "yahoo") config = { provider, mode, credentials: { user: credentials.user ?? "", appPassword: credentials.appPassword ?? "" } };
      else config = { provider: "imap", mode, credentials: { host: credentials.host ?? "", port: Number(credentials.port ?? 993), secure: credentials.secure !== "false", user: credentials.user ?? "", appPassword: credentials.appPassword ?? "" } };

      const adapter = createAdapter(config);
      const ac = new AbortController();
      const timeout = setTimeout(() => ac.abort(), 15000);
      try { await adapter.connect(ac.signal); await adapter.listFolders(ac.signal); }
      finally { clearTimeout(timeout); await adapter.disconnect(); }
      const session = sessionStore.create(provider, label ?? `${provider} (${mode})`, config);
      res.json({ accountId: session.id, provider: session.provider, label: session.label, mode });
    } catch (err) {
      res.status(502).json({ error: `Failed to connect: ${(err as Error).message}` });
    }
  });

  app.get("/api/accounts", (_req: Request, res: Response) => {
    res.json(sessionStore.list().map((s) => ({ accountId: s.id, provider: s.provider, label: s.label })));
  });

  app.delete("/api/accounts/:id", async (req: Request, res: Response) => {
    await sessionStore.remove(req.params.id!);
    res.status(204).send();
  });

  function sseHeaders(res: Response) {
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    });
  }

  app.get("/api/accounts/:id/scan/:type", async (req: Request, res: Response) => {
    const session = sessionStore.get(req.params.id!);
    if (!session) return res.status(404).json({ error: "Unknown account" });
    const type = req.params.type as "quick" | "full" | "spam";
    if (!["quick", "full", "spam"].includes(type)) return res.status(400).json({ error: "Unknown scan type" });
    if (session.activeScanWorker) return res.status(409).json({ error: "A scan is already active" });

    sseHeaders(res);
    res.flushHeaders();
    res.write(`event: scan-started\ndata: ${JSON.stringify({ type, provider: session.provider })}\n\n`);

    const isTypeScriptRuntime = import.meta.url.endsWith(".ts");
    const workerUrl = new URL(
      isTypeScriptRuntime ? "../workers/scanWorker.ts" : "../workers/scanWorker.js",
      import.meta.url,
    );

    let worker: Worker;
    try {
      worker = new Worker(workerUrl, {
        workerData: { config: session.config, type, pageSize: 20, personalPolicy: sessionStore.personalPolicy.snapshot() },
        ...(isTypeScriptRuntime ? { execArgv: ["--import", "tsx"] } : {}),
      });
    } catch (error) {
      res.write(`event: scan-error\ndata: ${JSON.stringify({ message: `Could not start scan worker: ${(error as Error).message}` })}\n\n`);
      res.end();
      return;
    }

    session.activeScanWorker = worker;
    let finished = false;
    let terminalEventSent = false;

    const writeEvent = (event: string, data: unknown) => {
      if (!res.writableEnded && !res.destroyed) {
        res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
      }
    };

    const cleanup = () => {
      if (finished) return;
      finished = true;
      if (session.activeScanWorker === worker) session.activeScanWorker = null;
      if (!res.writableEnded) res.end();
    };

    worker.on("message", (message) => {
      if (message.type === "status") writeEvent("scan-status", message.status);
      else if (message.type === "progress") {
        if (!res.writableEnded && !res.destroyed) res.write(`data: ${JSON.stringify(message.progress)}\n\n`);
      } else if (message.type === "complete") {
        terminalEventSent = true;
        writeEvent("scan-complete", {});
        cleanup();
      } else if (message.type === "error") {
        terminalEventSent = true;
        writeEvent("scan-error", { message: message.message, name: message.name });
        cleanup();
      }
    });

    worker.on("error", (error) => {
      terminalEventSent = true;
      writeEvent("scan-error", { message: error.message, name: error.name });
      cleanup();
    });

    worker.on("exit", (code) => {
      if (!terminalEventSent && !finished) {
        writeEvent("scan-error", {
          message: code === 0
            ? "Scan worker exited before returning a result."
            : `Scan worker exited unexpectedly with code ${code}.`,
        });
      }
      cleanup();
    });

    res.on("close", () => {
      if (!finished) {
        worker.postMessage({ type: "cancel" });
        setTimeout(() => { if (!finished) void worker.terminate(); }, 1000).unref();
      }
    });
  });

  app.post("/api/accounts/:id/scan/stop", async (req: Request, res: Response) => {
    const session = sessionStore.get(req.params.id!);
    if (!session) return res.status(404).json({ error: "Unknown account" });
    const worker = session.activeScanWorker;
    if (!worker) return res.json({ stopped: true, active: false });
    worker.postMessage({ type: "cancel" });
    const hardStop = setTimeout(() => { void worker.terminate(); }, 1000);
    hardStop.unref();
    res.json({ stopped: true, active: true });
  });

  app.post("/api/accounts/:id/messages/block-sender", (req: Request, res: Response) => {
    const { address } = req.body as { address: string };
    if (address) sessionStore.personalPolicy.blockSender(address);
    res.json({ blocked: true });
  });

  app.post("/api/accounts/:id/messages/block-domain", (req: Request, res: Response) => {
    const { domain } = req.body as { domain: string };
    if (domain) sessionStore.personalPolicy.blockDomain(domain);
    res.json({ blocked: true });
  });

  app.post("/api/accounts/:id/messages/trash", async (req: Request, res: Response) => {
    const session = sessionStore.get(req.params.id!);
    if (!session) return res.status(404).json({ error: "Unknown account" });
    const { providerNativeIds } = req.body as { providerNativeIds: string[] };
    const ac = new AbortController();
    const adapter = createAdapter(session.config);
    try { await adapter.connect(ac.signal); const result = await moveMessagesToTrash(adapter, providerNativeIds, ac.signal); res.json(result); }
    finally { await adapter.disconnect(); }
  });

  app.post("/api/accounts/:id/messages/unsubscribe", async (req: Request, res: Response) => {
    const { method, target } = req.body as { method: string; target: string };
    if (method !== "one_click_post") return res.json({ handledClientSide: true });
    const result = await executeOneClickUnsubscribe(target, (url) => fetch(url, { method: "POST" }));
    res.json(result);
  });

  app.post("/api/accounts/:id/messages/analyze-links", async (req: Request, res: Response) => {
    const session = sessionStore.get(req.params.id!);
    if (!session) return res.status(404).json({ error: "Unknown account" });
    const { envelope } = req.body as { envelope: import("../canonical/envelope.js").CanonicalEnvelope };
    const result = await analyzeLinks(envelope, hardenedFetch);
    res.json(result);
  });

  app.get("/api/dev/test-suite", async (_req: Request, res: Response) => {
    const report = await runDeveloperTestSuite();
    res.json(report);
  });

  return app;
}
