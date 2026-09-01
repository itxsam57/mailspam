import http from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { gzipSync } from "node:zlib";

const here = dirname(fileURLToPath(import.meta.url));
const credentialTrap = await readFile(
  join(here, "../../../acceptance-fixtures/analyze-links/credential-trap.html"),
  "utf8",
);
const compressedBody = gzipSync(Buffer.from("controlled compressed Analyze Links response", "utf8"));
const port = Number(process.env.PORT || 8787);

function send(res, statusCode, headers, body = "") {
  res.writeHead(statusCode, { "Cache-Control": "no-store", ...headers });
  res.end(body);
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url || "/", "http://127.0.0.1");

  if (url.pathname === "/health") {
    send(res, 200, { "Content-Type": "text/plain; charset=utf-8" }, "ok");
    return;
  }

  if (url.pathname === "/direct") {
    send(res, 200, { "Content-Type": "text/html; charset=utf-8" }, credentialTrap);
    return;
  }

  if (url.pathname === "/redirect-public") {
    send(res, 302, { Location: "/direct", "Content-Type": "text/plain; charset=utf-8" }, "redirecting");
    return;
  }

  if (url.pathname === "/redirect-private") {
    send(res, 302, { Location: `http://127.0.0.1:${port}/private`, "Content-Type": "text/plain; charset=utf-8" }, "blocked redirect target");
    return;
  }

  if (url.pathname === "/oversize") {
    const body = Buffer.alloc(600 * 1024, 0x78);
    res.writeHead(200, {
      "Cache-Control": "no-store",
      "Content-Type": "text/html; charset=utf-8",
      "Content-Length": String(body.length),
    });
    res.end(body);
    return;
  }

  if (url.pathname === "/compressed") {
    res.writeHead(200, {
      "Cache-Control": "no-store",
      "Content-Type": "text/html; charset=utf-8",
      "Content-Encoding": "gzip",
      "Content-Length": String(compressedBody.length),
    });
    res.end(compressedBody);
    return;
  }

  if (url.pathname === "/unsupported") {
    send(res, 200, { "Content-Type": "application/octet-stream" }, "opaque bytes");
    return;
  }

  if (url.pathname === "/headers") {
    const evidence = {
      authorizationPresent: typeof req.headers.authorization === "string",
      cookiePresent: typeof req.headers.cookie === "string",
      userAgent: req.headers["user-agent"] ?? null,
      acceptEncoding: req.headers["accept-encoding"] ?? null,
      method: req.method ?? null,
    };
    send(res, 200, { "Content-Type": "text/plain; charset=utf-8" }, JSON.stringify(evidence));
    return;
  }

  if (url.pathname === "/private") {
    send(res, 500, { "Content-Type": "text/plain; charset=utf-8" }, "THIS ROUTE MUST NEVER BE REACHED THROUGH ANALYZE LINKS");
    return;
  }

  send(res, 404, { "Content-Type": "text/plain; charset=utf-8" }, "not found");
});

server.listen(port, "127.0.0.1", () => {
  console.log(`controlled Analyze Links target listening on 127.0.0.1:${port}`);
});

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
