import { once } from "node:events";
import type { AddressInfo } from "node:net";
import { describe, expect, it } from "vitest";
import { createConsumerDesktopServer } from "../../server/src/api/consumerDesktopServer.js";

describe("consumer desktop outer security headers", () => {
  it("does not advertise the Express implementation on the outer consumer response", async () => {
    const app = createConsumerDesktopServer();
    const server = app.listen(0, "127.0.0.1");
    await once(server, "listening");

    try {
      const address = server.address() as AddressInfo;
      const response = await fetch(`http://127.0.0.1:${address.port}/__outer-security-header-probe__`);

      expect(response.headers.get("x-powered-by")).toBeNull();
    } finally {
      server.close();
      await once(server, "close");
    }
  });
});
