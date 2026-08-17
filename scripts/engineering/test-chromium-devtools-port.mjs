import assert from "node:assert/strict";
import { waitForDevToolsPort } from "./chromium-devtools-port.mjs";

function transient(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

{
  const reads = [
    () => { throw transient("EBUSY", "temporarily locked"); },
    () => "\n",
    () => "9222\n/devtools/browser/test",
  ];
  const port = await waitForDevToolsPort(
    "/tmp/profile",
    { exitCode: null },
    () => "",
    1_000,
    {
      readPortFile: () => reads.shift()?.() ?? "9222\n",
      delay: async () => {},
    },
  );
  assert.equal(port, 9222, "transient EBUSY and incomplete contents must be retried inside the existing bound");
}

{
  const port = await waitForDevToolsPort(
    "/tmp/profile",
    { exitCode: null },
    () => "",
    1_000,
    {
      readPortFile: () => { throw transient("ENOENT", "not created yet"); },
      delay: async () => {},
    },
  ).catch((error) => error);
  assert(port instanceof Error, "persistent ENOENT must still time out rather than fabricate a port");
  assert.match(port.message, /Timed out waiting for Chromium/u);
}

{
  const accessDenied = transient("EACCES", "permission denied");
  await assert.rejects(
    waitForDevToolsPort(
      "/tmp/profile",
      { exitCode: null },
      () => "",
      1_000,
      {
        readPortFile: () => { throw accessDenied; },
        delay: async () => {},
      },
    ),
    (error) => error === accessDenied,
    "unexpected filesystem failures must remain fail-fast",
  );
}

{
  await assert.rejects(
    waitForDevToolsPort(
      "/tmp/profile",
      { exitCode: 9 },
      () => "chromium failed",
      1_000,
      { readPortFile: () => "9222\n", delay: async () => {} },
    ),
    /Chromium exited before publishing DevToolsActivePort with code 9/u,
  );
}

console.log("Chromium DevToolsActivePort retry contract passed.");
