import { readFileSync, writeFileSync } from "node:fs";

function replaceExact(text, from, to, label, expectedCount = 1) {
  const count = text.split(from).length - 1;
  if (count !== expectedCount) {
    throw new Error(`${label}: expected ${expectedCount} occurrence(s), found ${count}`);
  }
  return text.split(from).join(to);
}

function edit(path, transform) {
  const before = readFileSync(path, "utf8");
  const after = transform(before);
  if (after === before) throw new Error(`${path}: guarded transform made no change`);
  writeFileSync(path, after);
}

edit("server/src/api/localDesktopServer.ts", (source) => {
  let next = source;
  next = replaceExact(
    next,
    "resolveMailboxAccountKey: (sessionId) => sessionStore.get(sessionId)?.policyAccountKey ?? null,",
    "resolveMailboxAccountKey: (sessionId) => sessionStore.getCanonical(sessionId)?.policyAccountKey ?? null,",
    "account-platform mailbox resolver",
  );

  const freshRoutes = [
    [
      'app.get("/api/accounts/:id/background-protection", (req: Request, res: Response) => {\n    const session = sessionStore.get(req.params.id!);',
      'app.get("/api/accounts/:id/background-protection", (req: Request, res: Response) => {\n    const session = sessionStore.getCanonical(req.params.id!);',
      "background status",
    ],
    [
      'app.post("/api/accounts/:id/background-protection", (req: Request, res: Response) => {\n    const session = sessionStore.get(req.params.id!);',
      'app.post("/api/accounts/:id/background-protection", (req: Request, res: Response) => {\n    const session = sessionStore.getCanonical(req.params.id!);',
      "background configure",
    ],
    [
      'app.get("/api/accounts/:id/scan-history", (req: Request, res: Response) => {\n    const session = sessionStore.get(req.params.id!);',
      'app.get("/api/accounts/:id/scan-history", (req: Request, res: Response) => {\n    const session = sessionStore.getCanonical(req.params.id!);',
      "scan history",
    ],
    [
      'app.post("/api/accounts/:id/messages/unblock-sender", (req: Request, res: Response) => {\n    const session = sessionStore.get(req.params.id!);',
      'app.post("/api/accounts/:id/messages/unblock-sender", (req: Request, res: Response) => {\n    const session = sessionStore.getCanonical(req.params.id!);',
      "unblock sender",
    ],
    [
      'app.post("/api/accounts/:id/messages/unblock-domain", (req: Request, res: Response) => {\n    const session = sessionStore.get(req.params.id!);',
      'app.post("/api/accounts/:id/messages/unblock-domain", (req: Request, res: Response) => {\n    const session = sessionStore.getCanonical(req.params.id!);',
      "unblock domain",
    ],
  ];
  for (const [from, to, label] of freshRoutes) next = replaceExact(next, from, to, label);

  if (!next.includes('app.delete("/api/accounts/:id", async (req: Request, res: Response) => {\n    const id = req.params.id!;\n    const session = sessionStore.get(id);')) {
    throw new Error("Disconnect must retain broad SessionStore.get cleanup ownership");
  }
  if (!next.includes('app.post("/api/accounts/:id/scan/stop", async (req: Request, res: Response) => {\n    const session = sessionStore.get(req.params.id!);')) {
    throw new Error("Scan stop must retain broad SessionStore.get cleanup ownership");
  }
  return next;
});

edit("server/src/api/policyManagement.ts", (source) => replaceExact(
  source,
  "const session = sessionStore.get(req.params.id!);",
  "const session = sessionStore.getCanonical(req.params.id!);",
  "personal-policy shared account owner",
));

edit("server/src/api/protectionActions.ts", (source) => {
  const routeLookup = "sessions.get(req.params.id!)";
  const count = source.split(routeLookup).length - 1;
  if (count < 1) throw new Error("Protection actions: expected broad route lookups");
  let next = source.split(routeLookup).join("sessions.getCanonical(req.params.id!)");
  next = next.split('SessionStore["get"]').join('SessionStore["getCanonical"]');
  if (next.includes(routeLookup)) throw new Error("Protection actions: stale broad route lookup remains");
  return next;
});

edit("server/src/api/familyAwareScanStream.ts", (source) => replaceExact(
  source,
  "const session = sessionStore.get(req.params.id!);",
  "const session = sessionStore.getCanonical(req.params.id!);",
  "family-aware scan account owner",
));

edit("server/src/api/scanStream.ts", (source) => {
  let next = replaceExact(
    source,
    "const session = sessionStore.get(req.params.id!);",
    "const session = sessionStore.getCanonical(req.params.id!);",
    "scan start/resume account owner",
  );
  next = next.split("ReturnType<typeof sessionStore.get>").join("ReturnType<typeof sessionStore.getCanonical>");
  return next;
});

console.log("EMA-34 Task 4 guarded canonical-route transform applied.");
