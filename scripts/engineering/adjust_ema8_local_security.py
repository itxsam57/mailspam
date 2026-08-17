from pathlib import Path

path = Path("server/src/api/localSecurity.ts")
source = path.read_text(encoding="utf-8")
replacements = [
    (
        '''  nonces: Map<string, number>;
  usedActionTokens: Set<string>;
  rateEvents: Map<string, number[]>;
''',
        '''  nonces: Map<string, number>;
  rateEvents: Map<string, number[]>;
''',
    ),
    (
        '''        nonces: new Map(),
        usedActionTokens: new Set(),
        rateEvents: new Map(),
''',
        '''        nonces: new Map(),
        rateEvents: new Map(),
''',
    ),
    (
        '''      const actionToken = typeof req.body?.token === "string" ? req.body.token : null;
      if (actionToken && session.usedActionTokens.has(actionToken)) {
        res.status(409).json({ error: "This message action has already been used. Rescan before performing another action." });
        return;
      }

''',
        '''      // Opaque mailbox action capabilities have operation-specific replay
      // semantics owned by their route/session registries. This generic local
      // security boundary authenticates the dashboard request with a one-time
      // mutation nonce; it must not globally spend an application capability.

''',
    ),
    (
        '''      if (actionToken) {
        const originalJson = res.json.bind(res);
        res.json = ((body: unknown) => {
          const locallyApplied = Boolean(body && typeof body === "object" && "localProtected" in body && (body as { localProtected?: unknown }).localProtected === true);
          if (res.statusCode < 400 || locallyApplied) session.usedActionTokens.add(actionToken);
          return originalJson(body);
        }) as typeof res.json;
      }
      next();
''',
        '''      next();
''',
    ),
]
for before, after in replacements:
    count = source.count(before)
    if count != 1:
        raise RuntimeError(f"expected local security source block exactly once, found {count}")
    source = source.replace(before, after, 1)
path.write_text(source, encoding="utf-8")
print("EMA-8 generic local security no longer globally spends semantic message capabilities")
