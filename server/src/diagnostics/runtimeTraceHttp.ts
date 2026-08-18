import {
  runWithRuntimeTraceRequest,
  type ResolvedRuntimeTraceWorkflow,
} from "./runtimeTraceRequestContext.js";

const MESSAGE_WORKFLOWS = Object.freeze({
  "block-sender": "message.block_sender",
  "block-domain": "message.block_domain",
  trash: "message.trash",
  "report-scam": "message.report_scam",
  "move-spam": "message.move_spam",
  "mark-safe": "message.mark_safe",
  "trust-sender": "message.trust_sender",
  unsubscribe: "message.unsubscribe",
  "analyze-links": "message.analyze_links",
} as const);

type RuntimeTraceHeaderValue = string | string[] | undefined;
type RuntimeTraceHttpHeaders = Record<string, RuntimeTraceHeaderValue>;

interface RuntimeTraceHttpRequest {
  method: string;
  path: string;
  headers: RuntimeTraceHttpHeaders;
}

type RuntimeTraceNext = () => void;

function pathOnly(value: string): string {
  const question = value.indexOf("?");
  return question >= 0 ? value.slice(0, question) : value;
}

function resolved(workflowId: string, options: Partial<ResolvedRuntimeTraceWorkflow> = {}): ResolvedRuntimeTraceWorkflow {
  return {
    workflowId,
    actionId: workflowId,
    ...options,
  };
}

/**
 * Resolve one protected desktop HTTP request to its canonical diagnostic
 * workflow without carrying mailbox/account identifiers into the trace. The
 * mapping is intentionally fail-closed: ambiguous and unknown routes produce
 * no workflow context rather than an invented correlation.
 */
export function resolveRuntimeHttpWorkflow(
  method: string,
  rawPathname: string,
): ResolvedRuntimeTraceWorkflow | null {
  const verb = String(method || "GET").toUpperCase();
  const pathname = pathOnly(String(rawPathname || ""));

  const scan = pathname.match(/^\/api\/accounts\/[^/]+\/scan\/(quick|full|spam)$/);
  if (verb === "GET" && scan) {
    const scanType = scan[1] as "quick" | "full" | "spam";
    return resolved(`mailbox.scan.${scanType}`, { scanType });
  }

  if (verb === "POST" && /^\/api\/accounts\/[^/]+\/scan\/stop$/.test(pathname)) {
    return resolved("mailbox.scan.stop");
  }
  if (verb === "GET" && /^\/api\/accounts\/[^/]+\/scan\/resume\/[^/]+$/.test(pathname)) {
    return resolved("mailbox.scan.resume");
  }
  if (verb === "GET" && /^\/api\/accounts\/[^/]+\/scan-history$/.test(pathname)) {
    return resolved("mailbox.scan.history");
  }

  const message = pathname.match(/^\/api\/accounts\/[^/]+\/messages\/([a-z-]+)$/);
  if (verb === "POST" && message) {
    const workflowId = MESSAGE_WORKFLOWS[message[1] as keyof typeof MESSAGE_WORKFLOWS];
    return workflowId ? resolved(workflowId) : null;
  }

  if (verb === "POST" && /^\/api\/accounts\/[^/]+\/background-protection$/.test(pathname)) {
    return resolved("protection.background.toggle");
  }
  if (verb === "POST" && pathname === "/api/accounts/workspace") {
    return resolved("account.select");
  }
  if (verb === "DELETE" && /^\/api\/accounts\/[^/]+$/.test(pathname)) {
    return resolved("account.disconnect");
  }

  if (verb === "POST" && /^\/api\/consumer\/v1\/accounts\/[^/]+\/health$/.test(pathname)) {
    return resolved("mailbox.health.run");
  }
  if (verb === "GET" && pathname === "/api/consumer/v1/support-bundle") {
    return resolved("support.bundle.export");
  }

  // Provider connection is intentionally not inferred from the generic
  // /api/accounts/connect route. Its payload is the only place that names the
  // provider, and diagnostics never read request bodies to choose a workflow.
  return null;
}

/**
 * Canonical desktop request correlation boundary. This middleware does not
 * authorize the request and does not inspect request bodies. It only binds a
 * valid opaque browser trace UUID to workflow identity derived from the trusted
 * method/path map for the lifetime of downstream execution.
 */
export function createRuntimeTraceHttpMiddleware() {
  return (req: RuntimeTraceHttpRequest, _res: unknown, next: RuntimeTraceNext): void => {
    const workflow = resolveRuntimeHttpWorkflow(req.method, req.path);
    if (!workflow) {
      next();
      return;
    }
    runWithRuntimeTraceRequest(req.headers, workflow, next);
  };
}
