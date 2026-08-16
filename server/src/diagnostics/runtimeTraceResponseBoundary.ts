import { recordCurrentRuntimeCheckpoint } from "./runtimeTraceRequestContext.js";

interface TraceResponseLike {
  statusCode?: number;
  end?: (...args: unknown[]) => unknown;
}

const ATTACHED = Symbol("email-shield-runtime-trace-response-attached");
const SKIPPED_PREFIXES = [
  "/api/security/mutation-token",
  "/api/dev/runtime-trace",
] as const;

function shouldSkip(requestUrl: string | undefined): boolean {
  if (!requestUrl) return false;
  const path = requestUrl.split("?", 1)[0] ?? requestUrl;
  return SKIPPED_PREFIXES.some((prefix) => path.startsWith(prefix));
}

export function attachRuntimeTraceResponse(
  response: TraceResponseLike & { [ATTACHED]?: boolean },
  requestUrl?: string,
): boolean {
  if (response[ATTACHED] || typeof response.end !== "function" || shouldSkip(requestUrl)) return false;
  const originalEnd = response.end;
  response[ATTACHED] = true;
  response.end = function tracedRuntimeEnd(...args: unknown[]): unknown {
    const status = Number.isSafeInteger(response.statusCode) ? Number(response.statusCode) : 200;
    recordCurrentRuntimeCheckpoint("backend_completed", {
      stage: "service",
      outcome: status >= 400 ? "failed" : "success",
      component: "local_api",
      httpStatus: Math.max(0, Math.min(599, status)),
      ...(status >= 400 ? { errorCode: `http_${Math.max(0, Math.min(599, status))}` } : {}),
    });
    return originalEnd.apply(this, args);
  };
  return true;
}
