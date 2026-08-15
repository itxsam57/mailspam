type TelemetryEnvironment = Readonly<Record<string, string | undefined>>;

type TechnicalTelemetryEvent =
  | "email_shield_app_started"
  | "email_shield_protected_state_ready"
  | "email_shield_protected_state_failed"
  | "email_shield_server_listening";

type TechnicalTelemetryProperties = Readonly<{
  duration_ms?: number;
  failure_kind?: "initialization_error";
}>;

export interface TechnicalTelemetry {
  capture(event: TechnicalTelemetryEvent, properties?: TechnicalTelemetryProperties): Promise<boolean>;
}

interface TechnicalTelemetryOptions {
  environment?: TelemetryEnvironment;
  platform?: NodeJS.Platform;
  appVersion?: string;
  fetchImpl?: typeof fetch;
}

const DEFAULT_POSTHOG_HOST = "https://us.i.posthog.com";
const CAPTURE_TIMEOUT_MS = 1_500;
const ANONYMOUS_DISTINCT_ID = "email-shield-desktop-runtime";

const ALLOWED_EVENTS = new Set<TechnicalTelemetryEvent>([
  "email_shield_app_started",
  "email_shield_protected_state_ready",
  "email_shield_protected_state_failed",
  "email_shield_server_listening",
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function validateProperties(
  event: TechnicalTelemetryEvent,
  properties: unknown,
): TechnicalTelemetryProperties | null {
  if (properties === undefined) {
    return event === "email_shield_protected_state_ready" || event === "email_shield_protected_state_failed"
      ? null
      : {};
  }
  if (!isRecord(properties)) return null;

  const keys = Object.keys(properties);
  if (keys.some((key) => key !== "duration_ms" && key !== "failure_kind")) return null;

  if (event === "email_shield_protected_state_ready") {
    if (keys.length !== 1 || keys[0] !== "duration_ms") return null;
    const durationMs = properties.duration_ms;
    if (typeof durationMs !== "number" || !Number.isFinite(durationMs) || durationMs < 0 || durationMs > 3_600_000) {
      return null;
    }
    return { duration_ms: Math.round(durationMs) };
  }

  if (event === "email_shield_protected_state_failed") {
    if (keys.length !== 1 || keys[0] !== "failure_kind" || properties.failure_kind !== "initialization_error") {
      return null;
    }
    return { failure_kind: "initialization_error" };
  }

  return keys.length === 0 ? {} : null;
}

function captureUrlFromHost(rawHost: string): URL | null {
  try {
    const host = new URL(rawHost);
    if (host.protocol !== "https:" || host.username || host.password || host.search || host.hash) return null;
    return new URL("/capture/", host);
  } catch {
    return null;
  }
}

function disabledTelemetry(): TechnicalTelemetry {
  return {
    async capture() {
      return false;
    },
  };
}

export function createTechnicalTelemetryFromEnvironment(
  options: TechnicalTelemetryOptions = {},
): TechnicalTelemetry {
  const environment = options.environment ?? process.env;
  if (environment.EMAIL_SHIELD_TELEMETRY !== "1") return disabledTelemetry();

  const projectToken = environment.EMAIL_SHIELD_POSTHOG_PROJECT_TOKEN?.trim();
  if (!projectToken) return disabledTelemetry();

  const captureUrl = captureUrlFromHost(
    environment.EMAIL_SHIELD_POSTHOG_HOST?.trim() || DEFAULT_POSTHOG_HOST,
  );
  if (!captureUrl) return disabledTelemetry();

  const platform = options.platform ?? process.platform;
  const appVersion = options.appVersion?.trim() || "unknown";
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") return disabledTelemetry();

  return {
    async capture(event, properties) {
      if (!ALLOWED_EVENTS.has(event)) return false;
      const safeProperties = validateProperties(event, properties);
      if (!safeProperties) return false;

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), CAPTURE_TIMEOUT_MS);
      timeout.unref?.();

      try {
        const response = await fetchImpl(captureUrl, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            api_key: projectToken,
            distinct_id: ANONYMOUS_DISTINCT_ID,
            event,
            timestamp: new Date().toISOString(),
            properties: {
              $process_person_profile: false,
              $geoip_disable: true,
              component: "desktop_server",
              app_version: appVersion,
              platform,
              ...safeProperties,
            },
          }),
          signal: controller.signal,
        });
        return response.ok;
      } catch {
        return false;
      } finally {
        clearTimeout(timeout);
      }
    },
  };
}
