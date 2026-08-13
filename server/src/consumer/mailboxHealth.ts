import type { CanonicalEnvelope, Provider } from "../canonical/envelope.js";

export type MailboxHealthState = "healthy_observed" | "attention" | "critical" | "incomplete";
export type CapabilityCheckState = "checked" | "not_authorized" | "unsupported" | "unavailable";

export interface MailboxHealthIndicator {
  code: string;
  severity: "info" | "warning" | "critical";
  title: string;
  detail: string;
  observedAt: string | null;
  provenance: "mailbox_observation" | "provider_security_api";
}

export interface ProviderSecurityCheck {
  id: "forwarding_rules" | "inbox_rules" | "delegates_send_as" | "connected_apps_sessions";
  state: CapabilityCheckState;
  detail: string;
  indicators: MailboxHealthIndicator[];
}

export interface MailboxSecuritySnapshot {
  provider: Provider;
  checkedAt: string;
  checks: ProviderSecurityCheck[];
}

export interface IdentitySecurityPort {
  inspect(provider: Provider, signal: AbortSignal): Promise<MailboxSecuritySnapshot>;
}

export class UnsupportedIdentitySecurityPort implements IdentitySecurityPort {
  async inspect(provider: Provider, signal: AbortSignal): Promise<MailboxSecuritySnapshot> {
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
    const detail = provider === "gmail" || provider === "outlook"
      ? "This connection does not request the additional provider security/settings permission required for authoritative account-rule inspection. Core mail protection remains active."
      : "This mail transport does not expose a portable authoritative account-security settings API through Email Shield's current least-privilege connection.";
    return {
      provider,
      checkedAt: new Date().toISOString(),
      checks: (["forwarding_rules", "inbox_rules", "delegates_send_as", "connected_apps_sessions"] as const).map((id) => ({
        id,
        state: provider === "gmail" || provider === "outlook" ? "not_authorized" : "unsupported",
        detail,
        indicators: [],
      })),
    };
  }
}

const TRUSTED_SECURITY_ALERT_DOMAINS: Readonly<Record<Provider, readonly string[]>> = Object.freeze({
  gmail: ["accounts.google.com", "google.com"],
  outlook: ["accountprotection.microsoft.com", "microsoft.com"],
  icloud: ["apple.com", "icloud.com"],
  yahoo: ["yahoo.com"],
  imap: [],
});

const SECURITY_BURST_WINDOW_MS = 15 * 60 * 1_000;
const SECURITY_BURST_MIN_MESSAGES = 30;
const SECURITY_BURST_MIN_FIRST_CONTACT = 20;
const SECURITY_BURST_MIN_DISTINCT_FIRST_CONTACT_SENDERS = 20;

function authPassed(envelope: CanonicalEnvelope): boolean {
  return envelope.authentication.dmarc === "pass"
    || (envelope.authentication.spf === "pass" && envelope.authentication.dkim === "pass");
}

function trustedProviderAlert(envelope: CanonicalEnvelope): boolean {
  const domain = envelope.from.domain?.toLowerCase() ?? "";
  const allowed = TRUSTED_SECURITY_ALERT_DOMAINS[envelope.provider];
  if (!allowed.some((candidate) => domain === candidate || domain.endsWith(`.${candidate}`))) return false;
  if (!authPassed(envelope)) return false;
  const text = `${envelope.subject}\n${envelope.textPreview ?? ""}`;
  return /\b(security alert|new sign[- ]?in|unusual activity|password changed|recovery|suspicious sign[- ]?in|account access)\b/i.test(text);
}

function senderIdentity(envelope: CanonicalEnvelope): string {
  return envelope.from.address?.trim().toLowerCase()
    || envelope.from.domain?.trim().toLowerCase()
    || `unknown:${envelope.providerNativeId}`;
}

function spamBombSecurityHidingIndicator(envelopes: readonly CanonicalEnvelope[]): MailboxHealthIndicator | null {
  const observations = envelopes
    .slice(0, 250)
    .map((envelope) => ({
      envelope,
      time: Date.parse(envelope.date),
    }))
    .filter((item) => Number.isFinite(item.time))
    .sort((left, right) => left.time - right.time);

  let best: {
    messages: number;
    firstContacts: number;
    distinctFirstContacts: number;
    observedAt: number;
  } | null = null;

  for (let start = 0; start < observations.length; start += 1) {
    const first = observations[start]!;
    const distinctFirstContacts = new Set<string>();
    let firstContacts = 0;
    let end = start;
    while (end < observations.length && observations[end]!.time - first.time <= SECURITY_BURST_WINDOW_MS) {
      const envelope = observations[end]!.envelope;
      if (envelope.threadContext.isFirstContact) {
        firstContacts += 1;
        distinctFirstContacts.add(senderIdentity(envelope));
      }
      end += 1;
    }
    const messages = end - start;
    const candidate = {
      messages,
      firstContacts,
      distinctFirstContacts: distinctFirstContacts.size,
      observedAt: observations[Math.max(start, end - 1)]!.time,
    };
    if (
      !best
      || candidate.distinctFirstContacts > best.distinctFirstContacts
      || (candidate.distinctFirstContacts === best.distinctFirstContacts && candidate.messages > best.messages)
    ) best = candidate;
  }

  if (
    !best
    || best.messages < SECURITY_BURST_MIN_MESSAGES
    || best.firstContacts < SECURITY_BURST_MIN_FIRST_CONTACT
    || best.distinctFirstContacts < SECURITY_BURST_MIN_DISTINCT_FIRST_CONTACT_SENDERS
  ) return null;

  return {
    code: "FIRST_CONTACT_MESSAGE_FLOOD",
    severity: "warning",
    title: "Message flood may hide a security alert",
    detail: `${best.messages} messages arrived inside a 15-minute window, including ${best.distinctFirstContacts} distinct first-contact senders. Scam-driven spam bombs can bury a legitimate password, purchase or account-security alert. Review your provider's official security and recent-activity pages directly; do not act from links inside the flood.`,
    observedAt: new Date(best.observedAt).toISOString(),
    provenance: "mailbox_observation",
  };
}

function envelopeIndicators(envelopes: readonly CanonicalEnvelope[]): MailboxHealthIndicator[] {
  const indicators: MailboxHealthIndicator[] = [];
  let relationshipDowngrades = 0;
  let replyToDrift = 0;
  for (const envelope of envelopes.slice(0, 250)) {
    if (envelope.threadContext.relationshipAuthenticationDowngrade) relationshipDowngrades += 1;
    if (envelope.threadContext.replyToChangedFromRelationshipHistory || envelope.threadContext.replyToChangedMidThread) replyToDrift += 1;
    if (trustedProviderAlert(envelope)) {
      indicators.push({
        code: "TRUSTED_PROVIDER_SECURITY_ALERT",
        severity: "warning",
        title: "Provider security alert observed",
        detail: "Email Shield observed an authenticated security-alert message from a trusted provider identity. Review it by opening the provider's official app or website directly rather than using message links.",
        observedAt: Number.isFinite(Date.parse(envelope.date)) ? new Date(envelope.date).toISOString() : null,
        provenance: "mailbox_observation",
      });
    }
  }
  if (relationshipDowngrades > 0) {
    indicators.push({
      code: "ESTABLISHED_IDENTITY_AUTH_DOWNGRADE",
      severity: "critical",
      title: "Known sender authentication changed",
      detail: `${relationshipDowngrades} message(s) from established relationships showed an authentication downgrade. This can indicate impersonation or a compromised sending path and should be independently verified.`,
      observedAt: null,
      provenance: "mailbox_observation",
    });
  }
  if (replyToDrift > 0) {
    indicators.push({
      code: "ESTABLISHED_REPLY_TO_DRIFT",
      severity: "warning",
      title: "Reply destination changed",
      detail: `${replyToDrift} message(s) changed Reply-To/thread behavior compared with established local history. Verify unusual payment or account requests through an independently obtained channel.`,
      observedAt: null,
      provenance: "mailbox_observation",
    });
  }
  const spamBomb = spamBombSecurityHidingIndicator(envelopes);
  if (spamBomb) indicators.push(spamBomb);
  return indicators.slice(0, 50);
}

export interface MailboxHealthReport {
  schemaVersion: 1;
  provider: Provider;
  generatedAt: string;
  state: MailboxHealthState;
  observedMessages: number;
  indicators: MailboxHealthIndicator[];
  providerChecks: ProviderSecurityCheck[];
  limitations: string[];
  privacy: "local_observations_provider_metadata_only";
}

export async function analyzeMailboxHealth(input: {
  provider: Provider;
  envelopes: readonly CanonicalEnvelope[];
  securityPort?: IdentitySecurityPort;
  signal?: AbortSignal;
}): Promise<MailboxHealthReport> {
  const signal = input.signal ?? new AbortController().signal;
  const securityPort = input.securityPort ?? new UnsupportedIdentitySecurityPort();
  const indicators = envelopeIndicators(input.envelopes);
  let providerChecks: ProviderSecurityCheck[];
  const limitations: string[] = [];
  try {
    const providerSnapshot = await securityPort.inspect(input.provider, signal);
    providerChecks = providerSnapshot.checks;
  } catch (error) {
    providerChecks = (["forwarding_rules", "inbox_rules", "delegates_send_as", "connected_apps_sessions"] as const).map((id) => ({
      id,
      state: "unavailable" as const,
      detail: "The provider security check failed or was unavailable. It was not treated as safe.",
      indicators: [],
    }));
    limitations.push(`Provider security inspection unavailable: ${error instanceof Error ? error.message : String(error)}`);
  }
  for (const check of providerChecks) indicators.push(...check.indicators);
  const incomplete = providerChecks.some((check) => check.state !== "checked");
  if (incomplete) limitations.push("Some provider account-security settings were not inspected because the current least-privilege mailbox authorization does not expose them.");
  if (input.envelopes.some((envelope) => envelope.parseStatus !== "complete" || envelope.diagnostics.contentCoverage === "insufficient")) {
    limitations.push("Some mailbox observations were partial or unreadable and were not interpreted as a clean result.");
  }
  const critical = indicators.some((indicator) => indicator.severity === "critical");
  const warning = indicators.some((indicator) => indicator.severity === "warning");
  const state: MailboxHealthState = critical ? "critical" : warning ? "attention" : incomplete ? "incomplete" : "healthy_observed";
  return {
    schemaVersion: 1,
    provider: input.provider,
    generatedAt: new Date().toISOString(),
    state,
    observedMessages: Math.min(250, input.envelopes.length),
    indicators: indicators.slice(0, 50),
    providerChecks,
    limitations: [...new Set(limitations)].slice(0, 20),
    privacy: "local_observations_provider_metadata_only",
  };
}