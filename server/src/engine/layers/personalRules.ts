import type { CanonicalEnvelope } from "../../canonical/envelope.js";
import type { LayerResult } from "../verdict.js";

export interface PersonalPolicySnapshot {
  blockedSenders: string[];
  blockedDomains: string[];
  trustedSenders: string[];
  approvedExceptions: string[];
}

export interface PersonalPolicyStore {
  isBlockedSender(address: string): boolean;
  isBlockedDomain(domain: string): boolean;
  isTrustedSender(address: string): boolean;
  isApprovedException(address: string): boolean;
}

export class InMemoryPersonalPolicyStore implements PersonalPolicyStore {
  private blockedSenders = new Set<string>();
  private blockedDomains = new Set<string>();
  private trustedSenders = new Set<string>();
  private approvedExceptions = new Set<string>();

  blockSender(address: string) { this.blockedSenders.add(address.toLowerCase()); }
  blockDomain(domain: string) { this.blockedDomains.add(domain.toLowerCase()); }
  trustSender(address: string) { this.trustedSenders.add(address.toLowerCase()); }
  approveException(address: string) { this.approvedExceptions.add(address.toLowerCase()); }
  unblockSender(address: string) { this.blockedSenders.delete(address.toLowerCase()); }
  unblockDomain(domain: string) { this.blockedDomains.delete(domain.toLowerCase()); }

  clear() {
    this.blockedSenders.clear();
    this.blockedDomains.clear();
    this.trustedSenders.clear();
    this.approvedExceptions.clear();
  }

  snapshot(): PersonalPolicySnapshot {
    return {
      blockedSenders: [...this.blockedSenders],
      blockedDomains: [...this.blockedDomains],
      trustedSenders: [...this.trustedSenders],
      approvedExceptions: [...this.approvedExceptions],
    };
  }

  restore(snapshot: Partial<PersonalPolicySnapshot>) {
    for (const value of snapshot.blockedSenders ?? []) this.blockSender(value);
    for (const value of snapshot.blockedDomains ?? []) this.blockDomain(value);
    for (const value of snapshot.trustedSenders ?? []) this.trustSender(value);
    for (const value of snapshot.approvedExceptions ?? []) this.approveException(value);
  }

  replace(snapshot: Partial<PersonalPolicySnapshot>) {
    this.clear();
    this.restore(snapshot);
  }

  isBlockedSender(address: string) { return this.blockedSenders.has(address.toLowerCase()); }
  isBlockedDomain(domain: string) { return this.blockedDomains.has(domain.toLowerCase()); }
  isTrustedSender(address: string) { return this.trustedSenders.has(address.toLowerCase()); }
  isApprovedException(address: string) { return this.approvedExceptions.has(address.toLowerCase()); }
}

export function personalRulesLayer(
  envelope: CanonicalEnvelope,
  store: PersonalPolicyStore,
): { result: LayerResult; confirmedByPersonalBlock: boolean } {
  const evidence: LayerResult["evidence"] = [];
  const address = envelope.from.address ?? "";
  const domain = envelope.from.domain ?? "";
  let confirmed = false;

  if (address && store.isTrustedSender(address)) {
    evidence.push({
      layer: "personal_rules",
      code: "TRUSTED_SENDER",
      description: "Sender is on the user's trusted senders list.",
      scoreContribution: -10,
      source: "personal_rule",
    });
  } else if (address && store.isApprovedException(address)) {
    evidence.push({
      layer: "personal_rules",
      code: "APPROVED_EXCEPTION",
      description: "Sender was explicitly approved as an exception by the user.",
      scoreContribution: -10,
      source: "personal_rule",
    });
  } else {
    if (address && store.isBlockedSender(address)) {
      confirmed = true;
      evidence.push({
        layer: "personal_rules",
        code: "BLOCKED_SENDER",
        description: "Sender address matches the user's personal block list.",
        scoreContribution: 10,
        source: "personal_rule",
      });
    }
    if (domain && store.isBlockedDomain(domain)) {
      confirmed = true;
      evidence.push({
        layer: "personal_rules",
        code: "BLOCKED_DOMAIN",
        description: "Sender domain matches the user's personal block list.",
        scoreContribution: 10,
        source: "personal_rule",
      });
    }
  }

  return {
    result: { layer: "personal_rules", applicable: true, evidence, incomplete: false },
    confirmedByPersonalBlock: confirmed,
  };
}
