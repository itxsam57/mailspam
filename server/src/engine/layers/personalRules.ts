import type { CanonicalEnvelope } from "../../canonical/envelope.js";
import { messageExceptionKey } from "../../workflows/messageReview.js";
import type { LayerResult } from "../verdict.js";

export interface PersonalPolicySnapshot {
  blockedSenders: string[];
  blockedDomains: string[];
  trustedSenders: string[];
  approvedExceptions: string[];
  unsubscribedActions: string[];
}

export interface PersonalPolicyStore {
  isBlockedSender(address: string): boolean;
  isBlockedDomain(domain: string): boolean;
  isTrustedSender(address: string): boolean;
  isApprovedException(value: string): boolean;
  isUnsubscribedAction(actionKey: string): boolean;
}

export class InMemoryPersonalPolicyStore implements PersonalPolicyStore {
  private blockedSenders = new Set<string>();
  private blockedDomains = new Set<string>();
  private trustedSenders = new Set<string>();
  private approvedExceptions = new Set<string>();
  private unsubscribedActions = new Set<string>();

  blockSender(address: string) { this.blockedSenders.add(address.toLowerCase()); }
  blockDomain(domain: string) { this.blockedDomains.add(domain.toLowerCase()); }
  trustSender(address: string) { this.trustedSenders.add(address.toLowerCase()); }
  approveException(value: string) { this.approvedExceptions.add(value.toLowerCase()); }
  rememberUnsubscribed(actionKey: string) { this.unsubscribedActions.add(actionKey.toLowerCase()); }
  unblockSender(address: string) { this.blockedSenders.delete(address.toLowerCase()); }
  unblockDomain(domain: string) { this.blockedDomains.delete(domain.toLowerCase()); }
  untrustSender(address: string) { this.trustedSenders.delete(address.toLowerCase()); }
  revokeException(value: string) { this.approvedExceptions.delete(value.toLowerCase()); }
  forgetUnsubscribed(actionKey: string) { this.unsubscribedActions.delete(actionKey.toLowerCase()); }

  clear() {
    this.blockedSenders.clear();
    this.blockedDomains.clear();
    this.trustedSenders.clear();
    this.approvedExceptions.clear();
    this.unsubscribedActions.clear();
  }

  snapshot(): PersonalPolicySnapshot {
    return {
      blockedSenders: [...this.blockedSenders],
      blockedDomains: [...this.blockedDomains],
      trustedSenders: [...this.trustedSenders],
      approvedExceptions: [...this.approvedExceptions],
      unsubscribedActions: [...this.unsubscribedActions],
    };
  }

  restore(snapshot: Partial<PersonalPolicySnapshot>) {
    for (const value of snapshot.blockedSenders ?? []) this.blockSender(value);
    for (const value of snapshot.blockedDomains ?? []) this.blockDomain(value);
    for (const value of snapshot.trustedSenders ?? []) this.trustSender(value);
    for (const value of snapshot.approvedExceptions ?? []) this.approveException(value);
    for (const value of snapshot.unsubscribedActions ?? []) this.rememberUnsubscribed(value);
  }

  replace(snapshot: Partial<PersonalPolicySnapshot>) {
    this.clear();
    this.restore(snapshot);
  }

  isBlockedSender(address: string) { return this.blockedSenders.has(address.toLowerCase()); }
  isBlockedDomain(domain: string) { return this.blockedDomains.has(domain.toLowerCase()); }
  isTrustedSender(address: string) { return this.trustedSenders.has(address.toLowerCase()); }
  isApprovedException(value: string) { return this.approvedExceptions.has(value.toLowerCase()); }
  isUnsubscribedAction(actionKey: string) { return this.unsubscribedActions.has(actionKey.toLowerCase()); }
}

export function personalRulesLayer(
  envelope: CanonicalEnvelope,
  store: PersonalPolicyStore,
): { result: LayerResult; confirmedByPersonalBlock: boolean } {
  const evidence: LayerResult["evidence"] = [];
  const address = envelope.from.address ?? "";
  const domain = envelope.from.domain ?? "";
  const exactMessageKey = messageExceptionKey(envelope);
  let confirmed = false;

  // An explicit block remains authoritative even if the same sender or message
  // was previously trusted. The user must remove the block from policy before
  // a Safe/trust rule can apply again.
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

  if (!confirmed) {
    if (store.isApprovedException(exactMessageKey)) {
      evidence.push({
        layer: "personal_rules",
        code: "APPROVED_MESSAGE_EXCEPTION",
        description: "This exact message was explicitly marked Safe by the user.",
        scoreContribution: -100,
        source: "personal_rule",
      });
    } else if (address && store.isTrustedSender(address)) {
      evidence.push({
        layer: "personal_rules",
        code: "TRUSTED_SENDER",
        description: "Sender is on the user's account-scoped trusted senders list.",
        scoreContribution: -10,
        source: "personal_rule",
      });
    } else if (address && store.isApprovedException(address)) {
      evidence.push({
        layer: "personal_rules",
        code: "APPROVED_EXCEPTION",
        description: "Sender was explicitly approved by a legacy personal rule.",
        scoreContribution: -10,
        source: "personal_rule",
      });
    }
  }

  return {
    result: { layer: "personal_rules", applicable: true, evidence, incomplete: false },
    confirmedByPersonalBlock: confirmed,
  };
}
