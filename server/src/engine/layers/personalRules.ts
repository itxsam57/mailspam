import type { CanonicalEnvelope } from "../../canonical/envelope.js";
import { campaignFingerprint } from "../../community/fingerprint.js";
import { messageExceptionKey } from "../../workflows/messageReview.js";
import type { LayerResult } from "../verdict.js";

export interface PersonalPolicySnapshot {
  blockedSenders: string[];
  blockedDomains: string[];
  /** Optional v1 extension. Missing means no Catch & Trash sender rules. */
  catchTrashSenders?: string[];
  /** Optional v1 extension. Missing means no Catch & Trash domain rules. */
  catchTrashDomains?: string[];
  trustedSenders: string[];
  approvedExceptions: string[];
  unsubscribedActions: string[];
  reportedCampaigns: string[];
}

export interface PersonalPolicyStore {
  isBlockedSender(address: string): boolean;
  isBlockedDomain(domain: string): boolean;
  isCatchTrashSender(address: string): boolean;
  isCatchTrashDomain(domain: string): boolean;
  isTrustedSender(address: string): boolean;
  isApprovedException(value: string): boolean;
  isUnsubscribedAction(actionKey: string): boolean;
  isReportedCampaign(fingerprint: string): boolean;
}

export class InMemoryPersonalPolicyStore implements PersonalPolicyStore {
  private blockedSenders = new Set<string>();
  private blockedDomains = new Set<string>();
  private catchTrashSenders = new Set<string>();
  private catchTrashDomains = new Set<string>();
  private trustedSenders = new Set<string>();
  private approvedExceptions = new Set<string>();
  private unsubscribedActions = new Set<string>();
  private reportedCampaigns = new Set<string>();

  blockSender(address: string) { this.blockedSenders.add(address.toLowerCase()); }
  blockDomain(domain: string) { this.blockedDomains.add(domain.toLowerCase()); }
  catchTrashSender(address: string) { this.catchTrashSenders.add(address.toLowerCase()); }
  catchTrashDomain(domain: string) { this.catchTrashDomains.add(domain.toLowerCase()); }
  trustSender(address: string) { this.trustedSenders.add(address.toLowerCase()); }
  approveException(value: string) { this.approvedExceptions.add(value.toLowerCase()); }
  rememberUnsubscribed(actionKey: string) { this.unsubscribedActions.add(actionKey.toLowerCase()); }
  reportCampaign(fingerprint: string) { this.reportedCampaigns.add(fingerprint.toLowerCase()); }
  unblockSender(address: string) { this.blockedSenders.delete(address.toLowerCase()); }
  unblockDomain(domain: string) { this.blockedDomains.delete(domain.toLowerCase()); }
  removeCatchTrashSender(address: string) { this.catchTrashSenders.delete(address.toLowerCase()); }
  removeCatchTrashDomain(domain: string) { this.catchTrashDomains.delete(domain.toLowerCase()); }
  untrustSender(address: string) { this.trustedSenders.delete(address.toLowerCase()); }
  revokeException(value: string) { this.approvedExceptions.delete(value.toLowerCase()); }
  forgetUnsubscribed(actionKey: string) { this.unsubscribedActions.delete(actionKey.toLowerCase()); }
  forgetReportedCampaign(fingerprint: string) { this.reportedCampaigns.delete(fingerprint.toLowerCase()); }

  clear() {
    this.blockedSenders.clear();
    this.blockedDomains.clear();
    this.catchTrashSenders.clear();
    this.catchTrashDomains.clear();
    this.trustedSenders.clear();
    this.approvedExceptions.clear();
    this.unsubscribedActions.clear();
    this.reportedCampaigns.clear();
  }

  snapshot(): PersonalPolicySnapshot {
    return {
      blockedSenders: [...this.blockedSenders],
      blockedDomains: [...this.blockedDomains],
      catchTrashSenders: [...this.catchTrashSenders],
      catchTrashDomains: [...this.catchTrashDomains],
      trustedSenders: [...this.trustedSenders],
      approvedExceptions: [...this.approvedExceptions],
      unsubscribedActions: [...this.unsubscribedActions],
      reportedCampaigns: [...this.reportedCampaigns],
    };
  }

  restore(snapshot: Partial<PersonalPolicySnapshot>) {
    for (const value of snapshot.blockedSenders ?? []) this.blockSender(value);
    for (const value of snapshot.blockedDomains ?? []) this.blockDomain(value);
    for (const value of snapshot.catchTrashSenders ?? []) this.catchTrashSender(value);
    for (const value of snapshot.catchTrashDomains ?? []) this.catchTrashDomain(value);
    for (const value of snapshot.trustedSenders ?? []) this.trustSender(value);
    for (const value of snapshot.approvedExceptions ?? []) this.approveException(value);
    for (const value of snapshot.unsubscribedActions ?? []) this.rememberUnsubscribed(value);
    for (const value of snapshot.reportedCampaigns ?? []) this.reportCampaign(value);
  }

  replace(snapshot: Partial<PersonalPolicySnapshot>) {
    this.clear();
    this.restore(snapshot);
  }

  isBlockedSender(address: string) { return this.blockedSenders.has(address.toLowerCase()); }
  isBlockedDomain(domain: string) { return this.blockedDomains.has(domain.toLowerCase()); }
  isCatchTrashSender(address: string) { return this.catchTrashSenders.has(address.toLowerCase()); }
  isCatchTrashDomain(domain: string) { return this.catchTrashDomains.has(domain.toLowerCase()); }
  isTrustedSender(address: string) { return this.trustedSenders.has(address.toLowerCase()); }
  isApprovedException(value: string) { return this.approvedExceptions.has(value.toLowerCase()); }
  isUnsubscribedAction(actionKey: string) { return this.unsubscribedActions.has(actionKey.toLowerCase()); }
  isReportedCampaign(fingerprint: string) { return this.reportedCampaigns.has(fingerprint.toLowerCase()); }
}

export function personalRulesLayer(
  envelope: CanonicalEnvelope,
  store: PersonalPolicyStore,
): { result: LayerResult; confirmedByPersonalBlock: boolean } {
  const evidence: LayerResult["evidence"] = [];
  const address = envelope.from.address ?? "";
  const domain = envelope.from.domain ?? "";
  const exactMessageKey = messageExceptionKey(envelope);
  const fingerprint = campaignFingerprint(envelope);
  let confirmed = false;

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
  if (address && store.isCatchTrashSender(address)) {
    confirmed = true;
    evidence.push({
      layer: "personal_rules",
      code: "CATCH_TRASH_SENDER",
      description: "The user explicitly enabled a post-unsubscribe Catch & Trash rule for this sender.",
      scoreContribution: 10,
      source: "personal_rule",
    });
  }
  if (domain && store.isCatchTrashDomain(domain)) {
    confirmed = true;
    evidence.push({
      layer: "personal_rules",
      code: "CATCH_TRASH_DOMAIN",
      description: "The user explicitly enabled a post-unsubscribe Catch & Trash rule for this sender domain.",
      scoreContribution: 10,
      source: "personal_rule",
    });
  }
  if (store.isReportedCampaign(fingerprint)) {
    confirmed = true;
    evidence.push({
      layer: "personal_rules",
      code: "LOCALLY_REPORTED_SCAM_CAMPAIGN",
      description: "This message matches a scam campaign previously reported by the user.",
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
        description: "Sender is on the user's account-scoped trusted list; trust cannot suppress independent threat evidence.",
        scoreContribution: 0,
        source: "personal_rule",
      });
    } else if (address && store.isApprovedException(address)) {
      evidence.push({
        layer: "personal_rules",
        code: "APPROVED_EXCEPTION",
        description: "Sender was approved by a legacy personal rule; approval cannot suppress independent threat evidence.",
        scoreContribution: 0,
        source: "personal_rule",
      });
    }
  }

  return {
    result: { layer: "personal_rules", applicable: true, evidence, incomplete: false },
    confirmedByPersonalBlock: confirmed,
  };
}
