import {
  createDefaultConsumerStateRepository,
  InMemoryConsumerStateRepository,
  type ConsumerAccountState,
  type ConsumerActivityRecord,
  type ConsumerMailboxRule,
  type ConsumerOnboardingState,
  type ConsumerStateFactoryOptions,
  type ConsumerStateRepository,
  type PublicConsumerActivityRecord,
} from "./consumerStatePersistence.js";
import type { ProtectionSensitivityProfile } from "../consumer/protectionSensitivity.js";

class DeferredConsumerStateRepository implements ConsumerStateRepository {
  private delegate: ConsumerStateRepository | null = null;
  private readonly fallback = new InMemoryConsumerStateRepository();
  private fallbackUsed = false;
  private initializing: Promise<void> | null = null;

  get persistent(): boolean { return this.delegate?.persistent ?? false; }

  async initialize(options: ConsumerStateFactoryOptions = {}): Promise<void> {
    if (this.delegate) return;
    if (this.fallbackUsed) throw new Error("Consumer-state persistence cannot be initialized after temporary in-memory consumer state has been used.");
    if (this.initializing) return this.initializing;
    this.initializing = (async () => { this.delegate = await createDefaultConsumerStateRepository(options); })();
    try { await this.initializing; }
    finally { this.initializing = null; }
  }

  private ready(): ConsumerStateRepository {
    if (this.delegate) return this.delegate;
    this.fallbackUsed = true;
    return this.fallback;
  }

  snapshot(accountKey: string): ConsumerAccountState { return this.ready().snapshot(accountKey); }
  setSensitivity(accountKey: string, profile: ProtectionSensitivityProfile): ConsumerAccountState { return this.ready().setSensitivity(accountKey, profile); }
  setRicherLocalNotifications(accountKey: string, enabled: boolean): ConsumerAccountState { return this.ready().setRicherLocalNotifications(accountKey, enabled); }
  setOnboarding(accountKey: string, input: ConsumerOnboardingState): ConsumerAccountState { return this.ready().setOnboarding(accountKey, input); }
  upsertRule(accountKey: string, input: Omit<ConsumerMailboxRule, "ruleId" | "createdAt"> & { ruleId?: string }): ConsumerMailboxRule { return this.ready().upsertRule(accountKey, input); }
  removeRule(accountKey: string, ruleId: string): boolean { return this.ready().removeRule(accountKey, ruleId); }
  appendActivity(accountKey: string, input: Omit<ConsumerActivityRecord, "activityId" | "createdAt"> & { activityId?: string; createdAt?: number }): ConsumerActivityRecord { return this.ready().appendActivity(accountKey, input); }
  listActivity(accountKey: string): PublicConsumerActivityRecord[] { return this.ready().listActivity(accountKey); }
  getActivity(accountKey: string, activityId: string): ConsumerActivityRecord | null { return this.ready().getActivity(accountKey, activityId); }
  markActivityUndone(accountKey: string, activityId: string, usedAt?: number): ConsumerActivityRecord { return this.ready().markActivityUndone(accountKey, activityId, usedAt); }
  clearAccount(accountKey: string): void { this.ready().clearAccount(accountKey); }
  clearActivity(accountKey: string): void { this.ready().clearActivity(accountKey); }
}

export const defaultConsumerStateRepository = new DeferredConsumerStateRepository();

export async function initializeDefaultConsumerStateRepository(options: ConsumerStateFactoryOptions = {}): Promise<void> {
  await defaultConsumerStateRepository.initialize(options);
}
