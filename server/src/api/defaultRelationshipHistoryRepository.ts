import {
  createDefaultRelationshipHistoryRepository,
  InMemoryRelationshipHistoryRepository,
  type RelationshipHistoryRepository,
  type RelationshipHistoryRepositoryFactoryOptions,
} from "./relationshipHistoryPersistence.js";
import type {
  RelationshipHistoryWorkerSnapshot,
  RelationshipObservation,
} from "../engine/relationshipHistory.js";

/**
 * Production initializes protected relationship history before listening.
 * Direct unit/server construction may use process-memory history, but once that
 * fallback is touched the process cannot later switch to durable state.
 */
class DeferredRelationshipHistoryRepository implements RelationshipHistoryRepository {
  private delegate: RelationshipHistoryRepository | null = null;
  private readonly fallback = new InMemoryRelationshipHistoryRepository();
  private fallbackUsed = false;
  private initializing: Promise<void> | null = null;

  get persistent(): boolean {
    return this.delegate?.persistent ?? false;
  }

  async initialize(options: RelationshipHistoryRepositoryFactoryOptions = {}): Promise<void> {
    if (this.delegate) return;
    if (this.fallbackUsed) {
      throw new Error("Relationship-history persistence cannot be initialized after temporary in-memory history has been used.");
    }
    if (this.initializing) return this.initializing;
    this.initializing = (async () => {
      this.delegate = await createDefaultRelationshipHistoryRepository(options);
    })();
    try {
      await this.initializing;
    } finally {
      this.initializing = null;
    }
  }

  workerSnapshot(accountKey: string): RelationshipHistoryWorkerSnapshot {
    return this.ready().workerSnapshot(accountKey);
  }

  merge(accountKey: string, observations: RelationshipObservation[]): void {
    this.ready().merge(accountKey, observations);
  }

  private ready(): RelationshipHistoryRepository {
    if (this.delegate) return this.delegate;
    this.fallbackUsed = true;
    return this.fallback;
  }
}

export const defaultRelationshipHistoryRepository = new DeferredRelationshipHistoryRepository();

export async function initializeDefaultRelationshipHistoryRepository(
  options: RelationshipHistoryRepositoryFactoryOptions = {},
): Promise<void> {
  await defaultRelationshipHistoryRepository.initialize(options);
}
