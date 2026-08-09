import {
  createDefaultPersonalPolicyRepository,
  InMemoryPolicyRepository,
  type PersonalPolicyRepository,
  type PersonalPolicyRepositoryFactoryOptions,
} from "./policyPersistence.js";

/**
 * The production desktop entry point initializes this delegate before accepting
 * requests. Direct server/unit construction may use the temporary in-memory
 * fallback, but once that fallback is touched the process may not later switch
 * to persistent storage: that would make earlier mutations appear durable when
 * they were not.
 */
class DeferredPersonalPolicyRepository implements PersonalPolicyRepository {
  private delegate: PersonalPolicyRepository | null = null;
  private readonly fallback = new InMemoryPolicyRepository();
  private fallbackUsed = false;
  private initializing: Promise<void> | null = null;

  get persistent(): boolean {
    return this.delegate?.persistent ?? false;
  }

  async initialize(options: PersonalPolicyRepositoryFactoryOptions = {}): Promise<void> {
    if (this.delegate) return;
    if (this.fallbackUsed) {
      throw new Error("Personal policy persistence cannot be initialized after temporary in-memory policy state has been used.");
    }
    if (this.initializing) return this.initializing;
    this.initializing = (async () => {
      const repository = await createDefaultPersonalPolicyRepository(options);
      this.delegate = repository;
    })();
    try {
      await this.initializing;
    } finally {
      this.initializing = null;
    }
  }

  load(accountKey: string) {
    return this.ready().load(accountKey);
  }

  save(accountKey: string, snapshot: Parameters<PersonalPolicyRepository["save"]>[1]): void {
    this.ready().save(accountKey, snapshot);
  }

  private ready(): PersonalPolicyRepository {
    if (this.delegate) return this.delegate;
    this.fallbackUsed = true;
    return this.fallback;
  }
}

export const defaultPersonalPolicyRepository = new DeferredPersonalPolicyRepository();

export async function initializeDefaultPersonalPolicyRepository(
  options: PersonalPolicyRepositoryFactoryOptions = {},
): Promise<void> {
  await defaultPersonalPolicyRepository.initialize(options);
}
