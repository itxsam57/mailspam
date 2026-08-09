import {
  createDefaultPersonalPolicyRepository,
  type PersonalPolicyRepository,
  type PersonalPolicyRepositoryFactoryOptions,
} from "./policyPersistence.js";

/**
 * The desktop server initializes this delegate before accepting requests. This
 * keeps the credential-vault lookup asynchronous at process startup while the
 * hot policy read/write path remains synchronous once the AES key is in memory.
 */
class DeferredPersonalPolicyRepository implements PersonalPolicyRepository {
  private delegate: PersonalPolicyRepository | null = null;
  private initializing: Promise<void> | null = null;

  get persistent(): boolean {
    return this.delegate?.persistent ?? false;
  }

  async initialize(options: PersonalPolicyRepositoryFactoryOptions = {}): Promise<void> {
    if (this.delegate) return;
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
    if (!this.delegate) {
      throw new Error("Personal policy persistence is not initialized. Restart Email Shield.");
    }
    return this.delegate;
  }
}

export const defaultPersonalPolicyRepository = new DeferredPersonalPolicyRepository();

export async function initializeDefaultPersonalPolicyRepository(
  options: PersonalPolicyRepositoryFactoryOptions = {},
): Promise<void> {
  await defaultPersonalPolicyRepository.initialize(options);
}
