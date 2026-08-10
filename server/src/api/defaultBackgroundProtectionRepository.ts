import {
  createDefaultBackgroundProtectionRepository,
  InMemoryBackgroundProtectionRepository,
  type BackgroundProtectionRecord,
  type BackgroundProtectionRepository,
  type BackgroundProtectionRepositoryFactoryOptions,
} from "./backgroundProtectionPersistence.js";

class DeferredBackgroundProtectionRepository implements BackgroundProtectionRepository {
  private delegate: BackgroundProtectionRepository | null = null;
  private readonly fallback = new InMemoryBackgroundProtectionRepository();
  private fallbackUsed = false;
  private initializing: Promise<void> | null = null;

  get persistent(): boolean {
    return this.delegate?.persistent ?? false;
  }

  async initialize(options: BackgroundProtectionRepositoryFactoryOptions = {}): Promise<void> {
    if (this.delegate) return;
    if (this.fallbackUsed) throw new Error("Background protection persistence cannot initialize after temporary state has been used.");
    if (this.initializing) return this.initializing;
    this.initializing = (async () => {
      this.delegate = await createDefaultBackgroundProtectionRepository(options);
    })();
    try { await this.initializing; }
    finally { this.initializing = null; }
  }

  get(accountKey: string): BackgroundProtectionRecord | null {
    return this.ready().get(accountKey);
  }

  list(): Array<{ accountKey: string; record: BackgroundProtectionRecord }> {
    return this.ready().list();
  }

  save(accountKey: string, record: BackgroundProtectionRecord): void {
    this.ready().save(accountKey, record);
  }

  remove(accountKey: string): void {
    this.ready().remove(accountKey);
  }

  recoverInterrupted(now?: number): void {
    this.ready().recoverInterrupted(now);
  }

  private ready(): BackgroundProtectionRepository {
    if (this.delegate) return this.delegate;
    this.fallbackUsed = true;
    return this.fallback;
  }
}

export const defaultBackgroundProtectionRepository = new DeferredBackgroundProtectionRepository();

export async function initializeDefaultBackgroundProtectionRepository(
  options: BackgroundProtectionRepositoryFactoryOptions = {},
): Promise<void> {
  await defaultBackgroundProtectionRepository.initialize(options);
}
