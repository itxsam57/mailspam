import {
  createDefaultScanStateRepository,
  InMemoryScanStateRepository,
  type ScanHistoryRecord,
  type ScanStateRepository,
  type ScanStateRepositoryFactoryOptions,
} from "./scanStatePersistence.js";

/**
 * Production initializes the encrypted repository before listening. Direct
 * unit/server construction may use an in-memory fallback, but once that
 * fallback is touched the process cannot later switch to durable state.
 */
class DeferredScanStateRepository implements ScanStateRepository {
  private delegate: ScanStateRepository | null = null;
  private readonly fallback = new InMemoryScanStateRepository();
  private fallbackUsed = false;
  private initializing: Promise<void> | null = null;

  get persistent(): boolean {
    return this.delegate?.persistent ?? false;
  }

  async initialize(options: ScanStateRepositoryFactoryOptions = {}): Promise<void> {
    if (this.delegate) return;
    if (this.fallbackUsed) {
      throw new Error("Scan-state persistence cannot be initialized after temporary in-memory scan state has been used.");
    }
    if (this.initializing) return this.initializing;
    this.initializing = (async () => {
      this.delegate = await createDefaultScanStateRepository(options);
    })();
    try {
      await this.initializing;
    } finally {
      this.initializing = null;
    }
  }

  list(accountKey: string): ScanHistoryRecord[] {
    return this.ready().list(accountKey);
  }

  get(accountKey: string, scanId: string): ScanHistoryRecord | null {
    return this.ready().get(accountKey, scanId);
  }

  save(accountKey: string, record: ScanHistoryRecord): void {
    this.ready().save(accountKey, record);
  }

  recoverInterrupted(): void {
    this.ready().recoverInterrupted();
  }

  private ready(): ScanStateRepository {
    if (this.delegate) return this.delegate;
    this.fallbackUsed = true;
    return this.fallback;
  }
}

export const defaultScanStateRepository = new DeferredScanStateRepository();

export async function initializeDefaultScanStateRepository(
  options: ScanStateRepositoryFactoryOptions = {},
): Promise<void> {
  await defaultScanStateRepository.initialize(options);
}
