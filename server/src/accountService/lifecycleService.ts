import type { AccountPlatformRepository, AccountPlatformRuntime } from "../platform/accountFamilyPorts.js";
import {
  ACCOUNT_PLATFORM_SCHEMA_VERSION,
  type AccountPlatformState,
} from "../platform/accountFamilyTypes.js";
import {
  AccountLifecycleService,
  type AccountDeletionResult,
  type FamilyDeletionResult,
  type PrivacySafeAccountExportV1,
} from "../platform/accountLifecycleService.js";
import { NodeAccountPlatformRuntime } from "../platform/desktopDeviceIdentity.js";
import { ACCOUNT_SERVICE_SCHEMA_VERSION } from "./types.js";
import type { AccountServiceStore } from "./store.js";

class ScopedLifecycleRepository implements AccountPlatformRepository {
  readonly persistent: boolean;

  constructor(
    private readonly store: AccountServiceStore,
    private readonly selectedAccountId: string,
  ) {
    this.persistent = store.persistent;
  }

  load(): AccountPlatformState {
    const state = this.store.load();
    return {
      schemaVersion: ACCOUNT_PLATFORM_SCHEMA_VERSION,
      currentAccountId: this.selectedAccountId,
      accounts: structuredClone(state.accounts),
      familyCircles: structuredClone(state.familyCircles),
      mailboxLinks: [],
    };
  }

  save(state: AccountPlatformState): void {
    if (state.mailboxLinks.length !== 0) throw new Error("Shared account lifecycle must never persist mailbox-profile links.");
    if (state.currentAccountId !== null && state.currentAccountId !== this.selectedAccountId) {
      throw new Error("Shared account lifecycle attempted to switch authorization context.");
    }
    this.store.save({
      schemaVersion: ACCOUNT_SERVICE_SCHEMA_VERSION,
      accounts: structuredClone(state.accounts),
      familyCircles: structuredClone(state.familyCircles),
    });
  }
}

class AccountServiceLifecycleRuntime implements AccountPlatformRuntime {
  private readonly base = new NodeAccountPlatformRuntime();
  constructor(private readonly clock: () => number) {}
  now(): number { return this.clock(); }
  id(prefix: "acct" | "family" | "invite"): string { return this.base.id(prefix); }
  secret(bytes = 24): string { return this.base.secret(bytes); }
}

/**
 * Remote/mobile lifecycle facade. It deliberately shares the same portable
 * AccountLifecycleService as desktop, but a scoped repository strips mailbox
 * links because the shared service must never know local mailbox identities.
 */
export class SharedAccountLifecycleService {
  private readonly runtime: AccountPlatformRuntime;

  constructor(
    private readonly store: AccountServiceStore,
    now: () => number = Date.now,
  ) {
    this.runtime = new AccountServiceLifecycleRuntime(now);
  }

  private scoped(accountId: string): AccountLifecycleService {
    return new AccountLifecycleService(
      new ScopedLifecycleRepository(this.store, accountId),
      this.runtime,
    );
  }

  exportAccount(accountId: string, deviceId: string): PrivacySafeAccountExportV1 {
    return this.scoped(accountId).exportAccountMetadata(deviceId);
  }

  rotateRecovery(accountId: string, deviceId: string): { recoveryCode: string } {
    return this.scoped(accountId).rotateRecoveryCode(deviceId);
  }

  revokeOtherDevices(accountId: string, deviceId: string): { revoked: number } {
    return this.scoped(accountId).revokeOtherDevices(deviceId);
  }

  signOutEverywhere(accountId: string, deviceId: string): { revoked: number } {
    return this.scoped(accountId).signOutEverywhere(deviceId);
  }

  deleteFamily(accountId: string, deviceId: string): FamilyDeletionResult {
    return this.scoped(accountId).deleteFamilyCircle(deviceId);
  }

  deleteAccount(accountId: string, deviceId: string): AccountDeletionResult {
    return this.scoped(accountId).deleteAccount(deviceId);
  }
}
