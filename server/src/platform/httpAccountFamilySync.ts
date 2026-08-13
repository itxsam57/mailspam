import { accountRegistrationStatement } from "../accountService/protocol.js";
import type { AccountServiceOperation } from "../accountService/types.js";
import type { PrivacySafeAccountExportV1 } from "./accountLifecycleService.js";
import {
  deriveDeviceId,
  hashRecoveryCode,
  type FamilyThreatSnapshot,
  type PublicAccountPlatformSnapshot,
} from "./accountFamilyTypes.js";
import type { DeviceIdentityPort, FamilySyncPort } from "./accountFamilyPorts.js";

export interface AccountFamilySyncSnapshot {
  schemaVersion: 1;
  account: PublicAccountPlatformSnapshot;
  familyThreats: FamilyThreatSnapshot | null;
  synchronizedAt: number;
}

const LIFECYCLE_OPERATIONS = new Set<AccountServiceOperation>([
  "account:export",
  "account:delete",
  "recovery:rotate",
  "devices:revoke-others",
  "devices:signout-everywhere",
  "family:delete",
]);

export class HttpAccountFamilySyncClient implements FamilySyncPort {
  constructor(
    private readonly baseUrl: string,
    private readonly accountId: string,
    private readonly deviceIdentity: DeviceIdentityPort,
    private readonly onSnapshot?: (snapshot: AccountFamilySyncSnapshot) => void,
  ) {
    const parsed = new URL(baseUrl);
    if (!["https:", "http:"].includes(parsed.protocol)) throw new Error("Account service URL must use HTTP or HTTPS.");
    if (parsed.protocol === "http:" && !["127.0.0.1", "localhost", "::1"].includes(parsed.hostname)) {
      throw new Error("Remote account service requires HTTPS; HTTP is allowed only for loopback acceptance testing.");
    }
    this.baseUrl = parsed.toString().replace(/\/$/, "");
  }

  private async request(path: string, init: RequestInit): Promise<Record<string, unknown>> {
    const response = await fetch(`${this.baseUrl}${path}`, {
      ...init,
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json",
        ...(init.headers ?? {}),
      },
      redirect: "error",
      cache: "no-store",
    });
    const body = await response.json().catch(() => ({})) as Record<string, unknown>;
    if (!response.ok) throw new Error(typeof body.error === "string" ? body.error : `Account service returned HTTP ${response.status}.`);
    return body;
  }

  async registerAccount(username: string, recoveryCode: string): Promise<PublicAccountPlatformSnapshot> {
    const identity = await this.deviceIdentity.currentPublicIdentity();
    const deviceId = deriveDeviceId(identity);
    const recoveryCodeHash = hashRecoveryCode(recoveryCode);
    const statement = accountRegistrationStatement({
      accountId: this.accountId,
      username,
      recoveryCodeHash,
      deviceId,
    });
    const deviceProof = await this.deviceIdentity.signChallenge(statement);
    const result = await this.request("/v1/accounts/register", {
      method: "POST",
      body: JSON.stringify({
        accountId: this.accountId,
        username,
        recoveryCodeHash,
        device: identity,
        deviceProof,
      }),
    });
    const snapshot = result.snapshot as PublicAccountPlatformSnapshot | undefined;
    if (!snapshot?.account || snapshot.account.accountId !== this.accountId || snapshot.deviceId !== deviceId) {
      throw new Error("Account service returned an invalid registration snapshot.");
    }
    return structuredClone(snapshot);
  }

  private async authenticated(
    operation: AccountServiceOperation,
    path: string,
    extra: Record<string, unknown> = {},
  ): Promise<Record<string, unknown>> {
    const identity = await this.deviceIdentity.currentPublicIdentity();
    const deviceId = deriveDeviceId(identity);
    const challengePath = LIFECYCLE_OPERATIONS.has(operation)
      ? "/v1/lifecycle/auth/challenge"
      : "/v1/auth/challenge";
    const challenge = await this.request(challengePath, {
      method: "POST",
      body: JSON.stringify({ accountId: this.accountId, deviceId, operation }),
    });
    if (typeof challenge.challengeId !== "string" || typeof challenge.challenge !== "string") {
      throw new Error("Account service returned an invalid authentication challenge.");
    }
    const signature = await this.deviceIdentity.signChallenge(challenge.challenge);
    return this.request(path, {
      method: "POST",
      body: JSON.stringify({
        accountId: this.accountId,
        auth: { challengeId: challenge.challengeId, signature },
        ...extra,
      }),
    });
  }

  async refresh(accountId: string): Promise<void> {
    if (accountId !== this.accountId) throw new Error("Account sync client is scoped to a different Email Shield account.");
    const result = await this.authenticated("snapshot", "/v1/sync/snapshot");
    const snapshot = result as unknown as AccountFamilySyncSnapshot;
    if (snapshot.schemaVersion !== 1 || !snapshot.account || !Number.isFinite(snapshot.synchronizedAt)) {
      throw new Error("Account service returned an invalid synchronization snapshot.");
    }
    this.onSnapshot?.(structuredClone(snapshot));
  }

  async snapshot(): Promise<AccountFamilySyncSnapshot> {
    const result = await this.authenticated("snapshot", "/v1/sync/snapshot");
    return result as unknown as AccountFamilySyncSnapshot;
  }

  async publishThreat(input: {
    accountId: string;
    familyCircleId: string;
    campaignFingerprint: string;
    source: "report_scam" | "family_block";
  }): Promise<void> {
    if (input.accountId !== this.accountId) throw new Error("Family threat sync is scoped to a different Email Shield account.");
    // familyCircleId is intentionally not sent as authority. The authenticated
    // service resolves current membership server-side so a client cannot write
    // into another family's circle by changing an ID.
    await this.authenticated("family:threat", "/v1/family/threat", {
      campaignFingerprint: input.campaignFingerprint,
      source: input.source,
    });
  }

  async createFamily(): Promise<PublicAccountPlatformSnapshot> {
    return await this.authenticated("family:create", "/v1/family/create") as unknown as PublicAccountPlatformSnapshot;
  }

  async createInvite(): Promise<{ inviteCode: string; expiresAt: number }> {
    return await this.authenticated("family:invite", "/v1/family/invite") as unknown as { inviteCode: string; expiresAt: number };
  }

  async joinFamily(inviteCode: string): Promise<PublicAccountPlatformSnapshot> {
    return await this.authenticated("family:join", "/v1/family/join", { inviteCode }) as unknown as PublicAccountPlatformSnapshot;
  }

  async leaveFamily(): Promise<PublicAccountPlatformSnapshot> {
    return await this.authenticated("family:leave", "/v1/family/leave") as unknown as PublicAccountPlatformSnapshot;
  }

  async setStrictFamilyProtection(enabled: boolean): Promise<PublicAccountPlatformSnapshot> {
    return await this.authenticated("family:strict", "/v1/family/strict", { enabled }) as unknown as PublicAccountPlatformSnapshot;
  }

  async removeMember(memberAccountId: string): Promise<PublicAccountPlatformSnapshot> {
    return await this.authenticated("family:remove-member", "/v1/family/remove-member", { memberAccountId }) as unknown as PublicAccountPlatformSnapshot;
  }

  async exportAccountMetadata(): Promise<PrivacySafeAccountExportV1> {
    return await this.authenticated("account:export", "/v1/lifecycle/account/export") as unknown as PrivacySafeAccountExportV1;
  }

  async rotateRecoveryCode(): Promise<{ recoveryCode: string; recoveryCodeNotice: string }> {
    return await this.authenticated("recovery:rotate", "/v1/lifecycle/recovery/rotate") as unknown as {
      recoveryCode: string;
      recoveryCodeNotice: string;
    };
  }

  async revokeOtherDevices(): Promise<{ revoked: number }> {
    return await this.authenticated("devices:revoke-others", "/v1/lifecycle/devices/revoke-others") as unknown as { revoked: number };
  }

  async signOutEverywhere(): Promise<{ revoked: number; recoveryRequired: true }> {
    return await this.authenticated("devices:signout-everywhere", "/v1/lifecycle/signout-everywhere") as unknown as {
      revoked: number;
      recoveryRequired: true;
    };
  }

  async deleteFamily(): Promise<Record<string, unknown>> {
    return await this.authenticated("family:delete", "/v1/lifecycle/family/delete", { confirmation: "DELETE FAMILY" });
  }

  async deleteAccount(): Promise<Record<string, unknown>> {
    return await this.authenticated("account:delete", "/v1/lifecycle/account/delete", { confirmation: "DELETE ACCOUNT" });
  }
}
