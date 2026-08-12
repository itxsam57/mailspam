import { deriveDeviceId, type FamilyThreatSnapshot, type PublicAccountPlatformSnapshot } from "./accountFamilyTypes.js";
import type { DeviceIdentityPort, FamilySyncPort } from "./accountFamilyPorts.js";

export interface AccountFamilySyncSnapshot {
  schemaVersion: 1;
  account: PublicAccountPlatformSnapshot;
  familyThreats: FamilyThreatSnapshot | null;
  synchronizedAt: number;
}

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

  private async authenticated(
    operation: "snapshot" | "family:create" | "family:invite" | "family:join" | "family:leave" | "family:strict" | "family:remove-member" | "family:threat",
    path: string,
    extra: Record<string, unknown> = {},
  ): Promise<Record<string, unknown>> {
    const identity = await this.deviceIdentity.currentPublicIdentity();
    const deviceId = deriveDeviceId(identity);
    const challenge = await this.request("/v1/auth/challenge", {
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
}
