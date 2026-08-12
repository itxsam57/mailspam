import type {
  EmailShieldAccount,
  FamilyCircle,
  PublicAccountPlatformSnapshot,
  RegisteredDevice,
  VerifiedEntitlement,
} from "../platform/accountFamilyTypes.js";

export const ACCOUNT_SERVICE_SCHEMA_VERSION = 1 as const;
export const ACCOUNT_SERVICE_CHALLENGE_TTL_MS = 2 * 60 * 1_000;
export const ACCOUNT_SERVICE_MAX_CHALLENGES = 10_000;

export type AccountServiceOperation =
  | "snapshot"
  | "family:create"
  | "family:invite"
  | "family:join"
  | "family:leave"
  | "family:strict"
  | "family:remove-member"
  | "family:threat";

export interface AccountServiceState {
  schemaVersion: typeof ACCOUNT_SERVICE_SCHEMA_VERSION;
  accounts: EmailShieldAccount[];
  familyCircles: FamilyCircle[];
}

export interface AccountRegistrationInput {
  accountId: string;
  username: string;
  recoveryCodeHash: string;
  device: RegisteredDevice;
}

export interface AccountServiceChallenge {
  challengeId: string;
  accountId: string;
  deviceId: string;
  operation: AccountServiceOperation;
  challenge: string;
  createdAt: number;
  expiresAt: number;
  usedAt: number | null;
}

export interface AccountServiceAuthProof {
  challengeId: string;
  signature: string;
}

export interface AccountServiceSnapshot {
  schemaVersion: typeof ACCOUNT_SERVICE_SCHEMA_VERSION;
  account: PublicAccountPlatformSnapshot;
  synchronizedAt: number;
}

export interface AccountServiceEntitlementUpdate {
  accountId: string;
  entitlement: VerifiedEntitlement;
}

export function emptyAccountServiceState(): AccountServiceState {
  return { schemaVersion: ACCOUNT_SERVICE_SCHEMA_VERSION, accounts: [], familyCircles: [] };
}
