import { normalizeUsername } from "../platform/accountFamilyTypes.js";

function accountId(value: string): string {
  if (!/^acct_[A-Za-z0-9_-]{8,160}$/.test(value)) throw new Error("Email Shield account ID is invalid.");
  return value;
}

function deviceId(value: string): string {
  if (!/^dev_[a-f0-9]{64}$/.test(value)) throw new Error("Device ID is invalid.");
  return value;
}

function recoveryHash(value: string): string {
  if (!/^[a-f0-9]{64}$/.test(value)) throw new Error("Recovery proof hash is invalid.");
  return value;
}

export function accountRegistrationStatement(input: {
  accountId: string;
  username: string;
  recoveryCodeHash: string;
  deviceId: string;
}): string {
  return [
    "email-shield-account-registration-v1",
    accountId(input.accountId),
    normalizeUsername(input.username),
    recoveryHash(input.recoveryCodeHash),
    deviceId(input.deviceId),
  ].join("\n");
}

export function accountRecoveryDeviceStatement(input: {
  username: string;
  deviceId: string;
}): string {
  return [
    "email-shield-account-recovery-device-v1",
    normalizeUsername(input.username),
    deviceId(input.deviceId),
  ].join("\n");
}
