import { homedir } from "node:os";
import { join } from "node:path";

export function defaultEmailShieldDataDirectory(): string {
  return process.env.EMAIL_SHIELD_DATA_DIR?.trim() || join(homedir(), ".email-shield");
}
