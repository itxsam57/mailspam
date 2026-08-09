import { spawn } from "node:child_process";
import { CredentialVaultError } from "./credentialVault.js";

export interface NativeCredentialCommandOptions {
  executable: string;
  args: string[];
  stdin?: string;
  backendLabel: string;
  timeoutMs?: number;
  maxOutputBytes?: number;
}

export interface NativeCredentialCommandResult {
  exitCode: number | null;
  stdout: Buffer;
}

const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_OUTPUT_BYTES = 16 * 1024;

/**
 * Run a trusted native credential helper without a shell. Sensitive input is
 * carried only on stdin; stderr is deliberately drained and discarded because
 * lower layers can include secret-bearing or user-specific diagnostics.
 */
export function runNativeCredentialCommand(
  options: NativeCredentialCommandOptions,
): Promise<NativeCredentialCommandResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(options.executable, options.args, {
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
      shell: false,
    });

    const chunks: Buffer[] = [];
    let bytes = 0;
    let settled = false;
    let timer: NodeJS.Timeout;

    const finish = (error?: Error, result?: NativeCredentialCommandResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error);
      else resolve(result!);
    };

    child.stdout.on("data", (chunk: Buffer) => {
      if (settled) return;
      bytes += chunk.length;
      if (bytes > (options.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES)) {
        child.kill();
        finish(new CredentialVaultError(
          "VAULT_OPERATION_FAILED",
          `${options.backendLabel} returned an oversized response.`,
        ));
        return;
      }
      chunks.push(Buffer.from(chunk));
    });

    child.stderr.resume();
    child.once("error", () => {
      finish(new CredentialVaultError(
        "VAULT_OPERATION_FAILED",
        `${options.backendLabel} could not be started.`,
      ));
    });
    child.once("close", (exitCode) => {
      if (settled) return;
      finish(undefined, { exitCode, stdout: Buffer.concat(chunks) });
    });

    timer = setTimeout(() => {
      child.kill();
      finish(new CredentialVaultError(
        "VAULT_OPERATION_FAILED",
        `${options.backendLabel} operation timed out.`,
      ));
    }, options.timeoutMs ?? DEFAULT_TIMEOUT_MS);

    if (options.stdin === undefined) child.stdin.end();
    else child.stdin.end(options.stdin, "utf8");
  });
}
