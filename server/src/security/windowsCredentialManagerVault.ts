import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { join } from "node:path";
import {
  CredentialVaultError,
  credentialTargetName,
  type CredentialReference,
  type CredentialVault,
  type CredentialVaultCapabilities,
  validateCredentialReference,
  validateCredentialSecret,
} from "./credentialVault.js";

export interface WindowsCredentialBridgeRequest {
  operation: "write" | "read" | "delete";
  target: string;
  secret?: string;
}

export interface WindowsCredentialBridgeResponse {
  ok: boolean;
  found?: boolean;
  secret?: string;
}

export interface WindowsCredentialBridge {
  invoke(request: WindowsCredentialBridgeRequest): Promise<WindowsCredentialBridgeResponse>;
}

const POWERSHELL_BRIDGE = String.raw`
$ErrorActionPreference = 'Stop'
$source = @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public static class EmailShieldCredentialApi
{
    private const uint CRED_TYPE_GENERIC = 1;
    private const uint CRED_PERSIST_LOCAL_MACHINE = 2;
    private const int ERROR_NOT_FOUND = 1168;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CREDENTIAL
    {
        public uint Flags;
        public uint Type;
        [MarshalAs(UnmanagedType.LPWStr)] public string TargetName;
        [MarshalAs(UnmanagedType.LPWStr)] public string Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        [MarshalAs(UnmanagedType.LPWStr)] public string TargetAlias;
        [MarshalAs(UnmanagedType.LPWStr)] public string UserName;
    }

    [DllImport("advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredWrite([In] ref CREDENTIAL credential, uint flags);

    [DllImport("advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredRead(string target, uint type, uint flags, out IntPtr credentialPtr);

    [DllImport("advapi32.dll", EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredDelete(string target, uint type, uint flags);

    [DllImport("advapi32.dll")]
    private static extern void CredFree(IntPtr buffer);

    public static void Write(string target, string secret)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(secret);
        if (bytes.Length == 0 || bytes.Length > 2560)
            throw new ArgumentException("Credential blob size is invalid.");

        IntPtr blob = Marshal.AllocCoTaskMem(bytes.Length);
        try
        {
            Marshal.Copy(bytes, 0, blob, bytes.Length);
            var credential = new CREDENTIAL
            {
                Flags = 0,
                Type = CRED_TYPE_GENERIC,
                TargetName = target,
                Comment = "Email Shield protected credential",
                CredentialBlobSize = (uint)bytes.Length,
                CredentialBlob = blob,
                Persist = CRED_PERSIST_LOCAL_MACHINE,
                AttributeCount = 0,
                Attributes = IntPtr.Zero,
                TargetAlias = null,
                UserName = "Email Shield"
            };

            if (!CredWrite(ref credential, 0))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        finally
        {
            Array.Clear(bytes, 0, bytes.Length);
            for (int i = 0; i < bytes.Length; i++) Marshal.WriteByte(blob, i, 0);
            Marshal.FreeCoTaskMem(blob);
        }
    }

    public static string Read(string target)
    {
        IntPtr credentialPtr;
        if (!CredRead(target, CRED_TYPE_GENERIC, 0, out credentialPtr))
        {
            int error = Marshal.GetLastWin32Error();
            if (error == ERROR_NOT_FOUND) return null;
            throw new Win32Exception(error);
        }

        try
        {
            var credential = Marshal.PtrToStructure<CREDENTIAL>(credentialPtr);
            if (credential.CredentialBlob == IntPtr.Zero || credential.CredentialBlobSize == 0)
                return String.Empty;

            byte[] bytes = new byte[credential.CredentialBlobSize];
            try
            {
                Marshal.Copy(credential.CredentialBlob, bytes, 0, bytes.Length);
                return Encoding.UTF8.GetString(bytes);
            }
            finally
            {
                Array.Clear(bytes, 0, bytes.Length);
            }
        }
        finally
        {
            CredFree(credentialPtr);
        }
    }

    public static void Delete(string target)
    {
        if (CredDelete(target, CRED_TYPE_GENERIC, 0)) return;
        int error = Marshal.GetLastWin32Error();
        if (error == ERROR_NOT_FOUND) return;
        throw new Win32Exception(error);
    }
}
'@
Add-Type -TypeDefinition $source
@{ ready = $true } | ConvertTo-Json -Compress

while (($requestText = [Console]::In.ReadLine()) -ne $null) {
    $request = $null
    $secret = $null
    try {
        $request = $requestText | ConvertFrom-Json
        switch ($request.operation) {
            'write' {
                [EmailShieldCredentialApi]::Write([string]$request.target, [string]$request.secret)
                @{ ok = $true } | ConvertTo-Json -Compress
            }
            'read' {
                $secret = [EmailShieldCredentialApi]::Read([string]$request.target)
                if ($null -eq $secret) {
                    @{ ok = $true; found = $false } | ConvertTo-Json -Compress
                } else {
                    @{ ok = $true; found = $true; secret = $secret } | ConvertTo-Json -Compress
                }
            }
            'delete' {
                [EmailShieldCredentialApi]::Delete([string]$request.target)
                @{ ok = $true } | ConvertTo-Json -Compress
            }
            default { throw 'Unsupported credential bridge operation.' }
        }
    } catch {
        @{ ok = $false } | ConvertTo-Json -Compress
    } finally {
        if ($null -ne $request -and $request.PSObject.Properties.Name -contains 'secret') {
            $request.secret = $null
        }
        $secret = $null
        $request = $null
        $requestText = $null
    }
}
`;

const MAX_OUTPUT_BYTES = 16 * 1024;
const HELPER_STARTUP_TIMEOUT_MS = 30_000;
const BRIDGE_OPERATION_TIMEOUT_MS = 10_000;
const MAX_QUEUED_LINES = 2;

type PendingLine = {
  resolve: (line: string) => void;
  reject: (error: Error) => void;
  timer: NodeJS.Timeout;
};

function trustedPowerShellPath(): string {
  const systemRoot = process.env.SystemRoot?.trim() || "C:\\Windows";
  return join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
}

function sanitizedBridgeError(message: string): CredentialVaultError {
  return new CredentialVaultError("VAULT_OPERATION_FAILED", message);
}

export class PowerShellWindowsCredentialBridge implements WindowsCredentialBridge {
  private child: ChildProcessWithoutNullStreams | null = null;
  private startup: Promise<void> | null = null;
  private operationTail: Promise<void> = Promise.resolve();
  private stdoutBuffer = Buffer.alloc(0);
  private queuedLines: string[] = [];
  private pendingLine: PendingLine | null = null;
  private exitHandler: (() => void) | null = null;

  invoke(request: WindowsCredentialBridgeRequest): Promise<WindowsCredentialBridgeResponse> {
    if (process.platform !== "win32") {
      return Promise.reject(new CredentialVaultError("VAULT_UNAVAILABLE", "Windows Credential Manager is unavailable on this platform."));
    }

    const run = this.operationTail.then(
      () => this.invokeSerialized(request),
      () => this.invokeSerialized(request),
    );
    this.operationTail = run.then(() => undefined, () => undefined);
    return run;
  }

  close(): void {
    this.resetHelper(sanitizedBridgeError("Windows Credential Manager helper was closed."));
  }

  private async invokeSerialized(request: WindowsCredentialBridgeRequest): Promise<WindowsCredentialBridgeResponse> {
    await this.ensureHelper();
    const child = this.child;
    if (!child) throw sanitizedBridgeError("Windows Credential Manager helper is unavailable.");

    try {
      await new Promise<void>((resolve, reject) => {
        child.stdin.write(`${JSON.stringify(request)}\n`, "utf8", (error) => {
          if (error) reject(sanitizedBridgeError("Windows Credential Manager request could not be written."));
          else resolve();
        });
      });

      const line = await this.waitForLine(
        BRIDGE_OPERATION_TIMEOUT_MS,
        "Windows Credential Manager operation timed out.",
      );
      let parsed: WindowsCredentialBridgeResponse | null = null;
      try {
        parsed = JSON.parse(line) as WindowsCredentialBridgeResponse;
      } catch {}

      if (!parsed || typeof parsed.ok !== "boolean" || !parsed.ok) {
        throw sanitizedBridgeError("Windows Credential Manager operation failed.");
      }
      return parsed;
    } catch (error) {
      if (error instanceof CredentialVaultError) {
        if (error.message.includes("timed out") || error.message.includes("could not be written") || error.message.includes("helper")) {
          this.resetHelper(error);
        }
        throw error;
      }
      const safe = sanitizedBridgeError("Windows Credential Manager operation failed.");
      this.resetHelper(safe);
      throw safe;
    }
  }

  private async ensureHelper(): Promise<void> {
    if (this.child) return;
    if (this.startup) return this.startup;
    this.startup = this.startHelper();
    try {
      await this.startup;
    } finally {
      this.startup = null;
    }
  }

  private async startHelper(): Promise<void> {
    const encodedCommand = Buffer.from(POWERSHELL_BRIDGE, "utf16le").toString("base64");
    let child: ChildProcessWithoutNullStreams;
    try {
      child = spawn(
        trustedPowerShellPath(),
        ["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encodedCommand],
        {
          stdio: ["pipe", "pipe", "pipe"],
          windowsHide: true,
          shell: false,
        },
      );
    } catch {
      throw sanitizedBridgeError("Windows Credential Manager could not be started.");
    }

    this.child = child;
    this.stdoutBuffer = Buffer.alloc(0);
    this.queuedLines = [];

    child.stdout.on("data", (chunk: Buffer) => this.acceptStdout(child, chunk));
    // Drain stderr to avoid child-process backpressure, but never retain or
    // surface it. A lower layer can contain sensitive operating-system or
    // credential context even when Email Shield did not put a secret there.
    child.stderr.resume();
    child.once("error", () => {
      if (this.child === child) {
        this.resetHelper(sanitizedBridgeError("Windows Credential Manager helper failed."));
      }
    });
    child.once("close", () => {
      if (this.child === child) {
        this.resetHelper(sanitizedBridgeError("Windows Credential Manager helper exited unexpectedly."), false);
      }
    });

    // The helper is subordinate to the desktop process, but it must not keep a
    // short-lived test/CLI process alive after all application work is done.
    child.unref();
    (child.stdin as NodeJS.WritableStream & { unref?: () => void }).unref?.();
    (child.stdout as NodeJS.ReadableStream & { unref?: () => void }).unref?.();
    (child.stderr as NodeJS.ReadableStream & { unref?: () => void }).unref?.();
    this.exitHandler = () => {
      try { child.kill(); } catch {}
    };
    process.once("exit", this.exitHandler);

    try {
      const readyLine = await this.waitForLine(
        HELPER_STARTUP_TIMEOUT_MS,
        "Windows Credential Manager helper initialization timed out.",
      );
      let ready = false;
      try {
        ready = (JSON.parse(readyLine) as { ready?: unknown }).ready === true;
      } catch {}
      if (!ready) throw sanitizedBridgeError("Windows Credential Manager helper initialization failed.");
    } catch (error) {
      const safe = error instanceof CredentialVaultError
        ? error
        : sanitizedBridgeError("Windows Credential Manager helper initialization failed.");
      this.resetHelper(safe);
      throw safe;
    }
  }

  private acceptStdout(child: ChildProcessWithoutNullStreams, chunk: Buffer): void {
    if (this.child !== child) return;
    this.stdoutBuffer = Buffer.concat([this.stdoutBuffer, Buffer.from(chunk)]);

    while (true) {
      const newline = this.stdoutBuffer.indexOf(0x0a);
      if (newline < 0) break;
      let lineBuffer = this.stdoutBuffer.subarray(0, newline);
      this.stdoutBuffer = this.stdoutBuffer.subarray(newline + 1);
      if (lineBuffer.length > 0 && lineBuffer[lineBuffer.length - 1] === 0x0d) {
        lineBuffer = lineBuffer.subarray(0, lineBuffer.length - 1);
      }
      if (lineBuffer.length > MAX_OUTPUT_BYTES) {
        this.resetHelper(sanitizedBridgeError("Windows Credential Manager returned an oversized response."));
        return;
      }
      const line = lineBuffer.toString("utf8");
      if (this.pendingLine) {
        const pending = this.pendingLine;
        this.pendingLine = null;
        clearTimeout(pending.timer);
        pending.resolve(line);
      } else {
        if (this.queuedLines.length >= MAX_QUEUED_LINES) {
          this.resetHelper(sanitizedBridgeError("Windows Credential Manager returned unexpected output."));
          return;
        }
        this.queuedLines.push(line);
      }
    }

    if (this.stdoutBuffer.length > MAX_OUTPUT_BYTES) {
      this.resetHelper(sanitizedBridgeError("Windows Credential Manager returned an oversized response."));
    }
  }

  private waitForLine(timeoutMs: number, timeoutMessage: string): Promise<string> {
    const queued = this.queuedLines.shift();
    if (queued !== undefined) return Promise.resolve(queued);
    if (this.pendingLine) {
      return Promise.reject(sanitizedBridgeError("Windows Credential Manager response state is invalid."));
    }

    return new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => {
        const error = sanitizedBridgeError(timeoutMessage);
        this.resetHelper(error);
      }, timeoutMs);
      this.pendingLine = { resolve, reject, timer };
    });
  }

  private resetHelper(error: CredentialVaultError, kill = true): void {
    const child = this.child;
    this.child = null;
    this.stdoutBuffer = Buffer.alloc(0);
    this.queuedLines = [];

    if (this.pendingLine) {
      const pending = this.pendingLine;
      this.pendingLine = null;
      clearTimeout(pending.timer);
      pending.reject(error);
    }

    if (this.exitHandler) {
      process.removeListener("exit", this.exitHandler);
      this.exitHandler = null;
    }
    if (kill && child) {
      try { child.kill(); } catch {}
    }
  }
}

export class WindowsCredentialManagerVault implements CredentialVault {
  constructor(private readonly bridge: WindowsCredentialBridge = new PowerShellWindowsCredentialBridge()) {}

  capabilities(): CredentialVaultCapabilities {
    return {
      backend: "windows-credential-manager",
      available: process.platform === "win32" || !(this.bridge instanceof PowerShellWindowsCredentialBridge),
      persistent: true,
      userBound: true,
      // Credential Manager protects secrets for the signed-in Windows user,
      // but hardware-backed and application-bound guarantees are not universal
      // and therefore must not be claimed.
      hardwareBacked: false,
      applicationBound: false,
    };
  }

  async write(reference: CredentialReference, secret: string): Promise<void> {
    validateCredentialReference(reference);
    validateCredentialSecret(secret);
    try {
      const response = await this.bridge.invoke({ operation: "write", target: credentialTargetName(reference), secret });
      if (!response.ok) throw new Error("Credential write was not confirmed.");
    } catch (error) {
      if (error instanceof CredentialVaultError) throw error;
      // Never retain an arbitrary lower-layer cause here. A bridge failure may
      // contain the very secret being written; keeping it as Error.cause would
      // make later logging or diagnostics capable of exposing that value.
      throw new CredentialVaultError("VAULT_OPERATION_FAILED", "Windows Credential Manager write failed.");
    }
  }

  async read(reference: CredentialReference): Promise<string | null> {
    validateCredentialReference(reference);
    try {
      const response = await this.bridge.invoke({ operation: "read", target: credentialTargetName(reference) });
      if (!response.ok) throw new Error("Credential read was not confirmed.");
      if (!response.found) return null;
      if (typeof response.secret !== "string" || response.secret.length === 0) {
        throw new Error("Credential Manager returned an invalid credential payload.");
      }
      validateCredentialSecret(response.secret);
      return response.secret;
    } catch (error) {
      if (error instanceof CredentialVaultError) throw error;
      throw new CredentialVaultError("VAULT_OPERATION_FAILED", "Windows Credential Manager read failed.");
    }
  }

  async delete(reference: CredentialReference): Promise<void> {
    validateCredentialReference(reference);
    try {
      const response = await this.bridge.invoke({ operation: "delete", target: credentialTargetName(reference) });
      if (!response.ok) throw new Error("Credential deletion was not confirmed.");
    } catch (error) {
      if (error instanceof CredentialVaultError) throw error;
      throw new CredentialVaultError("VAULT_OPERATION_FAILED", "Windows Credential Manager deletion failed.");
    }
  }
}
