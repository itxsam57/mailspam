import { spawn } from "node:child_process";
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

$requestText = [Console]::In.ReadToEnd()
$request = $requestText | ConvertFrom-Json
try {
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
    exit 1
}
`;

const MAX_OUTPUT_BYTES = 16 * 1024;
const BRIDGE_TIMEOUT_MS = 10_000;

function trustedPowerShellPath(): string {
  const systemRoot = process.env.SystemRoot?.trim() || "C:\\Windows";
  return join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
}

export class PowerShellWindowsCredentialBridge implements WindowsCredentialBridge {
  async invoke(request: WindowsCredentialBridgeRequest): Promise<WindowsCredentialBridgeResponse> {
    if (process.platform !== "win32") {
      throw new CredentialVaultError("VAULT_UNAVAILABLE", "Windows Credential Manager is unavailable on this platform.");
    }

    const encodedCommand = Buffer.from(POWERSHELL_BRIDGE, "utf16le").toString("base64");
    return new Promise<WindowsCredentialBridgeResponse>((resolve, reject) => {
      const child = spawn(
        trustedPowerShellPath(),
        ["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encodedCommand],
        {
          stdio: ["pipe", "pipe", "pipe"],
          windowsHide: true,
        },
      );

      const stdoutChunks: Buffer[] = [];
      let stdoutBytes = 0;
      let settled = false;
      let timer: NodeJS.Timeout;
      const finish = (error?: Error, response?: WindowsCredentialBridgeResponse) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (error) reject(error);
        else resolve(response!);
      };

      child.stdout.on("data", (chunk: Buffer) => {
        if (settled) return;
        stdoutBytes += chunk.length;
        if (stdoutBytes > MAX_OUTPUT_BYTES) {
          child.kill();
          finish(new CredentialVaultError("VAULT_OPERATION_FAILED", "Windows Credential Manager returned an oversized response."));
          return;
        }
        stdoutChunks.push(Buffer.from(chunk));
      });
      // Drain stderr to avoid child-process backpressure, but never retain or
      // surface it. A lower layer can contain sensitive operating-system or
      // credential context even when Email Shield did not put a secret there.
      child.stderr.resume();
      child.once("error", () => {
        finish(new CredentialVaultError("VAULT_OPERATION_FAILED", "Windows Credential Manager could not be started."));
      });
      child.once("close", (code) => {
        if (settled) return;
        let parsed: WindowsCredentialBridgeResponse | null = null;
        try {
          parsed = JSON.parse(Buffer.concat(stdoutChunks).toString("utf8").trim()) as WindowsCredentialBridgeResponse;
        } catch {}

        if (code !== 0 || !parsed?.ok) {
          finish(new CredentialVaultError("VAULT_OPERATION_FAILED", "Windows Credential Manager operation failed."));
          return;
        }
        finish(undefined, parsed);
      });

      timer = setTimeout(() => {
        child.kill();
        finish(new CredentialVaultError("VAULT_OPERATION_FAILED", "Windows Credential Manager operation timed out."));
      }, BRIDGE_TIMEOUT_MS);

      child.stdin.end(JSON.stringify(request), "utf8");
    });
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
