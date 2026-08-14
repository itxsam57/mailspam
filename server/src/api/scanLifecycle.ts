import type { ScanCounters } from "../workflows/scanWorkflows.js";

export type ScanTerminalStatus = "completed" | "failed" | "stopped";

export interface ScanFinalization {
  scanId: string;
  status: ScanTerminalStatus;
  historySaved: boolean;
  resumable: boolean;
  counters: ScanCounters;
}

interface ActiveScanState {
  scanId: string;
  stopRequested: boolean;
  finalization: Promise<ScanFinalization>;
  resolveFinalization: (value: ScanFinalization) => void;
}

/**
 * Process-local ownership of one active scan per mailbox session.
 *
 * Stop is intentionally two-phase: callers first mark stopRequested, then wait
 * on finalization. The scan owner resolves finalization only after its terminal
 * history/checkpoint state is durable and the Worker has actually exited. This
 * prevents a new scan from overlapping the Worker that produced the checkpoint.
 */
export class ActiveScanLifecycle {
  private readonly active = new Map<string, ActiveScanState>();

  begin(sessionId: string, scanId: string): void {
    if (this.active.has(sessionId)) throw new Error("A scan lifecycle is already active for this mailbox session.");
    let resolveFinalization!: (value: ScanFinalization) => void;
    const finalization = new Promise<ScanFinalization>((resolve) => { resolveFinalization = resolve; });
    this.active.set(sessionId, { scanId, stopRequested: false, finalization, resolveFinalization });
  }

  requestStop(sessionId: string): boolean {
    const state = this.active.get(sessionId);
    if (!state) return false;
    state.stopRequested = true;
    return true;
  }

  stopRequested(sessionId: string, scanId?: string): boolean {
    const state = this.active.get(sessionId);
    return Boolean(state && (!scanId || state.scanId === scanId) && state.stopRequested);
  }

  wait(sessionId: string): Promise<ScanFinalization> | null {
    return this.active.get(sessionId)?.finalization ?? null;
  }

  finalize(sessionId: string, scanId: string, value: ScanFinalization): boolean {
    const state = this.active.get(sessionId);
    if (!state || state.scanId !== scanId) return false;
    this.active.delete(sessionId);
    state.resolveFinalization(structuredClone(value));
    return true;
  }

  has(sessionId: string): boolean {
    return this.active.has(sessionId);
  }
}

export const activeScanLifecycle = new ActiveScanLifecycle();