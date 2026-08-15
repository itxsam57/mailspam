import type { NormalizedFolder } from "../../canonical/envelope.js";

export type FixtureMutableFolder = Extract<NormalizedFolder, "inbox" | "spam" | "trash">;
export type FixtureFolderState = SharedArrayBuffer;

// The synthetic corpus is deliberately small. Keep a fixed bounded shared
// state so Worker threads and the desktop owner observe the same fixture
// mailbox without sending message content through the scan API.
export const FIXTURE_FOLDER_STATE_CAPACITY = 4_096;

const FOLDER_TO_CODE: Record<FixtureMutableFolder, number> = {
  inbox: 1,
  spam: 2,
  trash: 3,
};

function folderFromCode(code: number): FixtureMutableFolder | null {
  if (code === FOLDER_TO_CODE.inbox) return "inbox";
  if (code === FOLDER_TO_CODE.spam) return "spam";
  if (code === FOLDER_TO_CODE.trash) return "trash";
  return null;
}

export function createFixtureFolderState(): FixtureFolderState {
  return new SharedArrayBuffer(FIXTURE_FOLDER_STATE_CAPACITY);
}

function view(state: FixtureFolderState): Uint8Array {
  if (!(state instanceof SharedArrayBuffer) || state.byteLength !== FIXTURE_FOLDER_STATE_CAPACITY) {
    throw new Error("Fixture mailbox shared folder state is invalid.");
  }
  return new Uint8Array(state);
}

export function readFixtureFolderState(
  state: FixtureFolderState,
  index: number,
): FixtureMutableFolder | null {
  if (!Number.isSafeInteger(index) || index < 0 || index >= FIXTURE_FOLDER_STATE_CAPACITY) {
    throw new Error("Fixture mailbox message index exceeds the shared-state bound.");
  }
  return folderFromCode(Atomics.load(view(state), index));
}

export function writeFixtureFolderState(
  state: FixtureFolderState,
  index: number,
  folder: FixtureMutableFolder,
): void {
  if (!Number.isSafeInteger(index) || index < 0 || index >= FIXTURE_FOLDER_STATE_CAPACITY) {
    throw new Error("Fixture mailbox message index exceeds the shared-state bound.");
  }
  Atomics.store(view(state), index, FOLDER_TO_CODE[folder]);
}
