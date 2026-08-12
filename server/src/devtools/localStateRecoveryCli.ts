import { archiveUnreadableLocalState } from "../api/localStateRecovery.js";

try {
  const result = await archiveUnreadableLocalState();
  if (!result.archiveDirectory) {
    console.log("Email Shield found no unreadable encrypted local state. Nothing was moved.");
  } else {
    console.log(`Archived ${result.archivedFiles.length} unreadable encrypted state file(s) to ${result.archiveDirectory}`);
    console.log("The original encrypted bytes and their SHA-256 digests were preserved. You can now run `npm run dev`.");
  }
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
