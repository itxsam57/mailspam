import type { EmailAdapter, SpamReportMode } from "../canonical/adapter.js";
import { normalizeProviderNativeIds } from "./blockAndCleanup.js";

export interface ReportSpamWorkflowResult {
  requested: number;
  reported: number;
  mode: SpamReportMode | null;
  failed: Array<{ messageId: string; reason: string }>;
}

/**
 * Executes an explicit provider-level Spam/Junk action. The workflow does not
 * block a sender, delete mail, report to Email Shield community intelligence,
 * or claim that the provider trained a global filter. It reports only the
 * exact provider-native messages supplied by an account-scoped opaque token.
 */
export async function reportMessagesAsSpam(
  adapter: EmailAdapter,
  providerNativeIds: unknown,
  signal: AbortSignal,
): Promise<ReportSpamWorkflowResult> {
  const ids = normalizeProviderNativeIds(providerNativeIds, 100);
  const result: ReportSpamWorkflowResult = {
    requested: ids.length,
    reported: 0,
    mode: null,
    failed: [],
  };

  try {
    const providerResult = await adapter.reportSpam(ids, signal);
    if (
      providerResult.requested !== ids.length ||
      providerResult.reported !== ids.length
    ) {
      throw new Error(
        `Provider reported ${providerResult.reported} of ${providerResult.requested} requested message(s).`,
      );
    }
    result.reported = providerResult.reported;
    result.mode = providerResult.mode;
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    for (const id of ids) result.failed.push({ messageId: id, reason });
  }

  return result;
}
