import type { CanonicalEnvelope } from "../canonical/envelope.js";

export interface UnsubscribeCapability {
  available: boolean;
  method: "one_click_post" | "mailto" | "link_only" | "none";
  /** The URL/mailto target the UI should invoke. */
  target: string | null;
}

/**
 * Determines how (or whether) a message can be unsubscribed from, per
 * spec's newsletter/marketing-abuse handling: prefer RFC 8058 one-click
 * POST (List-Unsubscribe-Post: List-Unsubscribe=One-Click) over a bare
 * List-Unsubscribe link, since a bare GET link can itself be a tracking
 * or confirmation trap on abusive senders.
 */
export function unsubscribeCapability(envelope: CanonicalEnvelope): UnsubscribeCapability {
  const { listUnsubscribe, listUnsubscribePost } = envelope.listHeaders;
  if (!listUnsubscribe) return { available: false, method: "none", target: null };

  const isOneClick = listUnsubscribePost?.toLowerCase().includes("one-click") ?? false;
  const mailtoMatch = listUnsubscribe.match(/mailto:(\S+)/i);
  const httpMatch = listUnsubscribe.match(/(https?:\/\/\S+)/i);

  if (isOneClick && httpMatch) {
    return { available: true, method: "one_click_post", target: httpMatch[1]! };
  }
  if (httpMatch) {
    return { available: true, method: "link_only", target: httpMatch[1]! };
  }
  if (mailtoMatch) {
    return { available: true, method: "mailto", target: mailtoMatch[1]! };
  }
  return { available: false, method: "none", target: null };
}

/**
 * Executes the one-click RFC 8058 POST. Only ever called for
 * method === "one_click_post" — link_only/mailto require the user to
 * follow through themselves (surfaced as a normal link/compose action in
 * the UI, not auto-invoked), since those aren't guaranteed to be a single
 * safe idempotent action.
 */
export async function executeOneClickUnsubscribe(
  target: string,
  postImpl: (url: string) => Promise<{ status: number }>
): Promise<{ success: boolean; status?: number }> {
  try {
    const res = await postImpl(target);
    return { success: res.status >= 200 && res.status < 300, status: res.status };
  } catch {
    return { success: false };
  }
}
