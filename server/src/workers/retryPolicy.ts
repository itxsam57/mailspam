export function isRetryableScanError(error: unknown): boolean {
  if (error instanceof DOMException && error.name === "AbortError") return false;
  if (!(error instanceof Error)) return false;
  return error.name === "ImapCommandTimeoutError" || /IMAP .+ exceeded \d+ms deadline/i.test(error.message);
}

export async function runWithSingleRetry<T>(
  operation: (attempt: 1 | 2) => Promise<T>,
  onRetry: (error: Error) => void | Promise<void>,
): Promise<T> {
  try {
    return await operation(1);
  } catch (error) {
    if (!isRetryableScanError(error)) throw error;
    await onRetry(error as Error);
    return await operation(2);
  }
}
