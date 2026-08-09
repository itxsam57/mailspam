const GOOGLE_REVOCATION_ENDPOINT = "https://oauth2.googleapis.com/revoke";
const MAX_REVOCATION_RESPONSE_BYTES = 16 * 1024;

export class GoogleOAuthRevocationError extends Error {
  constructor(message = "Google did not confirm OAuth access revocation.") {
    super(message);
    this.name = "GoogleOAuthRevocationError";
  }
}

/**
 * Revokes a Google access or refresh token using Google's OAuth revocation
 * endpoint. A token that Google reports as already invalid is treated as a
 * successful terminal state because there is no remaining provider grant that
 * Email Shield can revoke. Other failures remain visible and block local
 * credential deletion so disconnect cannot falsely report success.
 */
export async function revokeGoogleOAuthToken(token: string): Promise<void> {
  if (typeof token !== "string" || token.length < 8) {
    throw new GoogleOAuthRevocationError("The protected Google credential is unavailable for revocation.");
  }

  const body = new URLSearchParams({ token });
  let response: Response;
  try {
    response = await fetch(GOOGLE_REVOCATION_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
      redirect: "error",
      signal: AbortSignal.timeout(15_000),
    });
  } catch {
    throw new GoogleOAuthRevocationError();
  }

  if (response.status === 200) {
    // Drain a bounded response without surfacing it. Google's documented
    // successful response is empty, and provider output must never enter logs.
    await response.arrayBuffer().then((value) => {
      if (value.byteLength > MAX_REVOCATION_RESPONSE_BYTES) {
        throw new GoogleOAuthRevocationError("Google returned an oversized revocation response.");
      }
    }).catch((error) => {
      if (error instanceof GoogleOAuthRevocationError) throw error;
    });
    return;
  }

  const text = await response.text().catch(() => "");
  if (text.length <= MAX_REVOCATION_RESPONSE_BYTES) {
    try {
      const payload = JSON.parse(text) as { error?: unknown };
      if (payload.error === "invalid_token") return;
    } catch {}
  }
  throw new GoogleOAuthRevocationError();
}
