# Email Shield — Personal Policy Management Centre

## Scope

The Personal Policy Management Centre is the selected-account control surface for Email Shield's existing encrypted personal policy engine. It does not introduce a second policy store and it does not change verdict precedence.

Managed policy classes:

1. blocked senders;
2. blocked domains;
3. trusted senders;
4. Safe exceptions, including exact-message exception hashes and supported legacy sender exceptions;
5. unsubscribe-history action hashes;
6. locally reported scam-campaign fingerprints.

## Security boundary

All policy reads and mutations remain under the desktop local-security boundary:

- process-local HttpOnly session;
- CSRF proof on protected reads;
- exact same-origin enforcement for mutations;
- expiring single-use mutation nonce;
- loopback/Host isolation and response redaction inherited from the desktop server.

The browser does not persist policy state in localStorage or sessionStorage. Policy values are rendered through DOM text APIs rather than interpolated into HTML.

Every management mutation persists through `SessionStore.mutateAndPersistPersonalPolicy()`. If encrypted persistence fails, the in-memory policy snapshot rolls back. After a successful management mutation, existing scan action tokens are invalidated so stale message controls require a rescan.

## Management operations

The protected local API supports:

- single revoke by category and normalized value;
- bulk revoke, bounded to 500 requested items per mutation and persisted once atomically;
- complete clear of one category with category-matching confirmation;
- full six-category reset only when the exact phrase `RESET PERSONAL POLICY` is supplied;
- strict policy backup import using explicit `merge` or `replace` mode;
- strict policy-only export.

Search and filtering are browser-side presentation only. They do not create a second index or persistent copy of personal policy.

## Policy-only backup format

Export format version 1 is exactly:

```json
{
  "schema": "email-shield-personal-policy",
  "version": 1,
  "policy": {
    "blockedSenders": [],
    "blockedDomains": [],
    "trustedSenders": [],
    "approvedExceptions": [],
    "unsubscribedActions": [],
    "reportedCampaigns": []
  }
}
```

The export deliberately excludes:

- account/session IDs;
- policy account keys;
- provider configuration;
- mailbox credentials;
- app passwords;
- OAuth access, refresh or ID tokens;
- OAuth authorization codes or PKCE verifier material;
- OAuth client secrets;
- native credential-vault references;
- message subject/body/raw HTML;
- provider-native message identifiers.

Responses use `Cache-Control: no-store` and are downloaded as `email-shield-personal-policy.json`.

## Import validation

Import accepts only the exact version-1 schema above. Unknown or missing top-level and policy fields are rejected rather than ignored.

Category validation:

- blocked/trusted sender entries must normalize as sender email addresses;
- blocked-domain entries must normalize as sender domains;
- Safe exceptions must be an exact `message:<64 hex>` key or a supported normalized legacy sender exception;
- unsubscribe-history values must be 64 lowercase hex characters;
- reported-campaign fingerprints must be 64 lowercase hex characters;
- duplicates are removed after normalization;
- each list remains bounded by the existing local policy limit.

`merge` unions validated entries with the current selected-account snapshot. `replace` replaces all six categories. Both operations persist as one transaction and roll back completely if encrypted persistence fails.

## User-interface behavior

The panel follows the account chip currently selected in the dashboard. It provides:

- search across rule type/value;
- category filtering;
- per-entry revoke;
- select-visible and bulk revoke;
- clear current category;
- policy-only export;
- merge/replace import;
- explicit full reset.

Privacy-reduced hashes are abbreviated visually for exact-message exceptions, unsubscribe history and reported campaigns. Raw sender/domain values remain visible because those values are the personal rules the user explicitly needs to manage.

## Regression lock

- `REG-048`
- `A-38`
- `tests/unit/policyManagementApi.test.ts`
- `tests/unit/policyManagementWeb.test.ts`
- full Windows/macOS/Ubuntu engineering gate

The former `GAP-009` is resolved by this implementation. Subjective layout/readability remains `MAN-018` owner acceptance; the data, privacy, security, import/export and persistence behavior is automated.
