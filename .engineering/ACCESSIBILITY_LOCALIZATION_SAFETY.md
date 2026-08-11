# Email Shield — Accessibility, Localization and Safety Education Contract

Date: 2026-08-11
Status: repository implementation and automated source/behavior checks complete; owner assistive-technology review remains manual acceptance.

## Accessibility boundary

- The document has a language, keyboard-visible skip link, explicit main landmark and labelled regions.
- Provider/mode, dynamically rendered credential inputs, background schedule controls and policy search/filter/import controls have programmatic labels; placeholders are not labels.
- Native buttons, inputs, selects, details and links retain standard keyboard behavior. Selected accounts expose pressed/current state.
- Connection, scan, background, policy and developer-test status surfaces use polite atomic live announcements where appropriate. Large result feeds are not one giant assertive announcement.
- Detection-layer ticks expose text alternatives for fired, clean, incomplete and unavailable states; hover titles are supplementary only.
- Diagnostic and Safe-review tables have captions and scoped column headers.
- High-visibility focus, higher-contrast secondary text, reduced-motion behavior, forced-color borders and a single-column narrow layout are defined.
- The dashboard uses local system fonts. It makes no third-party font request and the local CSP permits only self-hosted fonts/styles.
- User/provider data continues to render through text nodes or explicit escaping; account labels no longer enter an HTML template.

## Localization boundary

`web/i18n.js` owns a strict message catalog, locale registration, regional fallback, safe interpolation and `Intl.DateTimeFormat`/`Intl.NumberFormat` helpers. English remains the complete source fallback so a partial translation cannot create empty controls. Locale state is memory-only; it does not enter browser storage or mailbox/global data.

The initial dashboard, onboarding controls and safety guide carry stable message keys. Dynamic date formatting in background protection, scan history and developer results uses the shared locale helper. More locale catalogs can be registered without changing detection, provider or persistence code.

This establishes localization readiness; it does not claim professional translation or linguistic review for locales not yet shipped.

## Deterministic safety education

The visible guide teaches four non-negotiable boundaries:

1. Safe applies only to successfully inspected content; Unknown/partial is incomplete and must never be treated as Safe.
2. Urgent requests are a reason to slow down. Users should not reply, call message-supplied numbers, pay or share passwords, one-time codes, recovery codes or seed phrases.
3. Report Scam, Block, Trash and Analyze Links are distinct actions. Reporting shares privacy-reduced indicators and does not move mail; link analysis is explicit and credential-free.
4. When doubt remains, use a known official site/app/number, ask a trusted person or leave the message untouched.

The guide makes no guarantee of complete protection and does not weaken the deterministic verdict contract.

## Manual acceptance still required

- keyboard-only completion of onboarding, scan, policy management, review actions, background controls and disconnect;
- screen-reader review of landmarks, account selection, live scan progress, message evidence/actions and errors;
- 200% and 400% zoom plus narrow viewport without clipped/overlapping controls;
- forced-color/high-contrast and reduced-motion review on supported desktop platforms;
- professional translation and linguistic QA before any non-English catalog is released.
