(() => {
  const catalogs = new Map();
  const english = Object.freeze({
    'app.name': 'Email Shield',
    'app.tagline': 'Local, deterministic mailbox protection',
    'nav.skip': 'Skip to main content',
    'developer.run': 'Run Developer Test Suite',
    'connect.heading': 'Connect an account',
    'connect.provider': 'Email provider',
    'connect.mode': 'Connection mode',
    'connect.action': 'Connect',
    'connect.fixture': 'Fixture demo mailbox (no credentials needed)',
    'connect.live': 'Live account (requires provider authorization)',
    'connect.help': 'Fixture mode loads a synthetic scam corpus. Live mode uses provider OAuth or a provider-approved app password.',
    'connect.empty': 'No accounts connected yet.',
    'account.use': 'Use account',
    'scan.heading': 'Scan selected account',
    'scan.quick': 'Quick Scan',
    'scan.full': 'Full Mailbox Audit',
    'scan.spam': 'Spam / Junk Scan',
    'scan.stop': 'Stop Scan',
    'background.heading': 'Background protection',
    'background.interval': 'Check this account every',
    'background.enable': 'Enable',
    'background.paused': 'Background protection is paused.',
    'background.help': 'Runs one resource-bounded Quick Scan at a time. Manual scans take priority; provider actions and Analyze Links never run automatically.',
    'education.heading': 'Safety guide',
    'education.intro': 'Email Shield explains deterministic evidence. It does not replace your provider, promise that every message is safe, or ask for passwords, payment, recovery codes, or seed phrases.',
    'education.verdicts.heading': 'Read the verdict carefully',
    'education.verdicts.body': 'Safe means no meaningful warning was found in content that was successfully inspected. Unknown or partial means inspection was incomplete—retry it; never treat it as Safe. Unknown mail stays in the Diagnostic audit instead of being presented as a threat warning.',
    'education.actions.heading': 'Pause before you act',
    'education.actions.body': 'Do not reply, call a number in the message, pay, or share a password, one-time code, recovery code, or seed phrase. Open the known official provider or organization site yourself.',
    'education.controls.heading': 'Actions are separate',
    'education.controls.body': 'Report Scam shares privacy-reduced indicators; it does not move mail. Block and Trash are account-scoped choices. Analyze Links is explicit and never uses mailbox cookies or provider credentials.',
    'education.help.heading': 'When you still are not sure',
    'education.help.body': 'Contact the organization using a trusted number or app, ask a trusted person, or leave the message untouched. Urgency is a reason to slow down.',
    'developer.heading': 'Developer Testing Suite',
    'operations.heading': 'Privacy-safe operations',
    'operations.refresh': 'Refresh operations',
    'operations.caption': 'Aggregate provider health. No mailbox address, message identity, subject, body, destination, or exception text is collected.',
    'operations.provider': 'Provider',
    'operations.transport': 'Transport',
    'operations.started': 'Scans started',
    'operations.completed': 'Completed',
    'operations.ended': 'Failed / stopped',
    'operations.examined': 'Messages examined',
    'operations.failures': 'Adapter failures',
    'operations.active': 'Active operations',
    'operations.loading': 'Loading aggregate operations…',
    'operations.failed': 'Aggregate operations are unavailable.',
    'operations.invalid': 'The operations response did not match the privacy-safe schema.',
    'operations.feed.verified': 'verified',
    'operations.feed.unavailable': 'unavailable',
    'operations.updated': 'Aggregate operations refreshed {date}.',
    'operations.summary': 'Feed: {feed} ({feedEntries} entries); queued privacy-reduced reports: {pending}; message-level Safe approvals: {falsePositive}; scam reports accepted/failed: {abuseAccepted}/{abuseFailed}; scheduled accounts: {background}.',
    'status.ready': 'Ready',
  });
  catalogs.set('en', english);
  let activeLocale = 'en';

  function normalizedLocale(locale) {
    if (typeof locale !== 'string' || !locale.trim()) return 'en';
    const candidate = locale.trim().replace('_', '-');
    try { return Intl.getCanonicalLocales(candidate)[0] || 'en'; }
    catch { return 'en'; }
  }

  function supportedLocale(locale) {
    const normalized = normalizedLocale(locale);
    if (catalogs.has(normalized)) return normalized;
    const language = normalized.split('-')[0];
    return catalogs.has(language) ? language : 'en';
  }

  function interpolate(template, values = {}) {
    return template.replace(/\{([A-Za-z][A-Za-z0-9]*)\}/g, (_match, name) => (
      Object.hasOwn(values, name) ? String(values[name]) : `{${name}}`
    ));
  }

  function t(key, values) {
    const catalog = catalogs.get(activeLocale) || english;
    const template = catalog[key] || english[key];
    return typeof template === 'string' ? interpolate(template, values) : `[${key}]`;
  }

  function register(locale, catalog) {
    const normalized = normalizedLocale(locale);
    if (!catalog || typeof catalog !== 'object' || Array.isArray(catalog)) throw new Error('A locale catalog object is required.');
    const clean = {};
    for (const [key, value] of Object.entries(catalog)) {
      if (!/^[a-z][a-z0-9]*(?:\.[a-z0-9]+)+$/.test(key) || typeof value !== 'string' || value.length > 2_000) {
        throw new Error('Locale catalog contains an invalid message.');
      }
      clean[key] = value;
    }
    catalogs.set(normalized, Object.freeze(clean));
  }

  function setLocale(locale) {
    activeLocale = supportedLocale(locale);
    document.documentElement.lang = activeLocale;
    apply(document);
    return activeLocale;
  }

  function formatDate(value, options = { dateStyle: 'medium', timeStyle: 'short' }) {
    const date = value instanceof Date ? value : new Date(value);
    if (!Number.isFinite(date.getTime())) return '—';
    return new Intl.DateTimeFormat(activeLocale, options).format(date);
  }

  function formatNumber(value, options) {
    const number = Number(value);
    return Number.isFinite(number) ? new Intl.NumberFormat(activeLocale, options).format(number) : '0';
  }

  function apply(root) {
    root.querySelectorAll('[data-i18n]').forEach((element) => {
      element.textContent = t(element.getAttribute('data-i18n'));
    });
    root.querySelectorAll('[data-i18n-aria-label]').forEach((element) => {
      element.setAttribute('aria-label', t(element.getAttribute('data-i18n-aria-label')));
    });
  }

  const requested = document.documentElement.dataset.locale || navigator.language || 'en';
  activeLocale = supportedLocale(requested);
  document.documentElement.lang = activeLocale;
  const api = Object.freeze({
    t,
    register,
    setLocale,
    formatDate,
    formatNumber,
    apply,
    locale: () => activeLocale,
    availableLocales: () => Object.freeze([...catalogs.keys()]),
  });
  Object.defineProperty(window, 'emailShieldI18n', { value: api, writable: false, configurable: false });
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', () => apply(document), { once: true });
  else apply(document);
})();
