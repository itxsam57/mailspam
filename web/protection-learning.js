(() => {
  const installedModules = window.emailShieldInstalledModules ||= new Set();
  if (installedModules.has('protection-learning')) return;
  installedModules.add('protection-learning');

  const submittedPositiveFeedback = new Set();

  function selectedAccountId() {
    return document.querySelector('.account-chip.active')?.dataset.id || null;
  }

  function cardFor(button) {
    return button.closest('.card') || button.closest('[data-message-row="true"]');
  }

  function reviewToken(button) {
    return button.dataset.reviewToken || cardFor(button)?.dataset.reviewToken || '';
  }

  async function post(accountId, endpoint, body) {
    const response = await fetch(`/api/accounts/${encodeURIComponent(accountId)}/messages/${endpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.error || `Server returned HTTP ${response.status}`);
    return result;
  }

  async function familyAvailable() {
    try {
      const response = await fetch('/api/profile/v1/snapshot', { cache: 'no-store' });
      const result = await response.json().catch(() => ({}));
      return response.ok && result.signedIn === true && Boolean(result.family);
    } catch {
      return false;
    }
  }

  async function chooseFamilyBlockSharing(scope) {
    if (!await familyAvailable()) return false;
    return window.confirm(
      `Also share this blocked campaign with your private Family Shield circle?\n\nChoose OK only when you believe it should protect family members too. Cancel keeps the ${scope} block personal. Email content is never shared.`,
    );
  }

  Object.defineProperty(window, 'emailShieldChooseFamilyBlockSharing', {
    value: chooseFamilyBlockSharing,
    writable: false,
    configurable: false,
    enumerable: false,
  });

  async function submitLegitimateFeedback(accountId, token) {
    const key = `${accountId}:${token}`;
    if (submittedPositiveFeedback.has(key)) return;
    submittedPositiveFeedback.add(key);
    try {
      await post(accountId, 'legitimate-feedback', { token });
    } catch {
      // Community learning is deliberately secondary to the user's durable
      // local Safe/Trust decision. A later fresh action can retry without
      // undoing local policy or exposing raw mailbox content.
      submittedPositiveFeedback.delete(key);
    }
  }

  function observeSuccessfulPositiveAction(button, accountId, token, kind) {
    const expected = kind === 'safe' ? 'Message marked Safe ✓' : 'Sender trusted ✓';
    let closed = false;
    const finish = () => {
      if (closed || button.textContent?.trim() !== expected) return;
      closed = true;
      observer.disconnect();
      clearTimeout(timeout);
      void submitLegitimateFeedback(accountId, token);
    };
    const observer = new MutationObserver(finish);
    observer.observe(button, { childList: true, subtree: true, characterData: true, attributes: true });
    const timeout = setTimeout(() => {
      closed = true;
      observer.disconnect();
    }, 45_000);
    finish();
  }

  // This module is intentionally not an owner of Block or Report Scam. Those
  // durable mutations belong to scan-monitor.js and review-actions.js. This
  // capture observer only attaches secondary positive-learning feedback before
  // the canonical Safe/Trust handler updates the button on success.
  window.addEventListener('click', (event) => {
    const button = event.target instanceof Element
      ? event.target.closest('[data-action="mark-safe"],[data-action="trust-sender"]')
      : null;
    if (!(button instanceof HTMLButtonElement) || button.disabled) return;
    const accountId = selectedAccountId();
    const token = reviewToken(button);
    if (!accountId || !token) return;
    const kind = button.dataset.action === 'mark-safe' ? 'safe' : 'trust';
    observeSuccessfulPositiveAction(button, accountId, token, kind);
  }, true);
})();
