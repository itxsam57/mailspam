(() => {
  const installedModules = window.emailShieldInstalledModules ||= new Set();
  if (installedModules.has('developer-controls')) return;
  installedModules.add('developer-controls');

  const operationsPanel = document.getElementById('operationsPanel');
  if (operationsPanel instanceof HTMLElement) {
    operationsPanel.hidden = true;
    operationsPanel.dataset.emailShieldDeveloperDiagnostic = 'true';
    delete operationsPanel.dataset.emailShieldDeveloperEnabled;
  }

  const button = document.getElementById('devSuiteBtn');
  const panel = document.getElementById('devPanel');
  const results = document.getElementById('devResults');
  if (!(button instanceof HTMLButtonElement) || !(panel instanceof HTMLElement) || !(results instanceof HTMLElement)) return;

  // Developer presentation is opt-in twice: the URL must explicitly request
  // engineering controls and the protected profile snapshot must confirm that
  // this desktop process was started with development entitlements enabled.
  // The server independently enforces the same boundary for execution.
  button.hidden = true;
  panel.style.display = 'none';
  const developerUiRequested = new URLSearchParams(window.location.search).get('developer') === '1';
  let developerUiEnabled = false;

  function fixtureControl(element) {
    if (!(element instanceof HTMLDetailsElement)) return false;
    const summary = element.querySelector(':scope > summary');
    return summary?.textContent?.trim() === 'Developer acceptance controls';
  }

  function secureDynamicDeveloperControls(root = document) {
    const details = [];
    if (fixtureControl(root)) details.push(root);
    if (root instanceof Document || root instanceof DocumentFragment || root instanceof HTMLElement) {
      root.querySelectorAll?.('details').forEach((element) => {
        if (fixtureControl(element)) details.push(element);
      });
    }
    for (const detail of details) {
      detail.dataset.emailShieldDeveloperControl = 'true';
      detail.hidden = !developerUiEnabled;
    }
  }

  // consumer-product.js creates its synthetic-fixture disclosure dynamically.
  // Observe additions before paint and keep every such control fail-closed until
  // the same protected entitlement proof used by this module succeeds.
  const observer = new MutationObserver((records) => {
    for (const record of records) {
      for (const node of record.addedNodes) secureDynamicDeveloperControls(node);
    }
  });
  observer.observe(document.body, { childList: true, subtree: true });
  secureDynamicDeveloperControls();

  function exposeDeveloperUi() {
    developerUiEnabled = true;
    button.hidden = false;
    document.querySelectorAll('[data-email-shield-developer-control="true"]').forEach((element) => {
      if (element instanceof HTMLElement) element.hidden = false;
    });
    if (operationsPanel instanceof HTMLElement) {
      operationsPanel.dataset.emailShieldDeveloperEnabled = 'true';
      operationsPanel.hidden = false;
    }
    window.dispatchEvent(new CustomEvent('email-shield-developer-ui-enabled'));
  }

  function addResultLine(label, value, pass = null) {
    const line = document.createElement('div');
    const prefix = document.createElement('span');
    prefix.textContent = `${label}: `;
    line.append(prefix);
    const output = document.createElement('span');
    output.textContent = String(value);
    if (pass === true) output.className = 'pass';
    else if (pass === false) output.className = 'fail';
    line.append(output);
    results.append(line);
  }

  async function runDeveloperSuite(event) {
    event.preventDefault();
    event.stopImmediatePropagation();
    if (!developerUiEnabled || button.hidden || button.disabled) return;

    panel.style.display = 'block';
    button.disabled = true;
    results.className = 'dev-summary';
    results.textContent = 'Running full corpus across all 5 providers…';
    try {
      const response = await fetch('/api/dev/test-suite');
      const report = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(report.error || 'Developer test suite failed.');
      const parity = Array.isArray(report.crossProviderParityFailures) ? report.crossProviderParityFailures.length : null;
      const falsePositives = Array.isArray(report.falsePositives) ? report.falsePositives.length : null;
      const falseNegatives = Array.isArray(report.falseNegatives) ? report.falseNegatives.length : null;
      if (![report.totalScans, report.maliciousCaught, report.maliciousTotal, report.legitClean, report.legitTotal, parity, falsePositives, falseNegatives]
        .every((value) => Number.isSafeInteger(value) && value >= 0)) {
        throw new Error('Developer test suite returned an invalid report.');
      }

      results.replaceChildren();
      addResultLine('Total scans', `${report.totalScans} (fixtures × 5 providers)`);
      addResultLine('Malicious caught', `${report.maliciousCaught}/${report.maliciousTotal}`, report.maliciousCaught === report.maliciousTotal);
      addResultLine('Legitimate correctly clean', `${report.legitClean}/${report.legitTotal}`, report.legitClean === report.legitTotal);
      addResultLine('Cross-provider parity failures', parity, parity === 0);
      addResultLine('False positives', falsePositives, falsePositives === 0);
      addResultLine('False negatives', falseNegatives, falseNegatives === 0);
      const generated = document.createElement('div');
      generated.className = 'hint';
      generated.style.marginTop = '10px';
      generated.textContent = `Generated ${window.emailShieldI18n?.formatDate(report.generatedAt) || new Date(report.generatedAt).toLocaleString()}`;
      results.append(generated);
    } catch (error) {
      results.textContent = error instanceof Error ? error.message : String(error);
      results.className = 'dev-summary fail';
    } finally {
      button.disabled = false;
    }
  }

  button.addEventListener('click', runDeveloperSuite, true);

  if (!developerUiRequested) return;
  void (async () => {
    try {
      const response = await fetch('/api/profile/v1/snapshot');
      const profile = await response.json().catch(() => ({}));
      if (response.ok && profile.developmentEntitlementsEnabled === true) exposeDeveloperUi();
    } catch {
      // Fail closed: developer controls stay hidden if entitlement proof cannot be read.
    }
  })();
})();