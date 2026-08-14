(() => {
  const installedModules = window.emailShieldInstalledModules ||= new Set();
  if (installedModules.has('developer-controls')) return;
  installedModules.add('developer-controls');

  const button = document.getElementById('devSuiteBtn');
  const panel = document.getElementById('devPanel');
  const results = document.getElementById('devResults');
  if (!(button instanceof HTMLButtonElement) || !(panel instanceof HTMLElement) || !(results instanceof HTMLElement)) return;

  // Developer execution is opt-in twice: the browser must explicitly request
  // developer UI and the protected profile snapshot must confirm that this
  // desktop process was started with development entitlements enabled.
  button.hidden = true;
  panel.style.display = 'none';
  const developerUiRequested = new URLSearchParams(window.location.search).get('developer') === '1';

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
    if (button.hidden || button.disabled) return;

    panel.style.display = 'block';
    button.disabled = true;
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
      results.className = 'fail';
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
      if (response.ok && profile.developmentEntitlementsEnabled === true) button.hidden = false;
    } catch {
      // Fail closed: developer controls stay hidden if entitlement proof cannot be read.
    }
  })();
})();