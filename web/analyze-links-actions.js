(() => {
  const installedModules = window.emailShieldInstalledModules ||= new Set();
  if (installedModules.has('analyze-links-actions')) return;
  installedModules.add('analyze-links-actions');

  const originalRenderCard = window.renderCard;
  if (typeof originalRenderCard !== 'function') return;

  const style = document.createElement('style');
  style.textContent = `
    .card.destination-high-risk{border-left-color:var(--high-risk)!important}
    .destination-analysis-status{display:block;margin-top:7px;font-size:11px;line-height:1.45;color:var(--text-muted)}
    .destination-analysis-status.high-risk{color:var(--high-risk)}
    .destination-analysis-status.error{color:#ff9a9f}
    .destination-analysis-status.complete{color:var(--safe)}
  `;
  document.head.appendChild(style);

  function escapeAttribute(value) {
    return String(value ?? '').replace(/[&<>"']/g, (character) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    })[character]);
  }

  function selectionSnapshot() {
    const owner = window.emailShieldAccountSelection;
    if (owner?.capture) return owner.capture();
    return Object.freeze({ id: document.querySelector('.account-chip.active')?.dataset.id || null, generation: null });
  }

  function selectionMatches(snapshot) {
    const owner = window.emailShieldAccountSelection;
    if (owner?.matches && snapshot?.generation !== null) return owner.matches(snapshot);
    return snapshot?.id === (document.querySelector('.account-chip.active')?.dataset.id || null);
  }

  function analysisStatus(card) {
    let status = card?.querySelector('.destination-analysis-status');
    if (status) return status;
    status = document.createElement('span');
    status.className = 'destination-analysis-status';
    status.setAttribute('role', 'status');
    card?.appendChild(status);
    return status;
  }

  window.renderCard = function renderCardWithAnalyzeLinks(result) {
    const html = originalRenderCard(result);
    const action = result?.reviewAction;
    if (action?.canAnalyzeLinks !== true || !action.token) return html;

    const template = document.createElement('template');
    template.innerHTML = String(html).trim();
    const card = template.content.firstElementChild;
    const actions = card?.querySelector('.card-actions');
    if (!card || !actions) return html;

    const button = document.createElement('button');
    button.type = 'button';
    button.dataset.action = 'analyze-links';
    button.dataset.reviewToken = escapeAttribute(action.token);
    button.textContent = 'Analyze Links';
    actions.appendChild(button);
    return card.outerHTML;
  };

  function classificationSummary(results) {
    const counts = new Map();
    for (const item of results) {
      const classification = typeof item?.classification === 'string' ? item.classification : 'error';
      counts.set(classification, (counts.get(classification) ?? 0) + 1);
    }
    return [...counts.entries()]
      .map(([classification, count]) => `${count} ${classification.replaceAll('_', ' ')}`)
      .join(', ');
  }

  document.addEventListener('click', async (event) => {
    const button = event.target instanceof Element ? event.target.closest('[data-action="analyze-links"]') : null;
    if (!(button instanceof HTMLButtonElement) || button.disabled) return;
    event.preventDefault();
    event.stopImmediatePropagation();

    const ownerSnapshot = selectionSnapshot();
    const accountId = ownerSnapshot.id;
    const token = button.dataset.reviewToken;
    const card = button.closest('.card');
    const status = analysisStatus(card);
    if (!accountId || !token) {
      status.textContent = 'Analyze Links failed: the selected mailbox or scanned-message capability is missing.';
      status.className = 'destination-analysis-status error';
      return;
    }

    const confirmed = window.confirm(
      'Analyze the destinations in this scanned message now?\n\nEmail Shield will make bounded network requests only to the canonical links captured during the scan. It does not send mailbox cookies, provider credentials, message bodies, contacts, or OAuth tokens. Redirects and DNS addresses are revalidated against private/reserved networks.',
    );
    if (!confirmed) return;
    if (!selectionMatches(ownerSnapshot)) {
      window.alert('The selected mailbox changed. No destination analysis was started.');
      return;
    }

    const previousText = button.textContent;
    button.disabled = true;
    button.textContent = 'Analyzing…';
    status.textContent = 'Analyzing canonical message destinations through the bounded DNS-pinned network checker…';
    status.className = 'destination-analysis-status';

    try {
      const response = await fetch(`/api/accounts/${encodeURIComponent(accountId)}/messages/analyze-links`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token }),
      });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(result.error || `Server returned HTTP ${response.status}`);
      if (!selectionMatches(ownerSnapshot)) return;
      if (result.accountId !== accountId || result.token !== token || !Array.isArray(result.results)) {
        throw new Error('The server did not confirm the scanned-message Analyze Links capability.');
      }

      const summary = classificationSummary(result.results);
      const untrusted = result.results.filter((item) => item?.classification === 'error').length;
      const dangerous = result.results.filter((item) => item?.classification === 'credential_trap' || item?.classification === 'malware').length;
      const analyzed = Number(result.analyzedDestinations ?? result.results.length);

      if (result.escalatedToHighRisk === true || dangerous > 0) {
        card?.classList.add('destination-high-risk');
        status.className = 'destination-analysis-status high-risk';
        status.textContent = `Analyze Links raised this message to High Risk: ${dangerous} dangerous destination(s) were detected across ${analyzed} analyzed link(s). ${summary}. Do not open the links or enter credentials.`;
      } else if (untrusted > 0) {
        status.className = 'destination-analysis-status error';
        status.textContent = `Analyze Links could not establish a trusted result for ${untrusted} of ${analyzed} destination(s): ${summary}. Uninspectable destinations are not treated as safe.`;
      } else {
        status.className = 'destination-analysis-status complete';
        status.textContent = `Analyze Links completed for ${analyzed} destination(s): ${summary}. No destination warning was found in this bounded check; this is not a guarantee that a site or message is safe.`;
      }
    } catch (error) {
      if (!selectionMatches(ownerSnapshot)) return;
      status.className = 'destination-analysis-status error';
      status.textContent = `Analyze Links failed safely: ${error instanceof Error ? error.message : String(error)} No destination was treated as safe.`;
    } finally {
      if (selectionMatches(ownerSnapshot)) {
        button.disabled = false;
        button.textContent = previousText || 'Analyze Links';
      }
    }
  }, true);
})();
