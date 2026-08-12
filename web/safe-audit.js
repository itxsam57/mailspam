(() => {
  const installedModules = window.emailShieldInstalledModules ||= new Set();
  if (installedModules.has('safe-audit')) return;
  installedModules.add('safe-audit');

  function installSafeAudit() {
    const diagnostics = document.getElementById('scanDiagnosticAudit');
    const diagnosticBody = diagnostics?.querySelector('tbody');
    if (!diagnostics || !diagnosticBody) return false;
    if (document.getElementById('safeMessageAudit')) return true;

    const style = document.createElement('style');
    style.textContent = `
      .safe-message-audit summary {color:#3fb88a;font-weight:600}
      .safe-message-audit .safe-empty {padding:10px 12px;color:var(--text-faint);font-size:11px;border-top:1px solid #2a2f3a}
      .safe-message-audit .safe-actions-cell {min-width:300px}
    `;
    document.head.appendChild(style);

    const safeAudit = document.createElement('details');
    safeAudit.id = 'safeMessageAudit';
    safeAudit.className = 'scan-diagnostics safe-message-audit';
    safeAudit.innerHTML = `
      <summary>Safe messages (0) — click to review</summary>
      <div class="scan-diagnostics-note">Safe messages remain outside the warning-card feed. You can correct a false Safe result by reporting the campaign to Email Shield's privacy-reduced community shield, move only this message to provider Spam/Junk, trust a sender, or unsubscribe when supported.</div>
      <div class="safe-empty">No messages have been classified Safe in this scan yet.</div>
      <div class="scan-diagnostics-scroll" hidden><table>
        <caption class="visually-hidden">Safe-message review and correction actions</caption>
        <thead><tr><th scope="col">Subject</th><th scope="col">Sender</th><th scope="col">Parse</th><th scope="col">Evidence / notes</th><th scope="col">Actions</th></tr></thead>
        <tbody></tbody>
      </table></div>`;
    diagnostics.before(safeAudit);

    const summary = safeAudit.querySelector('summary');
    const safeBody = safeAudit.querySelector('tbody');
    const scroll = safeAudit.querySelector('.scan-diagnostics-scroll');
    const empty = safeAudit.querySelector('.safe-empty');
    const status = document.getElementById('scanMonitorStatus');

    function escapeHtml(value) {
      return String(value ?? '').replace(/[&<>"']/g, (character) => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
      })[character]);
    }

    function unsubscribeLabel(method, done) {
      if (done && method === 'one_click_post') return 'Unsubscribed ✓';
      if (method === 'link_only') return 'Open unsubscribe page';
      if (method === 'mailto') return 'Email unsubscribe request';
      return 'Unsubscribe';
    }

    function syncSafeRows() {
      const sourceRows = [...diagnosticBody.querySelectorAll('tr')]
        .filter((row) => row.children[0]?.textContent?.trim().toLowerCase() === 'safe');

      summary.textContent = `Safe messages (${sourceRows.length}) — click to review`;
      safeBody.innerHTML = sourceRows.map((row) => {
        const cells = row.querySelectorAll('td');
        const subject = cells[2]?.innerHTML ?? '(no subject)';
        const sender = cells[3]?.innerHTML ?? 'unknown';
        const senderText = cells[3]?.textContent?.trim() ?? '';
        const parse = cells[4]?.innerHTML ?? 'unknown';
        const notes = cells[5]?.innerHTML ?? 'No scored evidence.';
        const reviewToken = row.dataset.reviewToken || '';
        const senderTrusted = row.dataset.senderTrusted === 'true';
        const canMoveToSpam = row.dataset.canReportSpam === 'true';
        const unsubscribeAvailable = row.dataset.unsubscribeAvailable === 'true';
        const unsubscribeMethod = row.dataset.unsubscribeMethod || 'none';
        const unsubscribeDone = row.dataset.unsubscribeDone === 'true';

        const actions = [];
        if (reviewToken) {
          actions.push(`<button data-action="report-scam" data-review-token="${escapeHtml(reviewToken)}" data-sender="${escapeHtml(senderText)}">Report Scam to Email Shield</button>`);
        }
        if (reviewToken && canMoveToSpam) {
          actions.push(`<button data-action="move-spam" data-review-token="${escapeHtml(reviewToken)}">Move to Spam/Junk</button>`);
        }
        if (reviewToken && senderText && senderText !== 'unknown') {
          actions.push(senderTrusted
            ? '<button disabled>Sender trusted ✓</button>'
            : `<button data-action="trust-sender" data-review-token="${escapeHtml(reviewToken)}" data-sender="${escapeHtml(senderText)}">Trust sender</button>`);
        }
        if (unsubscribeAvailable && row.dataset.unsubscribeToken && row.dataset.unsubscribeKey) {
          actions.push(`<button data-action="unsubscribe"
            data-unsubscribe-token="${escapeHtml(row.dataset.unsubscribeToken)}"
            data-unsubscribe-key="${escapeHtml(row.dataset.unsubscribeKey)}"
            data-unsubscribe-method="${escapeHtml(unsubscribeMethod)}"
            ${unsubscribeDone && unsubscribeMethod === 'one_click_post' ? 'disabled' : ''}>${unsubscribeLabel(unsubscribeMethod, unsubscribeDone)}</button>`);
        }
        if (!actions.length) actions.push('<span class="hint">No user action available</span>');

        return `<tr data-message-row="true" data-review-token="${escapeHtml(reviewToken)}">
          <td class="safe-subject">${subject}</td>
          <td class="safe-sender">${sender}</td>
          <td>${parse}</td>
          <td>${notes}</td>
          <td class="safe-actions-cell"><div class="safe-row-actions">${actions.join('')}</div><span class="review-action-status" data-action-status role="status"></span></td>
        </tr>`;
      }).join('');

      const hasSafe = sourceRows.length > 0;
      scroll.hidden = !hasSafe;
      empty.hidden = hasSafe;
      if (hasSafe && status?.classList.contains('complete')) safeAudit.open = true;
    }

    new MutationObserver(syncSafeRows).observe(diagnosticBody, { childList: true, subtree: true });
    if (status) {
      new MutationObserver(syncSafeRows).observe(status, {
        childList: true,
        characterData: true,
        subtree: true,
        attributes: true,
        attributeFilter: ['class'],
      });
    }
    syncSafeRows();
    return true;
  }

  if (installSafeAudit()) return;
  const observer = new MutationObserver(() => {
    if (installSafeAudit()) observer.disconnect();
  });
  observer.observe(document.documentElement, { childList: true, subtree: true });
})();
