(() => {
  const installedModules = window.emailShieldInstalledModules ||= new Set();
  if (installedModules.has('scam-check')) return;
  installedModules.add('scam-check');

  const scanStack = document.querySelector('.app-route[data-route="scan"] .shell-panel-stack');
  if (!scanStack) return;

  const style = document.createElement('style');
  style.textContent = `
    .scam-check-panel{order:-10}.scam-check-intro{display:flex;justify-content:space-between;gap:14px;align-items:flex-start}.scam-check-intro h3{margin:0 0 5px;font-size:16px}.scam-check-intro p{margin:0;color:var(--text-muted);font-size:11px;line-height:1.5;max-width:720px}.scam-check-local{font-size:10px;color:var(--safe);white-space:nowrap}
    .scam-check-tabs{display:flex;gap:6px;flex-wrap:wrap;margin:14px 0 10px}.scam-check-tabs button[aria-pressed="true"]{background:#222a36;border-color:#3a4658;color:var(--text)}
    .scam-check-field{display:flex;flex-direction:column;gap:6px}.scam-check-field label{font-size:10px;color:var(--text-faint);text-transform:uppercase;letter-spacing:.04em}.scam-check-field textarea{min-height:150px;resize:vertical}.scam-check-field textarea,.scam-check-field input[type="url"],.scam-check-field input[type="file"]{width:100%;box-sizing:border-box}.scam-check-field[hidden]{display:none!important}
    .scam-check-actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:10px}.scam-check-status{font-size:11px;color:var(--text-muted)}.scam-check-status.error{color:var(--danger)}
    .scam-check-result{margin-top:14px;border:1px solid var(--border);border-radius:9px;background:var(--panel-raised);padding:14px}.scam-check-result[hidden]{display:none!important}.scam-check-result-head{display:flex;justify-content:space-between;gap:10px;align-items:flex-start}.scam-check-result h4{margin:0;font-size:16px}.scam-check-badge{font-size:10px;text-transform:uppercase;letter-spacing:.04em;padding:4px 7px;border-radius:999px;border:1px solid var(--border)}.scam-check-result p{font-size:11px;color:var(--text-muted);line-height:1.55}.scam-check-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.scam-check-list h5{font-size:10px;text-transform:uppercase;color:var(--text-faint);letter-spacing:.04em;margin:0 0 7px}.scam-check-list ul{margin:0;padding-left:18px}.scam-check-list li{font-size:11px;color:var(--text-muted);line-height:1.5;margin:4px 0}.scam-check-note{margin-top:10px;font-size:10px;color:var(--text-faint);line-height:1.5}.scam-check-destination{margin-top:12px;padding:10px;border:1px solid var(--border);border-radius:7px}.scam-check-destination strong{display:block;font-size:11px;color:var(--text);margin-bottom:4px}.scam-check-destination span{display:block;font-size:10px;color:var(--text-muted);line-height:1.5}
    @media(max-width:700px){.scam-check-intro,.scam-check-result-head{flex-direction:column}.scam-check-grid{grid-template-columns:1fr}.scam-check-local{white-space:normal}}
  `;
  document.head.append(style);

  const panel = document.createElement('section');
  panel.className = 'panel scam-check-panel';
  panel.id = 'scamCheckPanel';
  panel.innerHTML = `
    <div class="scam-check-intro">
      <div><h3>Check something suspicious</h3><p>Paste a message or link, or choose an email/image file. Email Shield analyzes it through the same local protection engine used for connected mailboxes.</p></div>
      <span class="scam-check-local">● Local-first analysis</span>
    </div>
    <div class="scam-check-tabs" role="group" aria-label="Scam Check input type">
      <button type="button" data-scam-check-mode="message" aria-pressed="true">Message</button>
      <button type="button" data-scam-check-mode="url" aria-pressed="false">Link</button>
      <button type="button" data-scam-check-mode="file" aria-pressed="false">Email / image file</button>
    </div>
    <div class="scam-check-field" data-scam-check-field="message">
      <label for="scamCheckText">Suspicious message</label>
      <textarea id="scamCheckText" maxlength="524288" placeholder="Paste the suspicious email, SMS, chat message or other text here."></textarea>
    </div>
    <div class="scam-check-field" data-scam-check-field="url" hidden>
      <label for="scamCheckUrl">Suspicious link</label>
      <input id="scamCheckUrl" type="url" maxlength="8192" placeholder="https://example.com/...">
    </div>
    <div class="scam-check-field" data-scam-check-field="file" hidden>
      <label for="scamCheckFile">Email (.eml) or image (PNG/JPEG)</label>
      <input id="scamCheckFile" type="file" accept=".eml,message/rfc822,image/png,image/jpeg">
    </div>
    <div class="scam-check-actions">
      <button id="scamCheckRun" class="primary" type="button">Check now</button>
      <button id="scamCheckClear" type="button">Clear</button>
      <span id="scamCheckStatus" class="scam-check-status" role="status" aria-live="polite">Nothing is sent to a remote AI service.</span>
    </div>
    <div id="scamCheckResult" class="scam-check-result" hidden aria-live="polite"></div>
  `;
  scanStack.prepend(panel);

  const modeButtons = [...panel.querySelectorAll('[data-scam-check-mode]')];
  const fields = [...panel.querySelectorAll('[data-scam-check-field]')];
  const text = panel.querySelector('#scamCheckText');
  const url = panel.querySelector('#scamCheckUrl');
  const file = panel.querySelector('#scamCheckFile');
  const run = panel.querySelector('#scamCheckRun');
  const clear = panel.querySelector('#scamCheckClear');
  const status = panel.querySelector('#scamCheckStatus');
  const result = panel.querySelector('#scamCheckResult');
  let mode = 'message';

  function setMode(next) {
    mode = next;
    for (const button of modeButtons) button.setAttribute('aria-pressed', String(button.dataset.scamCheckMode === next));
    for (const field of fields) field.hidden = field.dataset.scamCheckField !== next;
    result.hidden = true;
    status.textContent = next === 'file'
      ? 'Images are checked locally for QR codes. Visible image text requires a supported local OCR bridge.'
      : next === 'url'
        ? 'The link is checked locally first, then the destination is fetched only because you explicitly asked to inspect it. Nothing is sent to a remote AI service.'
        : 'Nothing is sent to a remote AI service.';
    status.className = 'scam-check-status';
  }

  function appendList(container, heading, values) {
    const section = document.createElement('div');
    section.className = 'scam-check-list';
    const h = document.createElement('h5');
    h.textContent = heading;
    section.append(h);
    const list = document.createElement('ul');
    for (const value of values) {
      const li = document.createElement('li');
      li.textContent = value;
      list.append(li);
    }
    if (!values.length) {
      const li = document.createElement('li');
      li.textContent = 'None reported.';
      list.append(li);
    }
    section.append(list);
    container.append(section);
  }

  function destinationPresentation(data) {
    const destinationAnalysis = data?.destinationAnalysis;
    const inspected = Array.isArray(destinationAnalysis?.results) ? destinationAnalysis.results[0] : null;
    if (!inspected) return null;

    if (inspected.classification === 'benign') {
      return {
        heading: 'Destination inspected',
        detail: 'No credential trap or malware was found in the inspected destination content. This does not prove the site or message is safe.',
      };
    }
    if (inspected.classification === 'credential_trap') {
      return { heading: 'Credential trap detected', detail: 'The inspected destination contains a password-entry pattern. Do not enter credentials there.' };
    }
    if (inspected.classification === 'malware') {
      return { heading: 'Malware destination detected', detail: inspected.detail || 'The inspected destination matched a deterministic malware-behavior signature.' };
    }
    if (inspected.classification === 'blocked_unsafe_target') {
      return { heading: 'Destination blocked before connection', detail: inspected.detail || 'The destination was blocked by local network-safety policy before any connection was made.' };
    }
    if (inspected.classification === 'error') {
      return { heading: 'Destination inspection unavailable', detail: inspected.detail || 'The destination could not be inspected safely and was not treated as benign.' };
    }

    const labels = {
      adult_dating: 'Adult or dating destination signal detected',
      fake_support: 'Fake-support destination signal detected',
      crypto_payment: 'Crypto-payment destination signal detected',
      notification_trap: 'Notification-trap destination signal detected',
    };
    return {
      heading: labels[inspected.classification] || 'Destination risk signal detected',
      detail: inspected.detail || `Destination classification: ${String(inspected.classification || 'unknown').replaceAll('_', ' ')}.`,
    };
  }

  function showResult(data) {
    result.replaceChildren();
    const head = document.createElement('div');
    head.className = 'scam-check-result-head';
    const title = document.createElement('h4');
    title.textContent = data?.explanation?.headline || 'Analysis complete';
    const badge = document.createElement('span');
    badge.className = 'scam-check-badge';
    badge.textContent = String(data?.verdict || 'unknown').replaceAll('_', ' ');
    head.append(title, badge);
    result.append(head);

    const summary = document.createElement('p');
    summary.textContent = data?.explanation?.summary || 'Email Shield could not produce a detailed explanation.';
    result.append(summary);

    const grid = document.createElement('div');
    grid.className = 'scam-check-grid';
    appendList(grid, 'Why', Array.isArray(data?.explanation?.strongestSignals)
      ? data.explanation.strongestSignals.map((item) => item.description).filter(Boolean)
      : []);
    appendList(grid, 'What to do', Array.isArray(data?.explanation?.safeNextActions) ? data.explanation.safeNextActions : []);
    result.append(grid);

    const destination = destinationPresentation(data);
    if (destination) {
      const destinationBox = document.createElement('div');
      destinationBox.className = 'scam-check-destination';
      const destinationHeading = document.createElement('strong');
      destinationHeading.textContent = destination.heading;
      const destinationDetail = document.createElement('span');
      destinationDetail.textContent = destination.detail;
      destinationBox.append(destinationHeading, destinationDetail);
      result.append(destinationBox);
    }

    const limitations = Array.isArray(data?.explanation?.limitations) ? data.explanation.limitations : [];
    if (limitations.length) {
      const note = document.createElement('div');
      note.className = 'scam-check-note';
      note.textContent = `Limits: ${limitations.join(' ')}`;
      result.append(note);
    }
    result.hidden = false;
  }

  async function analyze() {
    run.disabled = true;
    result.hidden = true;
    status.textContent = mode === 'url' ? 'Checking locally and inspecting the destination…' : 'Checking locally…';
    status.className = 'scam-check-status';
    try {
      let response;
      if (mode === 'message') {
        const value = text.value.trim();
        if (!value) throw new Error('Paste a suspicious message first.');
        response = await fetch('/api/scam-check/v1/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ schemaVersion: 1, kind: 'message', text: value }),
        });
      } else if (mode === 'url') {
        const value = url.value.trim();
        if (!value) throw new Error('Enter a suspicious link first.');
        response = await fetch('/api/scam-check/v1/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ schemaVersion: 1, kind: 'url', url: value }),
        });
      } else {
        const selected = file.files?.[0];
        if (!selected) throw new Error('Choose an .eml, PNG or JPEG file first.');
        const lower = selected.name.toLowerCase();
        const image = selected.type === 'image/png' || selected.type === 'image/jpeg';
        const eml = selected.type === 'message/rfc822' || lower.endsWith('.eml');
        if (!image && !eml) throw new Error('Only .eml, PNG and JPEG files are supported.');
        response = await fetch(image ? '/api/scam-check/v1/image' : '/api/scam-check/v1/eml', {
          method: 'POST',
          headers: {
            'Content-Type': image ? selected.type : 'message/rfc822',
            'X-Email-Shield-File-Name': selected.name.slice(0, 512),
          },
          body: selected,
        });
      }
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || `Scam Check failed with HTTP ${response.status}.`);
      showResult(data);
      status.textContent = mode === 'url' ? 'Local analysis and explicit destination inspection complete.' : 'Local analysis complete.';
    } catch (error) {
      status.textContent = error instanceof Error ? error.message : String(error);
      status.className = 'scam-check-status error';
    } finally {
      run.disabled = false;
    }
  }

  modeButtons.forEach((button) => button.addEventListener('click', () => setMode(button.dataset.scamCheckMode)));
  run.addEventListener('click', analyze);
  clear.addEventListener('click', () => {
    text.value = '';
    url.value = '';
    file.value = '';
    result.hidden = true;
    status.textContent = 'Nothing is sent to a remote AI service.';
    status.className = 'scam-check-status';
  });
})();
