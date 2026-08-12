(() => {
  const installedModules = window.emailShieldInstalledModules ||= new Set();
  if (installedModules.has('app-shell')) return;
  installedModules.add('app-shell');

  const main = document.getElementById('mainContent');
  if (!main) return;

  const style = document.createElement('style');
  style.textContent = `
    body.email-shield-shell{padding-left:218px}.email-shield-shell header{margin-left:0}
    .app-sidebar{position:fixed;inset:0 auto 0 0;width:218px;background:#0b0e13;border-right:1px solid var(--border);z-index:80;display:flex;flex-direction:column;padding:18px 12px;box-sizing:border-box}
    .app-sidebar-brand{display:flex;align-items:center;gap:10px;padding:4px 8px 18px;border-bottom:1px solid var(--border);margin-bottom:12px}.app-sidebar-brand strong{font-size:14px}.app-sidebar-brand span{display:block;font-size:10px;color:var(--text-faint);margin-top:2px}
    .app-nav{display:flex;flex-direction:column;gap:4px;overflow:auto}.app-nav button{display:flex;align-items:center;gap:10px;width:100%;text-align:left;background:transparent;border:1px solid transparent;color:var(--text-muted);padding:9px 10px;border-radius:7px}.app-nav button:hover,.app-nav button:focus-visible{background:var(--panel-raised);color:var(--text)}.app-nav button[aria-current="page"]{background:#222a36;color:var(--text);border-color:#323b49}.app-nav-icon{width:18px;text-align:center;font-weight:700}.app-sidebar-foot{margin-top:auto;padding:12px 8px 0;border-top:1px solid var(--border);font-size:10px;color:var(--text-faint);line-height:1.45}
    .app-route[hidden]{display:none!important}.app-route{max-width:1180px;margin:0 auto}.app-route-title{display:flex;justify-content:space-between;align-items:flex-end;gap:12px;margin:4px 0 12px}.app-route-title h2{font-size:18px;margin:0}.app-route-title p{margin:0;color:var(--text-faint);font-size:11px}
    .home-hero{display:grid;grid-template-columns:minmax(0,1.5fr) minmax(260px,.8fr);gap:12px}.home-protection-card{padding:20px;border:1px solid var(--border);border-radius:10px;background:linear-gradient(145deg,#171d27,#12161d)}.home-protection-state{display:flex;align-items:center;gap:9px;font-size:12px;color:var(--safe);margin-bottom:10px}.home-protection-dot{width:10px;height:10px;border-radius:50%;background:var(--safe);box-shadow:0 0 0 4px rgba(63,184,138,.1)}.home-protection-card h2{font-size:24px;margin:0 0 6px}.home-protection-card p{color:var(--text-muted);font-size:12px;line-height:1.55;max-width:640px}.home-actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:16px}.home-summary-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.home-stat{border:1px solid var(--border);border-radius:9px;background:var(--panel-raised);padding:14px}.home-stat span{display:block;font-size:10px;color:var(--text-faint);text-transform:uppercase;letter-spacing:.05em}.home-stat strong{display:block;font-size:17px;margin-top:6px}.home-notice{margin-top:12px;padding:12px;border:1px solid var(--border);border-radius:8px;color:var(--text-muted);font-size:11px;line-height:1.5}
    .shell-panel-stack{display:flex;flex-direction:column;gap:14px}.shell-panel-stack>.panel{margin:0}.shell-protection-background{border:1px solid var(--border);background:var(--panel);border-radius:9px;padding:16px}.shell-protection-background #backgroundProtection{margin:0!important;border:0!important;padding:0!important}
    .mobile-bottom-nav{display:none}.mobile-more-backdrop{display:none}
    @media(max-width:900px){body.email-shield-shell{padding-left:0;padding-bottom:72px}.app-sidebar{transform:translateX(-105%);transition:transform .18s ease;width:min(82vw,280px);box-shadow:12px 0 30px rgba(0,0,0,.35)}.app-sidebar.mobile-open{transform:translateX(0)}.mobile-more-backdrop{position:fixed;inset:0;background:rgba(0,0,0,.52);z-index:70}.mobile-more-backdrop.open{display:block}.mobile-bottom-nav{position:fixed;display:grid;grid-template-columns:repeat(5,1fr);left:0;right:0;bottom:0;z-index:90;background:#0b0e13;border-top:1px solid var(--border);padding:max(5px,env(safe-area-inset-bottom)) 5px 6px}.mobile-bottom-nav button{border:0;background:transparent;color:var(--text-faint);font-size:10px;padding:7px 3px;display:flex;flex-direction:column;gap:2px;align-items:center}.mobile-bottom-nav button span:first-child{font-size:16px}.mobile-bottom-nav button[aria-current="page"]{color:var(--text)}.home-hero{grid-template-columns:1fr}header{position:relative;z-index:1}.email-shield-shell main{padding-bottom:16px}}
    @media(max-width:580px){.home-summary-grid{grid-template-columns:1fr}.app-route-title{align-items:flex-start;flex-direction:column}}
  `;
  document.head.appendChild(style);
  document.body.classList.add('email-shield-shell');

  const originalPanels = [...main.children].filter((node) => node instanceof HTMLElement && node.tagName === 'SECTION');
  const connectPanel = originalPanels.find((panel) => panel.querySelector('#connectHeading')) || null;
  const scanPanel = document.getElementById('scanPanel');
  const safetyPanel = document.getElementById('safetyEducation');
  const operationsPanel = document.getElementById('operationsPanel');
  const devPanel = document.getElementById('devPanel');
  const policyPanel = document.getElementById('policyManagementPanel');
  const historyPanel = document.getElementById('scanHistoryPanel');
  const familyPanel = document.getElementById('familyShieldPanel');
  const accountPanel = document.getElementById('accountPlanPanel');
  const background = document.getElementById('backgroundProtection');

  main.replaceChildren();

  const routes = [
    ['home', 'Home', 'Overview and protection status', '⌂'],
    ['scan', 'Scan', 'Run and review mailbox scans', '⌕'],
    ['protection', 'Protection', 'Personal rules and automatic protection', '◆'],
    ['family', 'Family Shield', 'Private family threat sharing', '◎'],
    ['community', 'Community', 'Privacy-safe network and operations', '◉'],
    ['history', 'History', 'Scan history and resumable work', '↺'],
    ['account', 'Account & Plan', 'Identity, devices and subscription', '●'],
    ['settings', 'Mailboxes & Settings', 'Connections, safety and diagnostics', '⚙'],
  ];
  const routeContainers = new Map();
  for (const [id, title, description] of routes) {
    const route = document.createElement('section');
    route.className = 'app-route';
    route.dataset.route = id;
    route.hidden = id !== 'home';
    const heading = document.createElement('div');
    heading.className = 'app-route-title';
    const h = document.createElement('h2');
    h.textContent = title;
    const p = document.createElement('p');
    p.textContent = description;
    heading.append(h, p);
    const stack = document.createElement('div');
    stack.className = 'shell-panel-stack';
    route.append(heading, stack);
    main.append(route);
    routeContainers.set(id, stack);
  }

  const home = document.createElement('section');
  home.className = 'panel home-panel';
  home.id = 'homePanel';
  home.innerHTML = `
    <div class="home-hero">
      <div class="home-protection-card">
        <div class="home-protection-state"><span class="home-protection-dot"></span><span id="homeProtectionState">Protection ready</span></div>
        <h2>Email Shield</h2>
        <p>Your mail stays with your providers. Email Shield scans locally, applies your personal and family protection rules, and shares only privacy-reduced threat intelligence when you explicitly report scams.</p>
        <div class="home-actions"><button id="homeScanNow" class="primary" type="button">Scan now</button><button id="homeFamily" type="button">Family Shield</button></div>
      </div>
      <div class="home-summary-grid">
        <div class="home-stat"><span>Mailbox</span><strong id="homeMailbox">None selected</strong></div>
        <div class="home-stat"><span>Plan</span><strong id="homePlan">Free</strong></div>
        <div class="home-stat"><span>Family</span><strong id="homeFamilyState">Not joined</strong></div>
        <div class="home-stat"><span>Last scan</span><strong id="homeLastScan">—</strong></div>
      </div>
    </div>
    <div class="home-notice">Security decisions remain layered: personal rules → private Family Shield → signed community warnings → globally confirmed threats. Family signals never become global consensus by themselves.</div>`;
  routeContainers.get('home').append(home);

  if (scanPanel) routeContainers.get('scan').append(scanPanel);
  if (background) {
    const protectionBackground = document.createElement('section');
    protectionBackground.className = 'shell-protection-background';
    protectionBackground.append(background);
    routeContainers.get('protection').append(protectionBackground);
  }
  if (policyPanel) routeContainers.get('protection').append(policyPanel);
  if (familyPanel) routeContainers.get('family').append(familyPanel);
  if (operationsPanel) routeContainers.get('community').append(operationsPanel);
  if (historyPanel) routeContainers.get('history').append(historyPanel);
  if (accountPanel) routeContainers.get('account').append(accountPanel);
  if (connectPanel) routeContainers.get('settings').append(connectPanel);
  if (safetyPanel) routeContainers.get('settings').append(safetyPanel);
  if (devPanel) routeContainers.get('settings').append(devPanel);

  const sidebar = document.createElement('aside');
  sidebar.className = 'app-sidebar';
  sidebar.setAttribute('aria-label', 'Email Shield features');
  const sideBrand = document.createElement('div');
  sideBrand.className = 'app-sidebar-brand';
  sideBrand.innerHTML = '<div class="brand-mark" aria-hidden="true">ES</div><div><strong>Email Shield</strong><span>Privacy-first protection</span></div>';
  const nav = document.createElement('nav');
  nav.className = 'app-nav';
  const navButtons = new Map();
  for (const [id, title, , icon] of routes) {
    const button = document.createElement('button');
    button.type = 'button';
    button.dataset.routeTarget = id;
    button.innerHTML = `<span class="app-nav-icon" aria-hidden="true">${icon}</span><span>${title}</span>`;
    if (id === 'home') button.setAttribute('aria-current', 'page');
    nav.append(button);
    navButtons.set(id, button);
  }
  const foot = document.createElement('div');
  foot.className = 'app-sidebar-foot';
  foot.textContent = 'Mail content stays local. Account and Family Shield state contain no raw email bodies.';
  sidebar.append(sideBrand, nav, foot);
  document.body.prepend(sidebar);

  const backdrop = document.createElement('div');
  backdrop.className = 'mobile-more-backdrop';
  document.body.append(backdrop);
  const bottom = document.createElement('nav');
  bottom.className = 'mobile-bottom-nav';
  bottom.setAttribute('aria-label', 'Mobile Email Shield navigation');
  const mobileItems = [
    ['home', '⌂', 'Home'], ['scan', '⌕', 'Scan'], ['family', '◎', 'Family'], ['history', '↺', 'Activity'], ['more', '☰', 'More'],
  ];
  for (const [id, icon, title] of mobileItems) {
    const button = document.createElement('button');
    button.type = 'button';
    button.dataset.mobileRoute = id;
    button.innerHTML = `<span aria-hidden="true">${icon}</span><span>${title}</span>`;
    if (id === 'home') button.setAttribute('aria-current', 'page');
    bottom.append(button);
  }
  document.body.append(bottom);

  let currentRoute = 'home';
  function closeMobileMenu() {
    sidebar.classList.remove('mobile-open');
    backdrop.classList.remove('open');
  }

  function showRoute(id, options = {}) {
    if (!routeContainers.has(id)) return;
    currentRoute = id;
    for (const route of main.querySelectorAll('.app-route')) route.hidden = route.dataset.route !== id;
    for (const [routeId, button] of navButtons) {
      if (routeId === id) button.setAttribute('aria-current', 'page');
      else button.removeAttribute('aria-current');
    }
    for (const button of bottom.querySelectorAll('[data-mobile-route]')) {
      if (button.dataset.mobileRoute === id) button.setAttribute('aria-current', 'page');
      else button.removeAttribute('aria-current');
    }
    closeMobileMenu();
    if (options.focus !== false) main.querySelector(`.app-route[data-route="${CSS.escape(id)}"] .app-route-title h2`)?.focus?.();
    if (location.hash !== `#${id}`) history.replaceState(null, '', `#${id}`);
    window.dispatchEvent(new CustomEvent('email-shield-route-changed', { detail: { route: id } }));
  }

  nav.addEventListener('click', (event) => {
    const button = event.target.closest('[data-route-target]');
    if (button) showRoute(button.dataset.routeTarget);
  });
  bottom.addEventListener('click', (event) => {
    const button = event.target.closest('[data-mobile-route]');
    if (!button) return;
    if (button.dataset.mobileRoute === 'more') {
      sidebar.classList.toggle('mobile-open');
      backdrop.classList.toggle('open', sidebar.classList.contains('mobile-open'));
      return;
    }
    showRoute(button.dataset.mobileRoute);
  });
  backdrop.addEventListener('click', closeMobileMenu);

  document.getElementById('homeScanNow')?.addEventListener('click', () => showRoute('scan'));
  document.getElementById('homeFamily')?.addEventListener('click', () => showRoute('family'));

  const homeMailbox = document.getElementById('homeMailbox');
  const homePlan = document.getElementById('homePlan');
  const homeFamilyState = document.getElementById('homeFamilyState');
  const homeLastScan = document.getElementById('homeLastScan');
  const homeProtectionState = document.getElementById('homeProtectionState');

  function updateMailboxSummary() {
    const selected = document.querySelector('#accountsList .account-chip.active');
    const text = selected?.querySelector('span')?.textContent?.trim() || 'None selected';
    homeMailbox.textContent = text.length > 30 ? `${text.slice(0, 27)}…` : text;
    homeProtectionState.textContent = selected ? 'Protection ready for selected mailbox' : 'Connect or select a mailbox';
  }

  async function updateProfileSummary() {
    try {
      const response = await fetch('/api/profile/v1/snapshot', { cache: 'no-store' });
      const data = await response.json();
      if (!response.ok || !data.signedIn) {
        homePlan.textContent = 'Free';
        homeFamilyState.textContent = 'Not joined';
        return;
      }
      homePlan.textContent = String(data.account.entitlement.plan || 'free').replace(/^./, (letter) => letter.toUpperCase());
      homeFamilyState.textContent = data.family ? `${data.family.seatsUsed}/${data.family.seatLimit || '—'} protected` : 'Not joined';
    } catch {}
  }

  async function updateHistorySummary() {
    const id = document.querySelector('#accountsList .account-chip.active')?.dataset.id;
    if (!id) { homeLastScan.textContent = '—'; return; }
    try {
      const response = await fetch(`/api/accounts/${encodeURIComponent(id)}/scan-history`, { cache: 'no-store' });
      const data = await response.json();
      const last = Array.isArray(data.history) ? data.history[0] : null;
      homeLastScan.textContent = last ? `${String(last.type || 'scan')} · ${String(last.status || '')}` : 'None yet';
    } catch { homeLastScan.textContent = 'Unavailable'; }
  }

  const accountsList = document.getElementById('accountsList');
  if (accountsList) new MutationObserver(() => { updateMailboxSummary(); void updateHistorySummary(); }).observe(accountsList, { childList: true, subtree: true, attributes: true });
  window.addEventListener('email-shield-profile-changed', updateProfileSummary);
  window.addEventListener('email-shield-family-changed', updateProfileSummary);
  window.addEventListener('email-shield-mailbox-profile-linked', updateProfileSummary);
  window.addEventListener('hashchange', () => {
    const id = location.hash.replace(/^#/, '');
    if (routeContainers.has(id)) showRoute(id, { focus: false });
  });

  updateMailboxSummary();
  void updateProfileSummary();
  void updateHistorySummary();
  const initial = location.hash.replace(/^#/, '');
  if (routeContainers.has(initial)) showRoute(initial, { focus: false });

  Object.defineProperty(window, 'emailShieldNavigate', {
    value: (route) => showRoute(route),
    writable: false,
    configurable: false,
  });
})();
