(() => {
  const installedModules = window.emailShieldInstalledModules ||= new Set();
  if (installedModules.has('ui-router')) return;
  installedModules.add('ui-router');

  const ROUTES = Object.freeze(['home', 'scan', 'protection', 'family', 'community', 'history', 'account', 'settings']);
  const routeSet = new Set(ROUTES);
  const main = document.getElementById('mainContent');
  const sidebar = document.querySelector('.app-sidebar');
  const nav = document.querySelector('.app-nav');
  const mobileNav = document.querySelector('.mobile-bottom-nav');
  const backdrop = document.querySelector('.mobile-more-backdrop');
  if (!(main instanceof HTMLElement) || !(nav instanceof HTMLElement)) return;

  function routeSection(route) {
    if (!routeSet.has(route)) return null;
    return main.querySelector(`.app-route[data-route="${route}"]`);
  }

  function routeStack(route) {
    const section = routeSection(route);
    if (!(section instanceof HTMLElement)) return null;
    return section.querySelector('.shell-panel-stack') || section;
  }

  function normalizeRouteContract() {
    for (const button of nav.querySelectorAll('[data-route-target]')) {
      const route = button.dataset.routeTarget;
      if (routeSet.has(route)) button.dataset.route = route;
    }
    for (const section of main.querySelectorAll('.app-route[data-route]')) {
      const route = section.dataset.route;
      if (routeSet.has(route)) section.dataset.appRoute = route;
    }
  }

  function mountDeclaredPanels() {
    for (const panel of main.querySelectorAll('[data-app-route]')) {
      if (!(panel instanceof HTMLElement) || panel.classList.contains('app-route')) continue;
      const route = panel.dataset.appRoute;
      const stack = routeStack(route);
      if (stack && panel.parentElement !== stack) stack.append(panel);
    }
  }

  function closeMobileMenu() {
    sidebar?.classList.remove('mobile-open');
    backdrop?.classList.remove('open');
  }

  function navigate(route, options = {}) {
    if (!routeSet.has(route)) return false;
    const target = routeSection(route);
    if (!(target instanceof HTMLElement)) return false;

    for (const section of main.querySelectorAll('.app-route[data-route]')) {
      section.hidden = section !== target;
    }
    for (const button of nav.querySelectorAll('[data-route-target]')) {
      if (button.dataset.routeTarget === route) button.setAttribute('aria-current', 'page');
      else button.removeAttribute('aria-current');
    }
    if (mobileNav) {
      for (const button of mobileNav.querySelectorAll('[data-mobile-route]')) {
        if (button.dataset.mobileRoute === route) button.setAttribute('aria-current', 'page');
        else if (button.dataset.mobileRoute !== 'more') button.removeAttribute('aria-current');
      }
    }

    closeMobileMenu();
    if (options.focus !== false) {
      const heading = target.querySelector('.app-route-title h2');
      if (heading instanceof HTMLElement) {
        heading.tabIndex = -1;
        heading.focus({ preventScroll: true });
      }
      target.scrollIntoView({ block: 'start' });
    }
    if (options.updateHash !== false && location.hash !== `#${route}`) {
      history.replaceState(null, '', `#${route}`);
    }
    window.dispatchEvent(new CustomEvent('email-shield-route-changed', { detail: { route } }));
    return true;
  }

  normalizeRouteContract();
  mountDeclaredPanels();

  const requestedInitialRoute = location.hash.startsWith('#') ? location.hash.slice(1) : '';
  const initialRoute = routeSet.has(requestedInitialRoute)
    ? requestedInitialRoute
    : nav.querySelector('[data-route-target][aria-current="page"]')?.dataset.routeTarget || 'home';
  navigate(initialRoute, { focus: false, updateHash: false });

  const router = Object.freeze({
    routes: ROUTES,
    navigate,
    mountDeclaredPanels,
    routeSection,
    routeStack,
  });
  Object.defineProperty(window, 'emailShieldRouter', {
    value: router,
    writable: false,
    configurable: false,
  });
  Object.defineProperty(window, 'emailShieldNavigate', {
    value: navigate,
    writable: false,
    configurable: false,
  });

  nav.addEventListener('click', (event) => {
    const target = event.target instanceof Element ? event.target.closest('[data-route-target]') : null;
    if (!(target instanceof HTMLButtonElement) || !nav.contains(target)) return;
    const route = target.dataset.routeTarget;
    if (!routeSet.has(route)) return;
    event.preventDefault();
    event.stopPropagation();
    navigate(route);
  }, true);

  mobileNav?.addEventListener('click', (event) => {
    const target = event.target instanceof Element ? event.target.closest('[data-mobile-route]') : null;
    if (!(target instanceof HTMLButtonElement) || !mobileNav.contains(target)) return;
    const route = target.dataset.mobileRoute;
    if (route === 'more') return;
    if (!routeSet.has(route)) return;
    event.preventDefault();
    event.stopPropagation();
    navigate(route);
  }, true);

  window.addEventListener('hashchange', () => {
    const route = location.hash.startsWith('#') ? location.hash.slice(1) : '';
    if (routeSet.has(route)) navigate(route, { updateHash: false });
  });

  let mountScheduled = false;
  const observer = new MutationObserver(() => {
    if (mountScheduled) return;
    mountScheduled = true;
    queueMicrotask(() => {
      mountScheduled = false;
      normalizeRouteContract();
      mountDeclaredPanels();
    });
  });
  observer.observe(main, { childList: true, subtree: true });
})();