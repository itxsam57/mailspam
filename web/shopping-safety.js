(() => {
  const installedModules = window.emailShieldInstalledModules ||= new Set();
  if (installedModules.has('shopping-safety')) return;
  installedModules.add('shopping-safety');

  const tools = document.querySelector('#consumerSafetyToolsPanel .consumer-two');
  if (!tools) return;

  const card = document.createElement('div');
  card.className = 'consumer-card';
  card.id = 'consumerShoppingSafety';

  const heading = document.createElement('h3');
  heading.textContent = 'Shopping Safety';
  const intro = document.createElement('p');
  intro.textContent = 'Check an unfamiliar storefront using only the URL and details you explicitly provide. Email Shield does not inspect browser history, orders, cookies or saved payment data.';

  const urlLabel = document.createElement('label');
  urlLabel.className = 'field';
  const urlTitle = document.createElement('span');
  urlTitle.textContent = 'Storefront URL';
  const urlInput = document.createElement('input');
  urlInput.id = 'consumerShoppingUrl';
  urlInput.className = 'consumer-input';
  urlInput.type = 'url';
  urlInput.placeholder = 'https://store.example';
  urlInput.autocomplete = 'off';
  urlLabel.append(urlTitle, urlInput);

  const sellerLabel = document.createElement('label');
  sellerLabel.className = 'field';
  const sellerTitle = document.createElement('span');
  sellerTitle.textContent = 'Seller name (optional)';
  const sellerInput = document.createElement('input');
  sellerInput.id = 'consumerShoppingSeller';
  sellerInput.className = 'consumer-input';
  sellerInput.maxLength = 512;
  sellerInput.autocomplete = 'off';
  sellerLabel.append(sellerTitle, sellerInput);

  const priceLabel = document.createElement('label');
  priceLabel.className = 'field';
  const priceTitle = document.createElement('span');
  priceTitle.textContent = 'Advertised price (optional)';
  const priceInput = document.createElement('input');
  priceInput.id = 'consumerShoppingPrice';
  priceInput.className = 'consumer-input';
  priceInput.maxLength = 1024;
  priceInput.autocomplete = 'off';
  priceLabel.append(priceTitle, priceInput);

  const paymentLabel = document.createElement('label');
  paymentLabel.className = 'field';
  const paymentTitle = document.createElement('span');
  paymentTitle.textContent = 'Payment instructions (optional)';
  const paymentInput = document.createElement('textarea');
  paymentInput.id = 'consumerShoppingPayment';
  paymentInput.className = 'consumer-input';
  paymentInput.rows = 3;
  paymentInput.maxLength = 8000;
  paymentInput.placeholder = 'Paste only the payment instructions you want checked';
  paymentLabel.append(paymentTitle, paymentInput);

  const pageLabel = document.createElement('label');
  pageLabel.className = 'field';
  const pageTitle = document.createElement('span');
  pageTitle.textContent = 'Storefront text (optional)';
  const pageInput = document.createElement('textarea');
  pageInput.id = 'consumerShoppingPageText';
  pageInput.className = 'consumer-input';
  pageInput.rows = 4;
  pageInput.maxLength = 32000;
  pageInput.placeholder = 'Paste suspicious seller/contact/offer text';
  pageLabel.append(pageTitle, pageInput);

  const actions = document.createElement('div');
  actions.className = 'consumer-actions';
  const check = document.createElement('button');
  check.id = 'consumerCheckShopping';
  check.type = 'button';
  check.textContent = 'Check purchase';
  actions.append(check);

  const output = document.createElement('div');
  output.id = 'consumerShoppingResult';
  output.className = 'hint';
  output.setAttribute('role', 'status');
  output.setAttribute('aria-live', 'polite');

  card.append(heading, intro, urlLabel, sellerLabel, priceLabel, paymentLabel, pageLabel, actions, output);
  tools.append(card);

  function verdictLabel(verdict) {
    if (verdict === 'high_risk') return 'HIGH RISK';
    if (verdict === 'caution') return 'CAUTION';
    if (verdict === 'unknown') return 'UNKNOWN';
    return 'NO STRONG SIGNAL';
  }

  check.addEventListener('click', async () => {
    output.textContent = 'Checking the explicitly supplied storefront details…';
    check.disabled = true;
    try {
      const response = await fetch('/api/consumer/v1/shopping/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          schemaVersion: 1,
          url: urlInput.value,
          sellerName: sellerInput.value,
          advertisedPriceText: priceInput.value,
          paymentText: paymentInput.value,
          pageText: pageInput.value,
        }),
      });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(result.error || `Shopping Safety failed (${response.status}).`);
      const signals = Array.isArray(result.signals)
        ? result.signals.map((signal) => String(signal?.detail || '')).filter(Boolean).slice(0, 6)
        : [];
      const limitation = Array.isArray(result.limitations) && result.limitations.length
        ? String(result.limitations[0])
        : 'A check cannot prove an unfamiliar seller is legitimate.';
      output.textContent = `${verdictLabel(result.verdict)}: ${signals.length ? signals.join(' ') : limitation}`;
    } catch (error) {
      output.textContent = error instanceof Error ? error.message : String(error);
    } finally {
      check.disabled = false;
    }
  });
})();
