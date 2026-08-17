import { readFileSync, writeFileSync } from "node:fs";

function replaceExact(text, from, to, label, expectedCount = 1) {
  const count = text.split(from).length - 1;
  if (count !== expectedCount) {
    throw new Error(`${label}: expected ${expectedCount} occurrence(s), found ${count}`);
  }
  return text.split(from).join(to);
}

function edit(path, transform) {
  const before = readFileSync(path, "utf8");
  const after = transform(before);
  if (after === before) throw new Error(`${path}: guarded transform made no change`);
  writeFileSync(path, after);
}

edit("web/index.html", (source) => replaceExact(
  source,
  `    row.className = \`account-chip\${selected ? ' active' : ''}\`;\n    row.dataset.id = String(account.accountId || '');\n    row.setAttribute('role', 'listitem');`,
  `    row.className = \`account-chip\${selected ? ' active' : ''}\`;\n    row.dataset.id = String(account.accountId || '');\n    const rawReachability = account.reachability?.state;\n    const reachability = rawReachability === 'checking'\n      || rawReachability === 'reachable'\n      || rawReachability === 'unavailable'\n      ? rawReachability\n      : 'unknown';\n    row.dataset.reachability = reachability;\n    row.setAttribute('role', 'listitem');`,
  "account chip sanitized reachability handoff",
));

edit("web/app-shell.js", (source) => {
  let next = source;
  next = replaceExact(
    next,
    `.home-protection-state{display:flex;align-items:center;gap:9px;font-size:12px;color:var(--safe);margin-bottom:10px}.home-protection-dot{width:10px;height:10px;border-radius:50%;background:var(--safe);box-shadow:0 0 0 4px rgba(63,184,138,.1)}`,
    `.home-protection-state{display:flex;align-items:center;gap:9px;font-size:12px;color:var(--text-muted);margin-bottom:10px}.home-protection-dot{width:10px;height:10px;border-radius:50%;background:var(--unknown);box-shadow:0 0 0 4px rgba(108,118,132,.1)}.home-protection-state[data-reachability="reachable"]{color:var(--safe)}.home-protection-state[data-reachability="reachable"] .home-protection-dot{background:var(--safe);box-shadow:0 0 0 4px rgba(63,184,138,.1)}.home-protection-state[data-reachability="unavailable"]{color:var(--review)}.home-protection-state[data-reachability="unavailable"] .home-protection-dot{background:var(--review);box-shadow:0 0 0 4px rgba(232,178,61,.1)}.home-protection-state[data-reachability="checking"]{color:var(--text-muted)}.home-protection-state[data-reachability="unknown"]{color:var(--text-muted)}.home-protection-state[data-reachability="none"]{color:var(--text-muted)}`,
    "Home reachability state styling",
  );
  next = replaceExact(
    next,
    `<div class="home-protection-state"><span class="home-protection-dot"></span><span id="homeProtectionState">Protection ready</span></div>`,
    `<div class="home-protection-state" data-reachability="none"><span class="home-protection-dot"></span><span id="homeProtectionState">Connect or select a mailbox</span></div>`,
    "Home initial fail-closed state",
  );
  next = replaceExact(
    next,
    `  const homeProtectionState = document.getElementById('homeProtectionState');\n\n  function updateMailboxSummary() {\n    const selected = document.querySelector('#accountsList .account-chip.active');\n    const text = selected?.querySelector('span')?.textContent?.trim() || 'None selected';\n    homeMailbox.textContent = text.length > 30 ? \`\${text.slice(0, 27)}…\` : text;\n    homeProtectionState.textContent = selected ? 'Protection ready for selected mailbox' : 'Connect or select a mailbox';\n  }`,
    `  const homeProtectionState = document.getElementById('homeProtectionState');\n  const homeProtectionIndicator = homeProtectionState?.closest('.home-protection-state');\n\n  function updateMailboxSummary() {\n    const selected = document.querySelector('#accountsList .account-chip.active');\n    const text = selected?.querySelector('span')?.textContent?.trim() || 'None selected';\n    homeMailbox.textContent = text.length > 30 ? \`\${text.slice(0, 27)}…\` : text;\n    const reachability = selected?.dataset.reachability || 'unknown';\n    if (!selected) {\n      homeProtectionState.textContent = 'Connect or select a mailbox';\n      if (homeProtectionIndicator) homeProtectionIndicator.dataset.reachability = 'none';\n      return;\n    }\n    homeProtectionState.textContent = reachability === 'reachable'\n      ? 'Mailbox connection verified'\n      : reachability === 'checking'\n        ? 'Checking mailbox connection'\n        : reachability === 'unavailable'\n          ? 'Mailbox connection needs attention'\n          : 'Mailbox status unavailable';\n    if (homeProtectionIndicator) homeProtectionIndicator.dataset.reachability = reachability;\n  }`,
    "Home fail-closed mailbox summary",
  );
  if (next.includes("Protection ready for selected mailbox")) {
    throw new Error("Home still infers protection readiness from account selection");
  }
  return next;
});

edit("scripts/engineering/smoke-onboarding-handoff.mjs", (source) => {
  let next = replaceExact(
    source,
    `      EMAIL_SHIELD_ENABLE_DEVELOPMENT_ENTITLEMENTS: "0",`,
    `      EMAIL_SHIELD_ENABLE_DEVELOPMENT_ENTITLEMENTS: "1",`,
    "browser fixture entitlement",
  );

  next = replaceExact(
    next,
    `  assert(result.sensitivityComplete === false, \`Sensitivity was incorrectly credited without a connected mailbox: \${JSON.stringify(result)}\`);\n\n  console.log(\`Executable onboarding handoff smoke passed with \${browserExecutable}.\`);\n  console.log("No-mailbox sensitivity action routed to provider setup, surfaced guidance/provider focus, preserved Outlook postponement, and granted no false completion.");`,
    `  assert(result.sensitivityComplete === false, \`Sensitivity was incorrectly credited without a connected mailbox: \${JSON.stringify(result)}\`);\n\n  const connectionStarted = await evaluate(client, \`(() => {\n    const provider = document.getElementById('providerSelect');\n    const mode = document.getElementById('modeSelect');\n    const connect = document.getElementById('connectBtn');\n    if (!provider || !mode || !connect) return false;\n    provider.value = 'gmail';\n    provider.dispatchEvent(new Event('change', { bubbles: true }));\n    mode.value = 'fixture';\n    mode.dispatchEvent(new Event('change', { bubbles: true }));\n    connect.click();\n    return true;\n  })()\`);\n  assert(connectionStarted === true, "Onboarding smoke could not start the fixture mailbox connection.");\n\n  const statusDeadline = Date.now() + 15_000;\n  let mailboxStatus = null;\n  while (Date.now() < statusDeadline) {\n    try {\n      mailboxStatus = await evaluate(client, \`(() => {\n        const selected = document.querySelector('#accountsList .account-chip.active');\n        const status = document.getElementById('homeProtectionState');\n        const indicator = status?.closest('.home-protection-state');\n        if (!selected || !status || !indicator) return null;\n        window.emailShieldNavigate?.('home', { focus: false });\n        return {\n          rowReachability: selected.dataset.reachability || null,\n          text: status.textContent?.trim() || '',\n          indicatorReachability: indicator.dataset.reachability || null,\n        };\n      })()\`);\n      if (mailboxStatus?.rowReachability && mailboxStatus?.text) break;\n    } catch {}\n    await sleep(100);\n  }\n\n  const expectedStatusText = {\n    checking: 'Checking mailbox connection',\n    reachable: 'Mailbox connection verified',\n    unavailable: 'Mailbox connection needs attention',\n    unknown: 'Mailbox status unavailable',\n  };\n  assert(mailboxStatus && Object.hasOwn(expectedStatusText, mailboxStatus.rowReachability), \`Connected mailbox exposed no sanitized reachability state: \${JSON.stringify(mailboxStatus)}\`);\n  assert(mailboxStatus.text === expectedStatusText[mailboxStatus.rowReachability], \`Home did not render the selected mailbox reachability truthfully: \${JSON.stringify(mailboxStatus)}\`);\n  assert(mailboxStatus.indicatorReachability === mailboxStatus.rowReachability, \`Home indicator did not follow the canonical selected mailbox reachability: \${JSON.stringify(mailboxStatus)}\`);\n  assert(!/protection ready/i.test(mailboxStatus.text), \`Home inferred protection from mailbox selection: \${JSON.stringify(mailboxStatus)}\`);\n\n  console.log(\`Executable onboarding handoff smoke passed with \${browserExecutable}.\`);\n  console.log("No-mailbox sensitivity action routed to provider setup, surfaced guidance/provider focus, preserved Outlook postponement, and granted no false completion.");\n  console.log("Connected fixture mailbox retained explicit sanitized reachability state and Home rendered fail-closed status instead of inferring protection from selection.");`,
    "permanent Chromium fail-closed Home acceptance",
  );
  return next;
});

console.log("EMA-34 Task 6 guarded fail-closed Home transform applied.");
