import { readFileSync, writeFileSync } from "node:fs";

function replaceExactly(source, before, after, label) {
  const first = source.indexOf(before);
  if (first < 0) throw new Error(`Missing approved patch anchor: ${label}`);
  if (source.indexOf(before, first + before.length) >= 0) {
    throw new Error(`Approved patch anchor is not unique: ${label}`);
  }
  return source.slice(0, first) + after + source.slice(first + before.length);
}

const monitorPath = "web/scan-monitor.js";
let monitor = readFileSync(monitorPath, "utf8");

monitor = replaceExactly(
  monitor,
  "  let source = null;\n  let accountId = null;\n  let scanOwnerSnapshot = null;\n  let receivedServerEvent = false;",
  "  let source = null;\n  let accountId = null;\n  let activeScanId = null;\n  let scanOwnerSnapshot = null;\n  let receivedServerEvent = false;",
  "scan monitor live ownership state",
);

monitor = replaceExactly(
  monitor,
  "    source = null;\n    accountId = null;\n    scanOwnerSnapshot = null;\n    return true;",
  "    source = null;\n    accountId = null;\n    activeScanId = null;\n    scanOwnerSnapshot = null;\n    return true;",
  "scan monitor finish ownership reset",
);

monitor = replaceExactly(
  monitor,
  "  window.addEventListener('email-shield-account-selection-changed', (event) => {\n    clearScanPresentation();\n    const detail = event instanceof CustomEvent ? event.detail : null;\n    if (source && accountId && accountId !== detail?.accountId) {\n      setStatus('A scan is still running for another connected mailbox. Stop it or let it finish before starting the selected mailbox.', 'running');\n      stopButton.disabled = false;\n      return;\n    }\n    setStatus(detail?.accountId\n      ? 'Selected account changed. Scan controls are ready.'\n      : 'Select a connected account to scan.');\n  });",
  "  window.addEventListener('email-shield-account-selection-changed', (event) => {\n    clearScanPresentation();\n    const detail = event instanceof CustomEvent ? event.detail : null;\n    if (source && accountId && accountId !== detail?.accountId) {\n      setStatus('A scan is still running for another connected mailbox. Stop it or let it finish before starting the selected mailbox.', 'running');\n      stopButton.disabled = false;\n      return;\n    }\n    setStatus(detail?.accountId\n      ? 'Selected account changed. Scan controls are ready.'\n      : 'Select a connected account to scan.');\n  });\n\n  // A live EventSource remains the scan-presentation owner across mailbox\n  // navigation. Rebind its generation only after the protected server workspace\n  // confirms that the same mailbox selection has settled. This preserves stale\n  // account protection while allowing A -> B -> A to resume live rendering.\n  window.addEventListener('email-shield-account-selection-settled', (event) => {\n    const detail = event instanceof CustomEvent ? event.detail : null;\n    if (!source || !accountId || detail?.accountId !== accountId) return;\n    const current = selectionSnapshot();\n    if (current.id === accountId) scanOwnerSnapshot = current;\n  });",
  "scan monitor settled selection rebind",
);

monitor = replaceExactly(
  monitor,
  "    const presentationIsCurrent = () => source === es && selectionMatches(requestedSelection);",
  "    const presentationIsCurrent = () => source === es && selectionMatches(scanOwnerSnapshot);",
  "scan monitor current presentation owner",
);

monitor = replaceExactly(
  monitor,
  "    es.addEventListener('scan-started', (event) => {\n      receivedServerEvent = true;\n      if (presentationIsCurrent()) {\n        let value = { resumed: Boolean(resumeScanId), counters: null };\n        try { value = JSON.parse(event.data); } catch {}\n        if (value.resumed === true && value.counters) {",
  "    es.addEventListener('scan-started', (event) => {\n      receivedServerEvent = true;\n      let value = { resumed: Boolean(resumeScanId), counters: null, scanId: null };\n      try { value = JSON.parse(event.data); } catch {}\n      if (typeof value.scanId === 'string' && value.scanId) activeScanId = value.scanId;\n      if (presentationIsCurrent()) {\n        if (value.resumed === true && value.counters) {",
  "scan monitor authoritative scan id",
);

monitor = replaceExactly(
  monitor,
  "  Object.defineProperty(window, 'emailShieldStartScan', {\n    value: (type, options = {}) => start(type, options), writable: false, configurable: false, enumerable: false,\n  });",
  "  Object.defineProperty(window, 'emailShieldScanMonitorOwnership', {\n    value: Object.freeze({\n      ownsLiveScan(candidateAccountId, candidateScanId = null) {\n        if (!source || !accountId || candidateAccountId !== accountId) return false;\n        if (typeof candidateScanId !== 'string' || !candidateScanId || !activeScanId) return true;\n        return candidateScanId === activeScanId;\n      },\n    }),\n    writable: false, configurable: false, enumerable: false,\n  });\n\n  Object.defineProperty(window, 'emailShieldStartScan', {\n    value: (type, options = {}) => start(type, options), writable: false, configurable: false, enumerable: false,\n  });",
  "scan monitor read-only ownership contract",
);

writeFileSync(monitorPath, monitor);

const reattachPath = "web/scan-live-reattach.js";
let reattach = readFileSync(reattachPath, "utf8");

reattach = replaceExactly(
  reattach,
  "  function presentationMatches(workspace) {\n    return Boolean(\n      adopted\n      && workspace?.selectedAccountId === adopted.accountId\n      && workspace?.presentation?.scanId === adopted.scanId,\n    );\n  }",
  "  function presentationMatches(workspace) {\n    return Boolean(\n      adopted\n      && workspace?.selectedAccountId === adopted.accountId\n      && workspace?.presentation?.scanId === adopted.scanId,\n    );\n  }\n\n  function liveMonitorOwns(workspace) {\n    const ownership = window.emailShieldScanMonitorOwnership;\n    return Boolean(\n      ownership?.ownsLiveScan?.(\n        workspace?.selectedAccountId ?? null,\n        workspace?.presentation?.scanId ?? null,\n      ),\n    );\n  }\n\n  function relinquishAdoptionToLiveMonitor() {\n    if (!adopted) return;\n    cancelPoll();\n    adopted = null;\n    stopInFlight = false;\n    // Do not change controls or presentation here. The live scan monitor already\n    // owns them; changing them would race the EventSource we are yielding to.\n  }",
  "reattach live monitor ownership helper",
);

reattach = replaceExactly(
  reattach,
  "  function adopt(workspace) {\n    const presentation = workspace?.presentation;\n    if (!presentation || presentation.status !== 'running') return;\n    if (typeof workspace.selectedAccountId !== 'string' || !workspace.selectedAccountId) return;\n    if (typeof presentation.scanId !== 'string' || !presentation.scanId) return;\n\n    if (adopted?.accountId === workspace.selectedAccountId && adopted?.scanId === presentation.scanId) {",
  "  function adopt(workspace) {\n    const presentation = workspace?.presentation;\n    if (!presentation || presentation.status !== 'running') return;\n    if (typeof workspace.selectedAccountId !== 'string' || !workspace.selectedAccountId) return;\n    if (typeof presentation.scanId !== 'string' || !presentation.scanId) return;\n\n    // Reattach is a detached-document recovery owner only. Never replay the\n    // server workspace over a scan that this document is already receiving via\n    // scan-monitor's live EventSource; doing so duplicates cards/action tokens.\n    if (liveMonitorOwns(workspace)) {\n      relinquishAdoptionToLiveMonitor();\n      return;\n    }\n\n    if (adopted?.accountId === workspace.selectedAccountId && adopted?.scanId === presentation.scanId) {",
  "reattach adoption ownership gate",
);

writeFileSync(reattachPath, reattach);
console.log("Applied approved live-scan ownership fix.");
