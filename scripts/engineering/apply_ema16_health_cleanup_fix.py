from pathlib import Path


def replace_once(path: str, before: str, after: str) -> None:
    file_path = Path(path)
    source = file_path.read_text(encoding="utf-8")
    count = source.count(before)
    if count != 1:
        raise RuntimeError(f"{path}: expected guarded source block exactly once, found {count}")
    file_path.write_text(source.replace(before, after, 1), encoding="utf-8")


replace_once(
    "web/consumer-product.js",
    '''    const subscriptions = document.getElementById('consumerSubscriptions');
    if (subscriptions) {
      subscriptions.replaceChildren();
      for (const item of (inbox.subscriptions || []).slice(0, 20)) {
        const row = document.createElement('div'); row.className = 'consumer-list-item';
        const info = document.createElement('div'); info.innerHTML = `<strong>${escapeHtml(item.displayName || item.senderDomain || 'Subscription')}</strong><div class="hint">${Number(item.messages || 0)} message(s) · ${item.unsubscribeAvailable ? 'unsubscribe available' : 'no verified unsubscribe control'}</div>`;
        const controls = document.createElement('div');
        const cleanup = document.createElement('button'); cleanup.type = 'button'; cleanup.textContent = 'Clean old mail';
        cleanup.addEventListener('click', async () => {
          if (!stillSelected(accountId)) {
            setHealthStatus('Mailbox selection changed. Run Health again before cleaning mail.', true);
            return;
          }
          if (!confirm(`Move older matching mail from ${item.displayName || item.senderDomain || 'this sender'} to Trash?`)) return;
          const confirmation = prompt('Type MOVE TO TRASH to confirm');
          if (confirmation !== 'MOVE TO TRASH' || !stillSelected(accountId)) return;
          try {
            const cleanupResult = await post(`/api/consumer/v1/accounts/${encodeURIComponent(accountId)}/cleanup`, {
              senderAddress: item.senderAddress,
              senderDomain: item.senderDomain,
              olderThanDays: 30,
              keepNewest: true,
              confirmation,
            });
            if (!stillSelected(accountId)) return;
            setHealthStatus(`${cleanupResult.movedToTrash} message(s) moved to Trash.${cleanupResult.undoAvailable ? ' Undo is available in Activity for 30 minutes.' : ''}`);
            await loadActivity();
          } catch (error) {
            if (stillSelected(accountId)) setHealthStatus(error.message || String(error), true);
          }
        });
        controls.append(cleanup); row.append(info, controls); subscriptions.append(row);
      }
      if (!(inbox.subscriptions || []).length) subscriptions.innerHTML = '<div class="hint">No newsletter/subscription inventory yet. Run Health after connecting a mailbox.</div>';
    }
''',
    '''    const subscriptions = document.getElementById('consumerSubscriptions');
    const cleanupGroups = new Map((inbox.cleanupGroups || []).map((group) => [group.key, group]));
    if (subscriptions) {
      subscriptions.replaceChildren();
      for (const item of (inbox.subscriptions || []).slice(0, 20)) {
        const cleanupGroup = cleanupGroups.get(item.key);
        const messagesOlderThan30Days = Number(cleanupGroup?.messagesOlderThan30Days || 0);
        const row = document.createElement('div'); row.className = 'consumer-list-item';
        const info = document.createElement('div');
        info.innerHTML = `<strong>${escapeHtml(item.displayName || item.senderDomain || 'Subscription')}</strong><div class="hint">${Number(item.messages || 0)} message(s) · ${messagesOlderThan30Days} older than 30 days · ${item.unsubscribeAvailable ? 'unsubscribe available' : 'no verified unsubscribe control'}</div>`;
        const controls = document.createElement('div');
        if (cleanupGroup && messagesOlderThan30Days > 0) {
          const cleanup = document.createElement('button'); cleanup.type = 'button'; cleanup.textContent = 'Clean old mail';
          cleanup.addEventListener('click', async () => {
            if (!stillSelected(accountId)) {
              setHealthStatus('Mailbox selection changed. Run Health again before cleaning mail.', true);
              return;
            }
            if (!confirm(`Move ${messagesOlderThan30Days} matching message(s) older than 30 days from ${item.displayName || item.senderDomain || 'this sender'} to Trash?`)) return;
            const confirmation = prompt('Type MOVE TO TRASH to confirm');
            if (confirmation !== 'MOVE TO TRASH' || !stillSelected(accountId)) return;
            try {
              const cleanupResult = await post(`/api/consumer/v1/accounts/${encodeURIComponent(accountId)}/cleanup`, {
                senderAddress: cleanupGroup.senderAddress,
                senderDomain: cleanupGroup.senderDomain,
                olderThanDays: 30,
                keepNewest: false,
                confirmation,
              });
              if (!stillSelected(accountId)) return;
              setHealthStatus(cleanupResult.movedToTrash > 0
                ? `${cleanupResult.movedToTrash} message(s) moved to Trash.${cleanupResult.undoAvailable ? ' Undo is available in Activity for 30 minutes.' : ''}`
                : 'No matching mail older than 30 days remained to move. Health will refresh now.');
              await runHealth();
              if (stillSelected(accountId)) await loadActivity();
            } catch (error) {
              if (stillSelected(accountId)) setHealthStatus(error.message || String(error), true);
            }
          });
          controls.append(cleanup);
        } else {
          const none = document.createElement('span');
          none.className = 'hint';
          none.textContent = 'No mail older than 30 days';
          controls.append(none);
        }
        row.append(info, controls); subscriptions.append(row);
      }
      if (!(inbox.subscriptions || []).length) subscriptions.innerHTML = '<div class="hint">No newsletter/subscription inventory yet. Run Health after connecting a mailbox.</div>';
    }
''',
)

replace_once(
    "server/src/api/consumerProtectionRoutes.ts",
    '''      const provider = session.config.provider;
      const canUndo = result.providerNativeIds.length > 0 && restoreSupported(provider, session.config.mode === "fixture");
      const activity = defaultConsumerStateRepository.appendActivity(session.policyAccountKey, {
        kind: "cleanup",
        severity: "info",
        provider,
        title: "Mailbox cleanup moved messages to Trash",
        detail: `${result.movedToTrash} matching message(s) were moved to Trash after explicit confirmation.${result.bounded ? " The operation was bounded; additional matching mail may remain." : ""}`,
        reasonCodes: ["BULK_CLEANUP_TO_TRASH"],
        undo: canUndo ? {
          providerNativeIds: result.providerNativeIds,
          expiresAt: Date.now() + UNDO_WINDOW_MS,
          usedAt: null,
        } : null,
      });
''',
    '''      const provider = session.config.provider;
      const changed = result.movedToTrash > 0;
      const canUndo = changed && result.providerNativeIds.length > 0 && restoreSupported(provider, session.config.mode === "fixture");
      const activity = defaultConsumerStateRepository.appendActivity(session.policyAccountKey, {
        kind: "cleanup",
        severity: "info",
        provider,
        title: changed ? "Mailbox cleanup completed" : "Mailbox cleanup made no changes",
        detail: changed
          ? `${result.movedToTrash} matching message(s) were moved to Trash after explicit confirmation.${result.bounded ? " The operation was bounded; additional matching mail may remain." : ""}`
          : `No matching messages remained eligible for the requested cleanup.${result.bounded ? " The bounded Health inventory may not include every mailbox message." : ""}`,
        reasonCodes: [changed ? "BULK_CLEANUP_TO_TRASH" : "BULK_CLEANUP_NO_CHANGE"],
        undo: canUndo ? {
          providerNativeIds: result.providerNativeIds,
          expiresAt: Date.now() + UNDO_WINDOW_MS,
          usedAt: null,
        } : null,
      });
''',
)

replace_once(
    "scripts/engineering/smoke-browser-scan-results.mjs",
    '''  assert(blockState.policyCounts.includes('Blocked senders: 1'), `Personal Policy UI did not refresh the durable block count. State: ${JSON.stringify(blockState)}`);
  assert(runtimeErrors.length === 0, `Consumer scan produced uncaught browser errors: ${JSON.stringify(runtimeErrors)}`);

  console.log(`Executable consumer scan-results smoke passed with ${executable}.`);
''',
    '''  assert(blockState.policyCounts.includes('Blocked senders: 1'), `Personal Policy UI did not refresh the durable block count. State: ${JSON.stringify(blockState)}`);

  await evaluate(client, `(() => {
    window.emailShieldNavigate('protection', { focus: false });
    window.confirm = () => true;
    window.prompt = () => 'MOVE TO TRASH';
    document.getElementById('consumerRunHealth')?.click();
    return true;
  })()`);
  let healthCleanupTarget = null;
  const healthDeadline = Date.now() + 30_000;
  while (Date.now() < healthDeadline) {
    healthCleanupTarget = await evaluate(client, `(() => {
      const rows = [...document.querySelectorAll('#consumerSubscriptions .consumer-list-item')];
      const row = rows.find((candidate) => candidate.querySelector('button')?.textContent?.includes('Clean old mail')) || null;
      if (!row) return null;
      const text = row.textContent || '';
      const match = text.match(/(\\d+) older than 30 days/);
      return { label: row.querySelector('strong')?.textContent || '', oldCount: Number(match?.[1] || 0) };
    })()`);
    if (healthCleanupTarget?.oldCount > 0) break;
    await sleep(100);
  }
  assert(healthCleanupTarget?.oldCount > 0, `Health did not expose an eligible old-mail cleanup group. State: ${JSON.stringify(healthCleanupTarget)}`);
  const healthLabelLiteral = JSON.stringify(healthCleanupTarget.label);
  await evaluate(client, `(() => {
    const row = [...document.querySelectorAll('#consumerSubscriptions .consumer-list-item')]
      .find((candidate) => candidate.querySelector('strong')?.textContent === ${healthLabelLiteral});
    const button = row?.querySelector('button');
    if (!button) throw new Error('Eligible Health cleanup control disappeared before click.');
    button.click();
    return true;
  })()`);
  let healthCleanupState = null;
  const cleanupDeadline = Date.now() + 30_000;
  while (Date.now() < cleanupDeadline) {
    healthCleanupState = await evaluate(client, `(async () => {
      const row = [...document.querySelectorAll('#consumerSubscriptions .consumer-list-item')]
        .find((candidate) => candidate.querySelector('strong')?.textContent === ${healthLabelLiteral}) || null;
      const match = (row?.textContent || '').match(/(\\d+) older than 30 days/);
      const activityResponse = await fetch('/api/consumer/v1/accounts/${accountId}/activity', { cache: 'no-store' });
      const activityBody = await activityResponse.json().catch(() => ({}));
      const cleanupActivity = Array.isArray(activityBody.activity)
        ? activityBody.activity.find((item) => item?.kind === 'cleanup') || null
        : null;
      return {
        oldCount: row ? Number(match?.[1] || 0) : 0,
        activityOk: activityResponse.ok,
        cleanupTitle: cleanupActivity?.title || '',
      };
    })()`);
    if (healthCleanupState?.activityOk && healthCleanupState.cleanupTitle && healthCleanupState.oldCount < healthCleanupTarget.oldCount) break;
    await sleep(100);
  }
  assert(healthCleanupState?.activityOk === true, `Health cleanup Activity could not be read. State: ${JSON.stringify(healthCleanupState)}`);
  assert(healthCleanupState.oldCount < healthCleanupTarget.oldCount, `Health cleanup did not refresh old-mail eligibility after provider mutation. Before: ${JSON.stringify(healthCleanupTarget)} After: ${JSON.stringify(healthCleanupState)}`);
  assert(healthCleanupState.cleanupTitle !== 'Mailbox cleanup moved messages to Trash', `Health cleanup retained the false-success legacy Activity title. State: ${JSON.stringify(healthCleanupState)}`);
  assert(runtimeErrors.length === 0, `Consumer scan produced uncaught browser errors: ${JSON.stringify(runtimeErrors)}`);

  console.log(`Executable consumer scan-results smoke passed with ${executable}.`);
''',
)
replace_once(
    "scripts/engineering/smoke-browser-scan-results.mjs",
    '''  console.log(`Protected Block sender persisted and refreshed Personal Policy for ${blockTarget.address}.`);
''',
    '''  console.log(`Protected Block sender persisted and refreshed Personal Policy for ${blockTarget.address}.`);
  console.log(`Health cleanup reduced old-mail eligibility for ${healthCleanupTarget.label} from ${healthCleanupTarget.oldCount} to ${healthCleanupState.oldCount}.`);
''',
)

print("EMA-16 Health cleanup root repair applied")
