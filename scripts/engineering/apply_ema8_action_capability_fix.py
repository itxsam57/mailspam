from pathlib import Path


def replace_once(path: str, before: str, after: str) -> None:
    file_path = Path(path)
    source = file_path.read_text(encoding="utf-8")
    count = source.count(before)
    if count != 1:
        raise RuntimeError(f"{path}: expected source block exactly once, found {count}")
    file_path.write_text(source.replace(before, after, 1), encoding="utf-8")


session_path = "server/src/api/sessionStore.ts"
replace_once(
    session_path,
    '''  workspaceSnapshot(): { selectedAccountId: string | null; presentation: WorkspaceScanPresentation | null } {
    const selected = this.selectedWorkspaceSessionId && this.getCanonical(this.selectedWorkspaceSessionId)
      ? this.selectedWorkspaceSessionId
      : null;
    if (!selected) this.selectedWorkspaceSessionId = null;
    return {
      selectedAccountId: selected,
      presentation: selected && this.workspacePresentations.has(selected)
        ? structuredClone(this.workspacePresentations.get(selected)!)
        : null,
    };
  }
''',
    '''  private hydrateReviewActionAvailability(session: AccountSession, entry: unknown): unknown {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) return entry;
    const record = entry as Record<string, unknown>;
    const reviewValue = record.reviewAction;
    if (!reviewValue || typeof reviewValue !== "object" || Array.isArray(reviewValue)) return entry;
    const reviewAction = reviewValue as Record<string, unknown>;
    const token = typeof reviewAction.token === "string" ? reviewAction.token : null;
    if (!token) return entry;
    const registered = session.reviewActions.get(token);
    if (!registered) return entry;
    const campaignProtected = session.personalPolicy.isReportedCampaign(
      registered.communityReport.campaignFingerprint,
    );
    return {
      ...record,
      reviewAction: {
        ...reviewAction,
        reportScamAvailable: !campaignProtected && !registered.claimedOperations.has("report_scam"),
      },
    };
  }

  workspaceSnapshot(): { selectedAccountId: string | null; presentation: WorkspaceScanPresentation | null } {
    const selectedSession = this.selectedWorkspaceSessionId
      ? this.getCanonical(this.selectedWorkspaceSessionId)
      : undefined;
    const selected = selectedSession?.id ?? null;
    if (!selected) this.selectedWorkspaceSessionId = null;
    const presentation = selected && this.workspacePresentations.has(selected)
      ? structuredClone(this.workspacePresentations.get(selected)!)
      : null;
    if (selectedSession && presentation) {
      presentation.suspiciousCards = presentation.suspiciousCards.map(
        (entry) => this.hydrateReviewActionAvailability(selectedSession, entry),
      );
      presentation.diagnosticSummaries = presentation.diagnosticSummaries.map(
        (entry) => this.hydrateReviewActionAvailability(selectedSession, entry),
      );
    }
    return { selectedAccountId: selected, presentation };
  }
''',
)
replace_once(
    session_path,
    '''    scamAlreadyReported: boolean;
    communityReported: boolean;
  } {
''',
    '''    scamAlreadyReported: boolean;
    communityReported: boolean;
    reportScamAvailable: boolean;
  } {
''',
)
replace_once(
    session_path,
    '''      scamAlreadyReported: alreadyReported,
      communityReported: alreadyReported,
    };
''',
    '''      scamAlreadyReported: alreadyReported,
      communityReported: alreadyReported,
      reportScamAvailable: !alreadyReported,
    };
''',
)

review_path = "web/review-actions.js"
replace_once(
    review_path,
    '''    const campaignProtected = action.scamAlreadyReported === true;
    const senderBlock = actions.querySelector('[data-action="block-sender"]');
''',
    '''    const campaignProtected = action.scamAlreadyReported === true;
    const campaignDecisionTaken = action.reportScamAvailable === false && !campaignProtected;
    const senderBlock = actions.querySelector('[data-action="block-sender"]');
''',
)
replace_once(
    review_path,
    '''    reportScam.textContent = campaignProtected ? 'Campaign protected locally ✓' : 'Report Scam to Email Shield';
    reportScam.disabled = campaignProtected;
''',
    '''    reportScam.textContent = campaignProtected
      ? 'Campaign protected locally ✓'
      : campaignDecisionTaken
        ? 'Campaign decision already saved ✓'
        : 'Report Scam to Email Shield';
    reportScam.disabled = campaignProtected || campaignDecisionTaken;
''',
)

learning_path = "web/protection-learning.js"
replace_once(
    learning_path,
    '''  async function familyAvailable() {
''',
    '''  function setReportScamAvailability(token, available, label = null) {
    document.querySelectorAll(`[data-action="report-scam"][data-review-token="${CSS.escape(token)}"]`).forEach((candidate) => {
      if (!(candidate instanceof HTMLButtonElement)) return;
      candidate.disabled = !available;
      if (typeof label === 'string' && label) candidate.textContent = label;
    });
  }

  async function familyAvailable() {
''',
)
replace_once(
    learning_path,
    '''    submittedPositiveFeedback.add(key);
    try {
      await post(accountId, 'legitimate-feedback', { token });
    } catch {
''',
    '''    submittedPositiveFeedback.add(key);
    setReportScamAvailability(token, false, 'Saving campaign feedback…');
    try {
      await post(accountId, 'legitimate-feedback', { token });
      setReportScamAvailability(token, false, 'Campaign decision already saved ✓');
    } catch {
      setReportScamAvailability(token, true, 'Report Scam to Email Shield');
''',
)

smoke_path = "scripts/engineering/smoke-browser-scan-results.mjs"
replace_once(
    smoke_path,
    '''  assert(snapshot.maliciousUnsafeActionVisible === false, "Unsafe HTTP unsubscribe destination was rendered as an actionable consumer control.");

  const blockTarget = await evaluate(client, `(() => {
''',
    '''  assert(snapshot.maliciousUnsafeActionVisible === false, "Unsafe HTTP unsubscribe destination was rendered as an actionable consumer control.");

  const positiveDecisionToken = await evaluate(client, `(() => {
    window.confirm = () => true;
    const button = [...document.querySelectorAll('.card button[data-action="mark-safe"]')]
      .find((candidate) => !candidate.disabled && candidate.dataset.reviewToken &&
        document.querySelector(`[data-action="report-scam"][data-review-token="${CSS.escape(candidate.dataset.reviewToken)}"]`));
    if (!button) return null;
    const token = button.dataset.reviewToken;
    button.click();
    return token;
  })()`);
  assert(positiveDecisionToken, `No Mark Safe + Report Scam decision pair was available after the fixture scan. Last state: ${JSON.stringify(snapshot)}`);

  let positiveDecisionState = null;
  const positiveDecisionDeadline = Date.now() + 15_000;
  while (Date.now() < positiveDecisionDeadline) {
    positiveDecisionState = await evaluate(client, `(() => {
      const report = document.querySelector('[data-action="report-scam"][data-review-token="${positiveDecisionToken}"]');
      const safe = document.querySelector('[data-action="mark-safe"][data-review-token="${positiveDecisionToken}"]');
      return {
        reportDisabled: report?.disabled === true,
        reportText: report?.textContent || '',
        safeDisabled: safe?.disabled === true,
        safeText: safe?.textContent || '',
      };
    })()`);
    if (positiveDecisionState?.reportDisabled && positiveDecisionState?.reportText.includes('Campaign decision already saved')) break;
    await sleep(100);
  }
  assert(positiveDecisionState?.safeDisabled === true && positiveDecisionState?.safeText.includes('marked Safe'),
    `Browser Mark Safe did not persist its visible local decision. State: ${JSON.stringify(positiveDecisionState)}`);
  assert(positiveDecisionState?.reportDisabled === true && positiveDecisionState?.reportText.includes('Campaign decision already saved'),
    `Positive campaign learning did not reconcile the mutually-exclusive Report Scam control. State: ${JSON.stringify(positiveDecisionState)}`);

  const blockTarget = await evaluate(client, `(() => {
''',
)
replace_once(
    smoke_path,
    '''  console.log("Legitimate newsletter + verified unsubscribe UI passed; unsafe HTTP unsubscribe remained non-actionable.");
  console.log(`Protected Block sender persisted and refreshed Personal Policy for ${blockTarget.address}.`);
''',
    '''  console.log("Legitimate newsletter + verified unsubscribe UI passed; unsafe HTTP unsubscribe remained non-actionable.");
  console.log("Mark Safe + positive campaign learning reconciled Report Scam without a deterministic capability conflict.");
  console.log(`Protected Block sender persisted and refreshed Personal Policy for ${blockTarget.address}.`);
''',
)

print("EMA-8 exact transform applied successfully")
