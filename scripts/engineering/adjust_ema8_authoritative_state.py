from pathlib import Path

path = Path("web/protection-learning.js")
source = path.read_text(encoding="utf-8")
before = '''  function publishCampaignDecisionState(token, state) {
    window.dispatchEvent(new CustomEvent('email-shield-campaign-decision-state', {
      detail: { token, state },
    }));
  }

  async function familyAvailable() {
'''
after = '''  function publishCampaignDecisionState(token, state) {
    window.dispatchEvent(new CustomEvent('email-shield-campaign-decision-state', {
      detail: { token, state },
    }));
  }

  async function authoritativeCampaignDecisionState(accountId, token, fallbackState) {
    try {
      const response = await fetch('/api/accounts/workspace', {
        headers: { Accept: 'application/json' },
        cache: 'no-store',
      });
      const workspace = await response.json().catch(() => ({}));
      if (!response.ok || workspace.selectedAccountId !== accountId) return fallbackState;
      const presentation = workspace.presentation && typeof workspace.presentation === 'object'
        ? workspace.presentation
        : {};
      const entries = [
        ...(Array.isArray(presentation.suspiciousCards) ? presentation.suspiciousCards : []),
        ...(Array.isArray(presentation.diagnosticSummaries) ? presentation.diagnosticSummaries : []),
      ];
      const entry = entries.find((candidate) => candidate?.reviewAction?.token === token);
      if (entry?.reviewAction?.reportScamAvailable === false) return 'saved';
      if (entry?.reviewAction?.reportScamAvailable === true) return 'available';
    } catch {
      // The mutation result remains the bounded fallback when optional workspace
      // presentation cannot be re-read. Never expose mailbox content here.
    }
    return fallbackState;
  }

  async function familyAvailable() {
'''
if source.count(before) != 1:
    raise RuntimeError(f"expected campaign state publisher exactly once, found {source.count(before)}")
source = source.replace(before, after, 1)

before_submit = '''    submittedPositiveFeedback.add(key);
    publishCampaignDecisionState(token, 'pending');
    try {
      await post(accountId, 'legitimate-feedback', { token });
      publishCampaignDecisionState(token, 'saved');
    } catch {
      publishCampaignDecisionState(token, 'available');
      // Community learning is deliberately secondary to the user's durable
      // local Safe/Trust decision. A later fresh action can retry without
      // undoing local policy or exposing raw mailbox content.
      submittedPositiveFeedback.delete(key);
    }
'''
after_submit = '''    submittedPositiveFeedback.add(key);
    publishCampaignDecisionState(token, 'pending');
    let fallbackState = 'available';
    try {
      await post(accountId, 'legitimate-feedback', { token });
      fallbackState = 'saved';
    } catch {
      // Community learning is deliberately secondary to the user's durable
      // local Safe/Trust decision. The server remains authoritative about
      // whether a concurrent/duplicate decision retained this capability.
    }
    const state = await authoritativeCampaignDecisionState(accountId, token, fallbackState);
    if (state === 'saved') submittedPositiveFeedback.add(key);
    else submittedPositiveFeedback.delete(key);
    publishCampaignDecisionState(token, state);
'''
if source.count(before_submit) != 1:
    raise RuntimeError(f"expected transformed feedback block exactly once, found {source.count(before_submit)}")
source = source.replace(before_submit, after_submit, 1)
path.write_text(source, encoding="utf-8")
print("EMA-8 positive-learning state now reconciles from the authoritative workspace capability")
