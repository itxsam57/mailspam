(() => {
  const installedModules = window.emailShieldInstalledModules ||= new Set();
  if (installedModules.has('media-authenticity')) return;
  installedModules.add('media-authenticity');

  const tools = document.querySelector('#consumerSafetyToolsPanel .consumer-two');
  if (!tools) return;

  const card = document.createElement('div');
  card.className = 'consumer-card';
  card.id = 'consumerMediaAuthenticity';

  const heading = document.createElement('h3');
  heading.textContent = 'Media Authenticity';
  const intro = document.createElement('p');
  intro.textContent = 'Check one image, audio clip or video that you explicitly select. Email Shield will not call media authentic when a detector is unavailable or inconclusive.';

  const fileLabel = document.createElement('label');
  fileLabel.className = 'field';
  const fileTitle = document.createElement('span');
  fileTitle.textContent = 'Selected media';
  const fileInput = document.createElement('input');
  fileInput.id = 'consumerMediaAuthenticityFile';
  fileInput.type = 'file';
  fileInput.accept = 'image/*,audio/*,video/*';
  fileInput.disabled = true;
  fileLabel.append(fileTitle, fileInput);

  const actions = document.createElement('div');
  actions.className = 'consumer-actions';
  const check = document.createElement('button');
  check.id = 'consumerCheckMediaAuthenticity';
  check.type = 'button';
  check.textContent = 'Check selected media';
  check.disabled = true;
  actions.append(check);

  const status = document.createElement('div');
  status.id = 'consumerMediaAuthenticityStatus';
  status.className = 'hint';
  status.setAttribute('role', 'status');
  status.setAttribute('aria-live', 'polite');
  status.textContent = 'Checking detector availability…';

  card.append(heading, intro, fileLabel, actions, status);
  tools.append(card);
  window.emailShieldRuntimeTrace?.registerControl(check, 'media_authenticity.run', 'media_authenticity.run', 'media_authenticity');

  let capability = null;

  function checkpoint(outcome = 'success', errorCode) {
    const trace = window.emailShieldRuntimeTrace;
    if (trace?.currentWorkflowId?.() !== 'media_authenticity.run') return;
    trace.checkpoint('media_authenticity.run.ui_confirmed', outcome, errorCode ? { errorCode } : undefined);
  }

  function mediaKind(file) {
    if (file.type.startsWith('image/')) return 'image';
    if (file.type.startsWith('audio/')) return 'audio';
    if (file.type.startsWith('video/')) return 'video';
    return null;
  }

  function limitFor(kind) {
    if (!capability?.supportedInput) return 0;
    if (kind === 'image') return Number(capability.supportedInput.imageMaxBytes || 0);
    if (kind === 'audio') return Number(capability.supportedInput.audioMaxBytes || 0);
    if (kind === 'video') return Number(capability.supportedInput.videoMaxBytes || 0);
    return 0;
  }

  function resultText(result) {
    const reason = Array.isArray(result.reasons) && result.reasons.length ? String(result.reasons[0]) : '';
    if (result.state === 'likely_manipulated') return `LIKELY MANIPULATED${result.confidenceBand ? ` (${String(result.confidenceBand).toUpperCase()} CONFIDENCE)` : ''}: ${reason}`;
    if (result.state === 'no_indicator') return `NO SUPPORTED INDICATOR: ${reason || 'The configured detector did not return a manipulation indicator.'} This is not proof that the media is authentic.`;
    if (result.state === 'inconclusive') return `INCONCLUSIVE: ${reason || 'The configured detector could not reach a reliable conclusion.'}`;
    return `UNAVAILABLE: ${reason || 'Media authenticity could not be checked. No authenticity claim was made.'}`;
  }

  async function loadCapability() {
    try {
      const response = await fetch('/api/consumer/v1/media/authenticity/status');
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.error || `Media Authenticity status failed (${response.status}).`);
      capability = body;
      if (body.available !== true) {
        fileInput.disabled = true;
        check.disabled = true;
        status.textContent = `UNAVAILABLE: ${body.limitation || 'No vetted detector is configured in this build.'}`;
        return;
      }
      fileInput.disabled = false;
      check.disabled = false;
      status.textContent = `${body.limitation || 'A vetted detector is configured.'} Only explicitly selected media is analyzed.`;
    } catch (error) {
      fileInput.disabled = true;
      check.disabled = true;
      status.textContent = `UNAVAILABLE: ${error instanceof Error ? error.message : String(error)}`;
    }
  }

  check.addEventListener('click', async () => {
    const file = fileInput.files?.[0];
    if (!file) {
      status.textContent = 'Choose one image, audio clip or video first.';
      checkpoint('rejected', 'media_file_missing');
      return;
    }
    const kind = mediaKind(file);
    if (!kind) {
      status.textContent = 'Unsupported media type. Choose an image, audio clip or video.';
      checkpoint('rejected', 'media_type_unsupported');
      return;
    }
    const limit = limitFor(kind);
    if (!Number.isFinite(limit) || limit < 1 || file.size > limit) {
      status.textContent = `Selected ${kind} exceeds the configured bounded input limit.`;
      checkpoint('rejected', 'media_input_limit');
      return;
    }

    check.disabled = true;
    status.textContent = 'Analyzing the explicitly selected media…';
    try {
      const response = await fetch('/api/consumer/v1/media/authenticity', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/octet-stream',
          'X-Email-Shield-Media-Kind': kind,
          'X-Email-Shield-Media-Mime': file.type || 'application/octet-stream',
        },
        body: await file.arrayBuffer(),
      });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(result.error || `Media Authenticity failed (${response.status}).`);
      status.textContent = resultText(result);
      checkpoint(result.state === 'unavailable' || result.state === 'inconclusive' ? 'partial' : 'success');
    } catch (error) {
      status.textContent = `UNAVAILABLE: ${error instanceof Error ? error.message : String(error)} No authenticity claim was made.`;
      checkpoint('failed', 'media_authenticity_failed');
    } finally {
      check.disabled = capability?.available !== true;
    }
  });

  void loadCapability();
})();
