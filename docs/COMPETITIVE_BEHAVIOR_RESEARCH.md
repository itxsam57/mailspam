# Email Shield — Public Competitor Behavior Benchmark

This document records only publicly documented product behaviors and claims that can inform independent Email Shield engineering. It does not authorize copying source code, private APIs, models, private datasets, branding, UI assets or trade secrets.

## Guardio

Publicly documented behaviors include real-time phishing protection across email/text/browsing, malicious-site blocking, malicious-download blocking, malicious-extension detection/neutralization, search-hijacker correction, breach monitoring, Gmail email-security labels/alerts and fake-review warnings.

Email Shield adaptation: local-first URL and browser-defense contract; phishing warnings before navigation; extension/download-risk handoff contract; privacy-safe breach checks; optional shopping/fake-review risk evidence where independently observable; provider-neutral email protection instead of Gmail-only behavior.

## Bitdefender

Publicly documented behaviors include Scamio/Scamio Pro on-demand checking of messages, emails, links, screenshots/images and QR codes; Scam Radar emerging-campaign warnings; Gmail/Outlook email protection; Android SMS/notification/chat protection; iOS SMS/calendar-invite protection; web scam protection; remote-access/banking scam-prevention alerts.

Email Shield adaptation: Check Anything; campaign radar using privacy-reduced fingerprints; mobile text/notification/calendar contracts; local browser/link defense; high-risk remote-access plus financial-scam intervention.

## McAfee

Publicly documented behaviors include full-context scam detection rather than URL-only checks; automatic scam detection across text/email/video; on-demand screenshot/message/link/QR checks; explain-why; High/Balanced/Low sensitivity; Gmail/Outlook/Yahoo coverage; safe browsing after click; and on-device deepfake audio/video detection on supported hardware.

Email Shield adaptation: full-context deterministic evidence fusion; consumer sensitivity profiles that cannot bypass hard threats; explainability; provider-neutral mail; local deepfake/voice-analysis plugin contract that is optional and hardware/resource bounded.

## Norton

Publicly documented behaviors include Norton Genie on-demand checking of text/email/social/web content, AI-powered scam guidance, SMS protection and deepfake protection.

Email Shield adaptation: local-first scam assistant presentation layer over deterministic evidence; mobile SMS contract; optional local deepfake plugin contract.

## Aura

Publicly documented behaviors include AI email protection across Gmail/iCloud/Outlook/AOL/Yahoo, spam/scam call and message protection, Safe Browsing, identity/dark-web monitoring, family alerts, unused digital-account cleanup, data-removal services and family identity protection.

Email Shield adaptation: provider-neutral mail; Family Guardian; privacy-safe breach exposure; local digital-account-footprint discovery from mailbox metadata/content processed locally; phone/callback verification contract; exclude credit/insurance/data-broker services unless later provided by a separately reviewed regulated/commercial partner.

## Clean Email

Publicly documented behaviors include bulk unsubscribe, catch-and-remove continued mailing after unsubscribe, sender Screener/quarantine, Smart Folders, bulk cleanup, Pause, Read Later, Mute, Keep Newest, rules, activity logs and breach/privacy monitoring.

Email Shield adaptation: Inbox Health using existing unsubscribe/blocking infrastructure, optional unknown-sender screening, safe cleanup rules, activity/undo, local categorization and privacy-safe breach checks.

## Google/Gmail

Publicly documented behaviors include phishing/spam warnings, authentication indicators, spoof/lookalike warnings, Safe Browsing, suspicious-message reporting, compromised-contact warnings, blocking and centralized subscription management.

Email Shield adaptation: preserve/consume provider evidence without blindly trusting it; strengthen independent sender/authentication/relationship evidence; cross-provider subscription inventory; independently verified safe-navigation guidance.

## Microsoft/Outlook/Defender

Publicly documented behaviors include spoof intelligence, sender verification indicators, Safe Links, attachment malware scanning, red/yellow safety bars, blocked/safe senders, phishing reporting and device web protection.

Email Shield adaptation: provider-neutral sender/authentication explanations; real-time URL defense contract; stronger attachment static analysis; reversible sender/domain policy controls; local web-protection foundation.

## Additional final-milestone capabilities derived from the benchmark

### Deepfake and voice-scam analysis contract

Add an optional plugin boundary for local deepfake/voice-clone risk analysis of user-submitted audio/video. The core application must remain usable without this module. No automatic cloud upload. Results are advisory evidence and must carry provenance/model-version/confidence calibration. Native hardware acceleration can be added during platform wrapping.

### Phone/callback verification

Extract phone numbers from suspicious content locally, flag callback/refund/support patterns, compare independently against trusted organization contact records only when a vetted source is available, and always advise users to obtain official contact details independently rather than calling a number from a suspicious message. Future mobile call screening remains a native-platform capability.

### Shopping and fake-store protection

Extend URL/site evidence to detect independently observable scam-store indicators such as very new/low-reputation domains when a privacy-safe reputation source is available, lookalike brands, suspicious payment/urgency language, impossible discount patterns and known malicious destinations. Fake-review indicators are advisory only unless supported by robust evidence.

### Digital Account Footprint

Using local mailbox processing, identify likely account-registration, verification, welcome and password-reset history to build a private inventory of online services the user appears to have used. Allow the user to mark accounts active/unused and generate safe official-site cleanup guidance. Do not upload the account inventory. Do not automatically close accounts.

### Optional local deepfake module acceptance

Any future local model must have bounded model size/runtime, offline inference, no telemetry by default, deterministic versioning, adversarial/legitimate evaluation, and an explicit unsupported-device state rather than silently falling back to cloud processing.
