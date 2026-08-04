import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";

/**
 * Synthetic scam corpus covering every category in spec Section 6.
 * Patterns are modeled on publicly-reported scam structures (FTC/FBI IC3
 * consumer alerts, anti-phishing writeups) — real wording, sender tricks,
 * and pressure patterns, but with fictitious domains/amounts/names so
 * nothing here is a live phishing sample. One malicious + one legitimate
 * control per category; three high-volume categories additionally get
 * MIME-encoding variants (plain/HTML/multipart/base64/quoted-printable)
 * to prove the engine scores equivalently regardless of encoding.
 */

const CRLF = "\r\n";

function qpEncode(text: string): string {
  return text
    .split("")
    .map((ch) => {
      const code = ch.charCodeAt(0);
      if (ch === "=") return "=3D";
      if (code > 126 || code < 32) return "=" + code.toString(16).toUpperCase().padStart(2, "0");
      return ch;
    })
    .join("");
}

interface EmailSpec {
  from: string;
  fromName?: string;
  replyTo?: string;
  subject: string;
  bodyText: string;
  bodyHtml?: string;
  authResults?: string; // raw Authentication-Results header value
  attachmentName?: string;
  attachmentContent?: string; // base64 already, or plain text to be encoded
  listId?: string;
  listUnsubscribe?: string;
  listUnsubscribePost?: string;
}

function buildEml(spec: EmailSpec, encoding: "plain" | "html" | "multipart" | "base64" | "quoted-printable" = "plain"): string {
  const headers: string[] = [
    `From: ${spec.fromName ? `"${spec.fromName}" ` : ""}<${spec.from}>`,
    `To: user@example-mailbox.test`,
    spec.replyTo ? `Reply-To: <${spec.replyTo}>` : null,
    `Subject: ${spec.subject}`,
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: <${Math.random().toString(36).slice(2)}@fixture.test>`,
    spec.authResults ? `Authentication-Results: mx.example.test; ${spec.authResults}` : null,
    spec.listId ? `List-ID: <${spec.listId}>` : null,
    spec.listUnsubscribe ? `List-Unsubscribe: <${spec.listUnsubscribe}>` : null,
    spec.listUnsubscribePost ? `List-Unsubscribe-Post: ${spec.listUnsubscribePost}` : null,
  ].filter((h): h is string => h !== null);

  if (encoding === "plain") {
    headers.push("Content-Type: text/plain; charset=utf-8");
    headers.push("Content-Transfer-Encoding: 7bit");
    return headers.join(CRLF) + CRLF + CRLF + spec.bodyText;
  }

  if (encoding === "quoted-printable") {
    headers.push("Content-Type: text/plain; charset=utf-8");
    headers.push("Content-Transfer-Encoding: quoted-printable");
    return headers.join(CRLF) + CRLF + CRLF + qpEncode(spec.bodyText);
  }

  if (encoding === "base64") {
    headers.push("Content-Type: text/plain; charset=utf-8");
    headers.push("Content-Transfer-Encoding: base64");
    const b64 = Buffer.from(spec.bodyText, "utf-8").toString("base64");
    const wrapped = b64.match(/.{1,76}/g)?.join(CRLF) ?? b64;
    return headers.join(CRLF) + CRLF + CRLF + wrapped;
  }

  if (encoding === "html") {
    headers.push("Content-Type: text/html; charset=utf-8");
    headers.push("Content-Transfer-Encoding: 7bit");
    return headers.join(CRLF) + CRLF + CRLF + (spec.bodyHtml ?? `<p>${spec.bodyText}</p>`);
  }

  // multipart/alternative (text + html), optionally with an attachment (multipart/mixed wrapping)
  const altBoundary = "altBoundary_" + Math.random().toString(36).slice(2);
  const mixedBoundary = "mixedBoundary_" + Math.random().toString(36).slice(2);
  const altPart =
    `--${altBoundary}${CRLF}` +
    `Content-Type: text/plain; charset=utf-8${CRLF}${CRLF}${spec.bodyText}${CRLF}` +
    `--${altBoundary}${CRLF}` +
    `Content-Type: text/html; charset=utf-8${CRLF}${CRLF}${spec.bodyHtml ?? `<p>${spec.bodyText}</p>`}${CRLF}` +
    `--${altBoundary}--`;

  if (spec.attachmentName) {
    headers.push(`Content-Type: multipart/mixed; boundary="${mixedBoundary}"`);
    const attContent = spec.attachmentContent
      ? Buffer.from(spec.attachmentContent).toString("base64")
      : Buffer.from("fixture-attachment-content").toString("base64");
    const body =
      `--${mixedBoundary}${CRLF}` +
      `Content-Type: multipart/alternative; boundary="${altBoundary}"${CRLF}${CRLF}` +
      altPart + CRLF +
      `--${mixedBoundary}${CRLF}` +
      `Content-Type: application/octet-stream; name="${spec.attachmentName}"${CRLF}` +
      `Content-Transfer-Encoding: base64${CRLF}` +
      `Content-Disposition: attachment; filename="${spec.attachmentName}"${CRLF}${CRLF}` +
      attContent + CRLF +
      `--${mixedBoundary}--`;
    return headers.join(CRLF) + CRLF + CRLF + body;
  }

  headers.push(`Content-Type: multipart/alternative; boundary="${altBoundary}"`);
  return headers.join(CRLF) + CRLF + CRLF + altPart;
}

interface CategoryFixture {
  category: string;
  malicious: EmailSpec;
  legit: EmailSpec;
  mimeVariants?: boolean;
}

const FIXTURES: CategoryFixture[] = [
  {
    category: "brand_impersonation",
    malicious: {
      from: "security@paypal-secure-alerts.com",
      fromName: "PayPal Security",
      subject: "Your PayPal account will be suspended within 24 hours",
      bodyText:
        "We detected unusual sign-in activity on your PayPal account. Your account will be suspended within 24 hours unless you verify your account now. Click here to confirm your identity: http://paypal-secure-alerts.com/verify",
      authResults: "spf=fail smtp.mailfrom=paypal-secure-alerts.com; dkim=fail; dmarc=fail",
    },
    legit: {
      from: "service@paypal.com",
      fromName: "PayPal",
      subject: "Your receipt for a payment to Example Store",
      bodyText: "You sent a payment of $42.00 USD to Example Store. This is your receipt. View details at https://paypal.com/activity",
      authResults: "spf=pass smtp.mailfrom=paypal.com; dkim=pass; dmarc=pass",
    },
    mimeVariants: false,
  },
  {
    category: "callback_scam",
    malicious: {
      from: "billing@subscription-renewals.net",
      fromName: "Order Support",
      subject: "Invoice: Your subscription has been renewed for $499.99",
      bodyText:
        "Your annual subscription has been renewed for $499.99. If you did not authorize this charge, call us now at (888) 555-0134 to request a refund within 24 hours.",
      authResults: "spf=fail; dkim=fail; dmarc=fail",
    },
    legit: {
      from: "billing@realsoftwareco.com",
      fromName: "RealSoftwareCo Billing",
      subject: "Your invoice from RealSoftwareCo",
      bodyText: "Your monthly subscription invoice is attached. Manage your subscription any time at https://realsoftwareco.com/account",
      authResults: "spf=pass; dkim=pass; dmarc=pass",
    },
  },
  {
    category: "credential_phishing",
    malicious: {
      from: "no-reply@accounts-verify-secure.com",
      fromName: "Account Services",
      subject: "Unusual sign-in activity detected — verify your account",
      bodyText:
        "We noticed unusual sign-in activity on your account. Your account will be suspended within 24 hours. Please confirm your identity and enter your password and one-time passcode here: http://accounts-verify-secure.com/login",
      bodyHtml:
        '<p>We noticed unusual sign-in activity. Your account will be suspended within 24 hours.</p><a href="http://accounts-verify-secure.com/login">https://accounts.google.com/login</a>',
      authResults: "spf=fail; dkim=fail; dmarc=fail",
    },
    legit: {
      from: "no-reply@google.com",
      fromName: "Google",
      subject: "Security alert: new sign-in from Chrome on Windows",
      bodyText: "A new sign-in to your Google Account was detected. If this was you, no action is needed. Review activity at https://myaccount.google.com/security",
      authResults: "spf=pass; dkim=pass; dmarc=pass",
    },
    mimeVariants: true,
  },
  {
    category: "business_email_compromise",
    malicious: {
      from: "ceo.office@company-corp-inc.com",
      fromName: "Michael Chen (CEO)",
      replyTo: "m.chen.ceo@company-corp-inc.co",
      subject: "Quick request",
      bodyText:
        "Are you available right now? I need you to process an urgent wire transfer to a new vendor today. Keep this confidential for now, don't discuss it with anyone else on the team, I'll explain later. Can you do this right away?",
      authResults: "spf=fail; dkim=fail; dmarc=fail",
    },
    legit: {
      from: "michael.chen@company-corp.com",
      fromName: "Michael Chen",
      subject: "Q3 planning doc",
      bodyText: "Hi team, attached is the draft Q3 planning doc for review before Thursday's meeting. Let me know your thoughts.",
      authResults: "spf=pass; dkim=pass; dmarc=pass",
    },
    mimeVariants: true,
  },
  {
    category: "cryptocurrency_scam",
    malicious: {
      from: "support@crypto-invest-platform.io",
      fromName: "CryptoInvest Support",
      subject: "Your wallet requires validation — guaranteed returns inside",
      bodyText:
        "Our investment platform offers guaranteed returns and can double your Bitcoin in 30 days. Act now, limited spots. Please validate your wallet by entering your seed phrase at http://crypto-invest-platform.io/validate",
      authResults: "spf=fail; dkim=fail; dmarc=fail",
    },
    legit: {
      from: "no-reply@coinbase.com",
      fromName: "Coinbase",
      subject: "Your BTC purchase confirmation",
      bodyText: "You successfully purchased 0.01 BTC. View your transaction history at https://coinbase.com/transactions",
      authResults: "spf=pass; dkim=pass; dmarc=pass",
    },
    mimeVariants: true,
  },
  {
    category: "delivery_payment_scam",
    malicious: {
      from: "delivery@parcel-redelivery-notice.com",
      fromName: "Delivery Notice",
      subject: "Your parcel could not be delivered — customs fee required",
      bodyText:
        "Your parcel is being held due to an unpaid customs fee. Pay a small fee within 24 hours or the parcel will be returned. Update your address and payment here: http://parcel-redelivery-notice.com/pay",
      authResults: "spf=fail; dkim=fail; dmarc=fail",
    },
    legit: {
      from: "tracking@ups.com",
      fromName: "UPS",
      subject: "Your package has shipped",
      bodyText: "Your package is on its way. Track your shipment at https://ups.com/track",
      authResults: "spf=pass; dkim=pass; dmarc=pass",
    },
  },
  {
    category: "romance_adult_social_lure",
    malicious: {
      from: "sofia.lonely.heart@meetup-connect-now.com",
      fromName: "Sofia",
      subject: "I've been feeling so lonely, view my profile?",
      bodyText:
        "Hi, I've been feeling lonely and looking for love. Click to view my profile and photos, let's chat: http://meetup-connect-now.com/profile. Please keep this secret between us for now.",
      authResults: "spf=fail; dkim=fail; dmarc=fail",
    },
    legit: {
      from: "notifications@realdatingapp.com",
      fromName: "RealDatingApp",
      subject: "You have a new match!",
      bodyText: "You matched with someone new. Open the app to start chatting. https://realdatingapp.com/matches",
      authResults: "spf=pass; dkim=pass; dmarc=pass",
    },
  },
  {
    category: "job_task_scam",
    malicious: {
      from: "hr@remote-hiring-now.com",
      fromName: "Remote Hiring Team",
      subject: "Work-from-home position — no experience needed, start today",
      bodyText:
        "We're hiring for a work-from-home task-based job, no experience needed. Start today. We'll send equipment; please pay a small equipment fee first, or deposit the check we send and wire back the overpayment difference.",
      authResults: "spf=fail; dkim=fail; dmarc=fail",
    },
    legit: {
      from: "careers@realcompany.com",
      fromName: "RealCompany Careers",
      subject: "Your application to RealCompany",
      bodyText: "Thank you for applying to RealCompany. Our recruiting team will reach out within two weeks if there's a match.",
      authResults: "spf=pass; dkim=pass; dmarc=pass",
    },
  },
  {
    category: "government_legal_scam",
    malicious: {
      from: "notice@irs-tax-refund-center.com",
      fromName: "IRS Tax Refund Center",
      subject: "Final notice: legal action pending — respond immediately",
      bodyText:
        "Failure to respond will result in legal action and a warrant for arrest. Your tax refund and benefits are suspended pending compliance. Pay immediately to avoid court proceedings.",
      authResults: "spf=fail; dkim=fail; dmarc=fail",
    },
    legit: {
      from: "no-reply@irs.gov",
      fromName: "IRS",
      subject: "Your Economic Impact Payment status",
      bodyText: "You can check your payment status by logging into your account at https://irs.gov/account. The IRS never demands immediate payment by email.",
      authResults: "spf=pass; dkim=pass; dmarc=pass",
    },
  },
  {
    category: "prize_reward_scam",
    malicious: {
      from: "claims@lottery-winner-notice.com",
      fromName: "International Lottery",
      subject: "Congratulations, you've won! Claim now, offer expires today",
      bodyText:
        "You've won a $1,000,000 prize in our loyalty rewards lottery. Claim your prize now, this expires today. A small processing fee (advance fee) is required to release your voucher.",
      authResults: "spf=fail; dkim=fail; dmarc=fail",
    },
    legit: {
      from: "rewards@realretailer.com",
      fromName: "RealRetailer Rewards",
      subject: "You've earned 500 loyalty points",
      bodyText: "You've earned 500 loyalty points on your last purchase. Redeem them any time at https://realretailer.com/rewards",
      authResults: "spf=pass; dkim=pass; dmarc=pass",
    },
  },
  {
    category: "cloud_document_scam",
    malicious: {
      from: "no-reply@docusign-notify-secure.com",
      fromName: "DocuSign",
      subject: "A document requires your signature — expires in 24 hours",
      bodyText:
        "John Smith has shared a document with you via DocuSign that requires your signature. This expires in 24 hours. Click to review and sign: http://docusign-notify-secure.com/sign",
      authResults: "spf=fail; dkim=fail; dmarc=fail",
    },
    legit: {
      from: "no-reply@docusign.net",
      fromName: "DocuSign",
      subject: "Completed: Your document has been signed by all parties",
      bodyText: "Your document 'Service Agreement' has been signed by all parties. View the completed document at https://docusign.net/documents",
      authResults: "spf=pass; dkim=pass; dmarc=pass",
    },
  },
  {
    category: "qr_phishing",
    malicious: {
      from: "no-reply@secure-mfa-update.com",
      fromName: "IT Security",
      subject: "Scan to re-verify your MFA device",
      bodyText:
        "Your MFA device needs re-verification. Scan the attached QR code with your phone camera to confirm your identity. This image-only link cannot be inspected before scanning.",
      authResults: "spf=fail; dkim=fail; dmarc=fail",
      attachmentName: "qr_code.png",
      attachmentContent: "fixture-qr-png-not-a-real-image",
    },
    legit: {
      from: "it-support@realcompany.com",
      fromName: "RealCompany IT",
      subject: "Reminder: badge photo for new ID card",
      bodyText: "Reminder to submit your badge photo for your new employee ID card by Friday.",
      authResults: "spf=pass; dkim=pass; dmarc=pass",
      attachmentName: "badge_instructions.png",
      attachmentContent: "fixture-badge-png-not-a-real-image",
    },
  },
  {
    category: "malware_delivery",
    malicious: {
      from: "invoices@vendor-billing-dept.com",
      fromName: "Vendor Billing",
      subject: "Invoice attached for your review",
      bodyText: "Please find the attached invoice for your recent order. Open the attached file to view details.",
      authResults: "spf=fail; dkim=fail; dmarc=fail",
      attachmentName: "invoice.pdf.exe",
      attachmentContent: "MZ-fixture-not-a-real-executable",
    },
    legit: {
      from: "billing@realvendor.com",
      fromName: "RealVendor Billing",
      subject: "Your invoice #48213",
      bodyText: "Please find your invoice attached as a PDF for your records.",
      authResults: "spf=pass; dkim=pass; dmarc=pass",
      attachmentName: "invoice_48213.pdf",
      attachmentContent: "%PDF-1.4-fixture-not-a-real-pdf",
    },
  },
  {
    category: "browser_trap",
    malicious: {
      from: "alert@browser-security-check.com",
      fromName: "Browser Security Alert",
      subject: "Your computer is infected — call now for support",
      bodyText:
        "Warning: your computer is infected with 3 viruses. Call now to speak with a support agent. Enable notifications to receive real-time protection updates: http://browser-security-check.com/enable",
      authResults: "spf=fail; dkim=fail; dmarc=fail",
    },
    legit: {
      from: "no-reply@realantivirus.com",
      fromName: "RealAntivirus",
      subject: "Your subscription renewal receipt",
      bodyText: "Your RealAntivirus subscription was renewed. View your receipt at https://realantivirus.com/account",
      authResults: "spf=pass; dkim=pass; dmarc=pass",
    },
  },
  {
    category: "newsletter_marketing_abuse",
    malicious: {
      from: "deals@bulk-marketing-blast.com",
      fromName: "Mega Deals Daily",
      subject: "RE: RE: You're still subscribed — click to unsubscribe (fake)",
      bodyText: "You are receiving this because you're on our list. Click the link below to unsubscribe: http://bulk-marketing-blast.com/unsub?track=1",
      listId: "megadeals.bulk-marketing-blast.com",
      listUnsubscribe: "http://bulk-marketing-blast.com/unsub?track=1",
      authResults: "spf=fail; dkim=fail; dmarc=fail",
    },
    legit: {
      from: "newsletter@realnewsco.com",
      fromName: "RealNews Weekly",
      subject: "Your weekly digest",
      bodyText: "Here's your weekly digest of top stories.",
      listId: "weekly.realnewsco.com",
      listUnsubscribe: "https://realnewsco.com/unsubscribe?one-click=true",
      listUnsubscribePost: "List-Unsubscribe=One-Click",
      authResults: "spf=pass; dkim=pass; dmarc=pass",
    },
  },
  {
    category: "conversation_hijacking",
    malicious: {
      from: "accounting@partner-co-vendor.com",
      fromName: "Partner Co Accounting",
      replyTo: "accounting@partner-co-vendor.co",
      subject: "RE: RE: Invoice payment — updated bank details",
      bodyText:
        "Following up on our thread — please note our bank details have changed. Send the wire transfer to the new account listed below instead of the previous one. Please confirm once sent.",
      authResults: "spf=fail; dkim=fail; dmarc=fail",
    },
    legit: {
      from: "accounting@partner-co.com",
      fromName: "Partner Co Accounting",
      subject: "RE: Invoice payment",
      bodyText: "Confirming we received your payment for invoice #7734. Thank you!",
      authResults: "spf=pass; dkim=pass; dmarc=pass",
    },
  },
];

const outDir = join(import.meta.dirname, "scam-corpus");
const manifest: Array<{ category: string; kind: "malicious" | "legit"; file: string; variant: string }> = [];

for (const fixture of FIXTURES) {
  const catDir = join(outDir, fixture.category);
  mkdirSync(catDir, { recursive: true });

  const variants: Array<"plain" | "html" | "multipart" | "base64" | "quoted-printable"> = fixture.mimeVariants
    ? ["plain", "html", "multipart", "base64", "quoted-printable"]
    : ["plain"];

  for (const kind of ["malicious", "legit"] as const) {
    const spec = fixture[kind];
    for (const variant of variants) {
      const eml = buildEml(spec, variant);
      const filename = `${kind}-${variant}.eml`;
      writeFileSync(join(catDir, filename), eml, "utf-8");
      manifest.push({ category: fixture.category, kind, file: join(fixture.category, filename), variant });
    }
  }
}

writeFileSync(join(outDir, "manifest.json"), JSON.stringify(manifest, null, 2), "utf-8");
console.log(`Generated ${manifest.length} fixture files across ${FIXTURES.length} categories.`);
