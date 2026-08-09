import type { LinkInfo } from "../canonical/envelope.js";

/**
 * Message content is attacker-controlled input. Keep structural interaction
 * inspection bounded and deterministic; if a limit is reached the caller must
 * block an automatic Safe verdict rather than silently treating uninspected
 * content as clean.
 */
export const MAX_HTML_INTERACTION_CHARS = 512 * 1024;
export const MAX_PLAIN_TEXT_INTERACTION_CHARS = 512 * 1024;
export const MAX_HTML_INTERACTION_TAGS = 4096;
export const MAX_HTML_INTERACTION_LINKS = 256;
const MAX_VISIBLE_LINK_TEXT_CHARS = 512;

interface ParsedTag {
  name: string;
  closing: boolean;
  attrs: Map<string, string>;
  start: number;
  end: number;
}

export interface HtmlInteractionAnalysis {
  links: LinkInfo[];
  htmlHrefs: string[];
  hasForm: boolean;
  hasPasswordField: boolean;
  incomplete: boolean;
  incompleteReasons: string[];
}

function isWhitespace(char: string | undefined): boolean {
  return Boolean(char && /\s/.test(char));
}

function isTagNameChar(char: string | undefined): boolean {
  return Boolean(char && /[A-Za-z0-9:_-]/.test(char));
}

function isAttributeNameChar(char: string | undefined): boolean {
  return Boolean(char && !/[\s=/>]/.test(char));
}

function safeCodePoint(value: number): string {
  if (!Number.isInteger(value) || value < 0 || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff)) {
    return "\uFFFD";
  }
  return String.fromCodePoint(value);
}

/** Decode entity forms that can materially alter a URL or a displayed-domain label. */
export function decodeHtmlEntities(value: string): string {
  const numericDecoded = value
    .replace(/&#x([0-9a-f]{1,6});?/gi, (_match, hex: string) => safeCodePoint(Number.parseInt(hex, 16)))
    .replace(/&#([0-9]{1,7});?/g, (_match, decimal: string) => safeCodePoint(Number.parseInt(decimal, 10)));

  const named: Record<string, string> = {
    amp: "&",
    apos: "'",
    bsol: "\\",
    colon: ":",
    commat: "@",
    equals: "=",
    gt: ">",
    lt: "<",
    newline: "\n",
    nbsp: " ",
    num: "#",
    percnt: "%",
    period: ".",
    quest: "?",
    quot: '"',
    semi: ";",
    sol: "/",
    tab: "\t",
  };
  return numericDecoded.replace(
    /&(amp|apos|bsol|colon|commat|equals|gt|lt|newline|nbsp|num|percnt|period|quest|quot|semi|sol|tab);/gi,
    (match, name: string) => named[name.toLowerCase()] ?? match,
  );
}

function parseTag(html: string, start: number): ParsedTag | null {
  let index = start + 1;
  let closing = false;
  if (html[index] === "/") {
    closing = true;
    index += 1;
  }
  while (isWhitespace(html[index])) index += 1;

  const nameStart = index;
  while (isTagNameChar(html[index])) index += 1;
  if (index === nameStart) return null;
  const name = html.slice(nameStart, index).toLowerCase();
  const attrs = new Map<string, string>();

  while (index < html.length) {
    while (isWhitespace(html[index])) index += 1;
    if (html[index] === ">") {
      return { name, closing, attrs, start, end: index };
    }
    if (html[index] === "/" && html[index + 1] === ">") {
      return { name, closing, attrs, start, end: index + 1 };
    }
    if (index >= html.length) break;

    const attrStart = index;
    while (isAttributeNameChar(html[index])) index += 1;
    if (index === attrStart) {
      index += 1;
      continue;
    }
    const attrName = html.slice(attrStart, index).toLowerCase();
    while (isWhitespace(html[index])) index += 1;

    let attrValue = "";
    if (html[index] === "=") {
      index += 1;
      while (isWhitespace(html[index])) index += 1;
      const quote = html[index] === '"' || html[index] === "'" ? html[index] : null;
      if (quote) {
        index += 1;
        const valueStart = index;
        while (index < html.length && html[index] !== quote) index += 1;
        attrValue = html.slice(valueStart, index);
        if (html[index] === quote) index += 1;
      } else {
        const valueStart = index;
        while (index < html.length && !isWhitespace(html[index]) && html[index] !== ">") index += 1;
        attrValue = html.slice(valueStart, index);
      }
    }
    if (!attrs.has(attrName)) attrs.set(attrName, decodeHtmlEntities(attrValue));
  }

  return { name, closing, attrs, start, end: Math.max(start, html.length - 1) };
}

function scanTags(html: string): { tags: ParsedTag[]; tagLimitReached: boolean } {
  const tags: ParsedTag[] = [];
  const lowerHtml = html.toLowerCase();
  let index = 0;
  while (index < html.length && tags.length < MAX_HTML_INTERACTION_TAGS) {
    const start = html.indexOf("<", index);
    if (start < 0) break;
    if (html.startsWith("<!--", start)) {
      const commentEnd = html.indexOf("-->", start + 4);
      index = commentEnd < 0 ? html.length : commentEnd + 3;
      continue;
    }
    if (html[start + 1] === "!" || html[start + 1] === "?") {
      const declarationEnd = html.indexOf(">", start + 2);
      index = declarationEnd < 0 ? html.length : declarationEnd + 1;
      continue;
    }
    const tag = parseTag(html, start);
    if (!tag) {
      index = start + 1;
      continue;
    }
    tags.push(tag);
    index = Math.max(start + 1, tag.end + 1);

    // SCRIPT and STYLE are raw-text elements. Markup-looking strings inside
    // them are inert text for this static email analysis and must not be
    // reinterpreted as anchors/forms/redirects.
    if (!tag.closing && (tag.name === "script" || tag.name === "style")) {
      const closingStart = lowerHtml.indexOf(`</${tag.name}`, index);
      index = closingStart < 0 ? html.length : closingStart;
    }
  }
  return {
    tags,
    tagLimitReached: tags.length >= MAX_HTML_INTERACTION_TAGS && html.indexOf("<", index) >= 0,
  };
}

function urlCandidate(raw: string): string {
  const trimmed = raw.trim();
  if (/^www\./i.test(trimmed)) return `https://${trimmed}`;
  if (/^\/\//.test(trimmed)) return `https:${trimmed}`;
  return trimmed;
}

function trustedBaseHref(raw: string | undefined): string | null {
  if (!raw) return null;
  try {
    const parsed = new URL(urlCandidate(raw));
    if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password) return null;
    return parsed.toString();
  } catch {
    return null;
  }
}

function normalizedDestination(raw: string, baseHref: string | null): string {
  const candidate = urlCandidate(decodeHtmlEntities(raw));
  if (!candidate) return "";
  try {
    return baseHref ? new URL(candidate, baseHref).toString() : new URL(candidate).toString();
  } catch {
    return candidate;
  }
}

function visibleAnchorText(html: string, tags: ParsedTag[], tagIndex: number): string | null {
  const open = tags[tagIndex]!;
  let end = open.end + 1;
  for (let index = tagIndex + 1; index < tags.length; index += 1) {
    const candidate = tags[index]!;
    if (candidate.name === "a" && candidate.closing) {
      end = candidate.start;
      break;
    }
  }
  if (end <= open.end + 1) return null;
  const inner = html.slice(open.end + 1, end)
    .replace(/<script\b[\s\S]*?<\/script\s*>/gi, " ")
    .replace(/<style\b[\s\S]*?<\/style\s*>/gi, " ")
    .replace(/<[^>]*>/g, " ");
  const text = decodeHtmlEntities(inner).replace(/\s+/g, " ").trim();
  return text ? text.slice(0, MAX_VISIBLE_LINK_TEXT_CHARS) : null;
}

function metaRefreshDestination(tag: ParsedTag): string | null {
  if (tag.name !== "meta" || tag.closing) return null;
  if ((tag.attrs.get("http-equiv") ?? "").trim().toLowerCase() !== "refresh") return null;
  const content = tag.attrs.get("content") ?? "";
  const match = content.match(/^\s*\d+(?:\.\d+)?\s*;\s*url\s*=\s*(.+?)\s*$/i);
  if (!match) return null;
  return match[1]!.replace(/^(?:"([\s\S]*)"|'([\s\S]*)')$/, (_whole, doubleQuoted: string, singleQuoted: string) => (
    doubleQuoted ?? singleQuoted ?? ""
  ));
}

function makeBodyLink(
  rawUrl: string,
  normalizedUrl: string,
  visibleText: string | null,
  interaction: NonNullable<LinkInfo["interaction"]>,
): LinkInfo {
  return {
    visibleText,
    rawUrl,
    normalizedUrl,
    claimedBrand: null,
    brandDomainMismatch: null,
    source: "body",
    interaction,
  };
}

function destinationLimitReason(): string {
  return `Message interaction inspection was limited to ${MAX_HTML_INTERACTION_LINKS} destinations.`;
}

function appendLink(
  links: LinkInfo[],
  seen: Set<string>,
  link: LinkInfo,
  incompleteReasons: string[],
): void {
  if (!link.rawUrl.trim()) return;
  const key = `${link.interaction ?? "navigation"}\0${link.normalizedUrl || link.rawUrl}\0${link.visibleText ?? ""}`;
  if (seen.has(key)) return;
  if (links.length >= MAX_HTML_INTERACTION_LINKS) {
    if (!incompleteReasons.includes(destinationLimitReason())) incompleteReasons.push(destinationLimitReason());
    return;
  }
  seen.add(key);
  links.push(link);
}

function appendPlainTextLinks(
  text: string | null | undefined,
  links: LinkInfo[],
  seen: Set<string>,
  incompleteReasons: string[],
): void {
  if (!text) return;
  const boundedText = text.length > MAX_PLAIN_TEXT_INTERACTION_CHARS
    ? text.slice(0, MAX_PLAIN_TEXT_INTERACTION_CHARS)
    : text;
  if (text.length > MAX_PLAIN_TEXT_INTERACTION_CHARS) {
    incompleteReasons.push(`Plain-text interaction inspection was bounded to ${MAX_PLAIN_TEXT_INTERACTION_CHARS} characters.`);
  }

  const bareRe = /(?:https?:\/\/|www\.)[^\s<>"']+/gi;
  let match: RegExpExecArray | null;
  while ((match = bareRe.exec(boundedText))) {
    const rawUrl = match[0]!.replace(/[),.;!?]+$/, "");
    const normalizedUrl = normalizedDestination(rawUrl, null);
    appendLink(
      links,
      seen,
      makeBodyLink(rawUrl, normalizedUrl, match[0]!, "navigation"),
      incompleteReasons,
    );
  }
}

/**
 * Extracts browser-relevant destinations without executing HTML. It handles
 * quoted/unquoted attributes, entity-obfuscated values, BASE-relative links,
 * form/formaction submissions and META refresh redirects. Plain-text URLs are
 * inspected even when a multipart HTML alternative also exists.
 */
export function analyzeHtmlInteractions(
  htmlValue: string | false | null | undefined,
  plainText: string | null | undefined,
): HtmlInteractionAnalysis {
  const html = typeof htmlValue === "string" ? htmlValue : "";
  const boundedHtml = html.length > MAX_HTML_INTERACTION_CHARS
    ? html.slice(0, MAX_HTML_INTERACTION_CHARS)
    : html;
  const incompleteReasons: string[] = [];
  if (html.length > MAX_HTML_INTERACTION_CHARS) {
    incompleteReasons.push(`HTML interaction inspection was bounded to ${MAX_HTML_INTERACTION_CHARS} characters.`);
  }

  const { tags, tagLimitReached } = scanTags(boundedHtml);
  if (tagLimitReached) {
    incompleteReasons.push(`HTML interaction inspection was bounded to ${MAX_HTML_INTERACTION_TAGS} tags.`);
  }

  const baseHref = trustedBaseHref(tags.find((tag) => !tag.closing && tag.name === "base")?.attrs.get("href"));
  const links: LinkInfo[] = [];
  const htmlHrefs: string[] = [];
  const seen = new Set<string>();
  const seenHrefs = new Set<string>();
  let hasForm = false;
  let hasPasswordField = false;

  for (let index = 0; index < tags.length; index += 1) {
    const tag = tags[index]!;
    if (tag.closing) continue;
    if (tag.name === "form") hasForm = true;
    if (tag.name === "input" && (tag.attrs.get("type") ?? "").trim().toLowerCase() === "password") {
      hasPasswordField = true;
    }

    if (tag.name === "a" || tag.name === "area") {
      const href = tag.attrs.get("href");
      if (href?.trim()) {
        const normalizedUrl = normalizedDestination(href, baseHref);
        if (!seenHrefs.has(href) && htmlHrefs.length < MAX_HTML_INTERACTION_LINKS) {
          seenHrefs.add(href);
          htmlHrefs.push(href);
        } else if (!seenHrefs.has(href) && !incompleteReasons.includes(destinationLimitReason())) {
          incompleteReasons.push(destinationLimitReason());
        }
        appendLink(
          links,
          seen,
          makeBodyLink(
            href,
            normalizedUrl,
            tag.name === "a" ? visibleAnchorText(boundedHtml, tags, index) : null,
            "navigation",
          ),
          incompleteReasons,
        );
      }
    }

    const action = tag.name === "form"
      ? tag.attrs.get("action")
      : (tag.name === "button" || tag.name === "input")
        ? tag.attrs.get("formaction")
        : undefined;
    if (action?.trim()) {
      appendLink(
        links,
        seen,
        makeBodyLink(action, normalizedDestination(action, baseHref), null, "form_action"),
        incompleteReasons,
      );
    }

    const refresh = metaRefreshDestination(tag);
    if (refresh?.trim()) {
      appendLink(
        links,
        seen,
        makeBodyLink(refresh, normalizedDestination(refresh, baseHref), null, "automatic_redirect"),
        incompleteReasons,
      );
    }
  }

  appendPlainTextLinks(plainText, links, seen, incompleteReasons);
  return {
    links,
    htmlHrefs,
    hasForm,
    hasPasswordField,
    incomplete: incompleteReasons.length > 0,
    incompleteReasons,
  };
}
