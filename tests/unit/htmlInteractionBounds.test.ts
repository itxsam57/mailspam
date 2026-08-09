import { describe, expect, it } from "vitest";
import {
  analyzeHtmlInteractions,
  MAX_HTML_INTERACTION_LINKS,
  MAX_HTML_INTERACTION_TAGS,
  MAX_PLAIN_TEXT_INTERACTION_CHARS,
} from "../../server/src/util/htmlInteraction.js";

describe("HTML interaction parser bounds", () => {
  it("does not reinterpret markup-looking strings inside SCRIPT or STYLE raw text", () => {
    const analysis = analyzeHtmlInteractions([
      '<script>const bait = `<a href="https://script-only.example">Open</a>`;</script>',
      '<style>.x::after { content: "<form action=https://style-only.example>"; }</style>',
      '<a href="https://real.example/path">Real</a>',
    ].join(""), null);

    expect(analysis.links.map((link) => link.normalizedUrl)).toEqual(["https://real.example/path"]);
    expect(analysis.hasForm).toBe(false);
  });

  it("caps canonical destinations and marks the remainder incomplete", () => {
    const html = Array.from(
      { length: MAX_HTML_INTERACTION_LINKS + 1 },
      (_, index) => `<a href="https://destination-${index}.example/path">${index}</a>`,
    ).join("");
    const analysis = analyzeHtmlInteractions(html, null);

    expect(analysis.links).toHaveLength(MAX_HTML_INTERACTION_LINKS);
    expect(analysis.incomplete).toBe(true);
    expect(analysis.incompleteReasons).toContain(
      `Message interaction inspection was limited to ${MAX_HTML_INTERACTION_LINKS} destinations.`,
    );
  });

  it("caps parsed tags and marks an uninspected markup tail incomplete", () => {
    const html = `${"<span>x</span>".repeat(MAX_HTML_INTERACTION_TAGS)}<a href=https://after-tag-limit.example>Hidden</a>`;
    const analysis = analyzeHtmlInteractions(html, null);

    expect(analysis.incomplete).toBe(true);
    expect(analysis.incompleteReasons).toContain(
      `HTML interaction inspection was bounded to ${MAX_HTML_INTERACTION_TAGS} tags.`,
    );
    expect(analysis.links.map((link) => link.normalizedUrl)).not.toContain("https://after-tag-limit.example/");
  });

  it("bounds plain-text interaction scanning and does not inspect a URL beyond the accepted prefix", () => {
    const text = `${"A".repeat(MAX_PLAIN_TEXT_INTERACTION_CHARS)} https://after-text-limit.example/path`;
    const analysis = analyzeHtmlInteractions("<p>Visible HTML</p>", text);

    expect(analysis.incomplete).toBe(true);
    expect(analysis.incompleteReasons).toContain(
      `Plain-text interaction inspection was bounded to ${MAX_PLAIN_TEXT_INTERACTION_CHARS} characters.`,
    );
    expect(analysis.links.map((link) => link.normalizedUrl)).not.toContain("https://after-text-limit.example/path");
  });

  it("marks excess plain-text destinations incomplete instead of silently stopping at the exact limit", () => {
    const text = Array.from(
      { length: MAX_HTML_INTERACTION_LINKS + 1 },
      (_, index) => `https://plain-${index}.example/path`,
    ).join(" ");
    const analysis = analyzeHtmlInteractions("", text);

    expect(analysis.links).toHaveLength(MAX_HTML_INTERACTION_LINKS);
    expect(analysis.incomplete).toBe(true);
    expect(analysis.incompleteReasons).toContain(
      `Message interaction inspection was limited to ${MAX_HTML_INTERACTION_LINKS} destinations.`,
    );
  });

  it("decodes security-relevant named entities without executing markup", () => {
    const analysis = analyzeHtmlInteractions(
      '<a href="https&colon;&sol;&sol;evil&period;example&sol;login">https&colon;&sol;&sol;bank&period;example</a>',
      null,
    );

    expect(analysis.links[0]).toMatchObject({
      normalizedUrl: "https://evil.example/login",
      visibleText: "https://bank.example",
    });
  });
});
