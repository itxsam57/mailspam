/**
 * Produce a comparison-only view of untrusted message text.
 *
 * The original content is never changed or persisted. Compatibility
 * normalization joins full-width forms, format controls are removed, and a
 * deliberately small cross-script map covers Latin-looking Cyrillic/Greek
 * characters commonly used to split security terms. This is not a language
 * transliterator and is intentionally only used by deterministic rules.
 */
const INVISIBLE_FORMAT_CONTROLS = /[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180e\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/gu;

const LATIN_LOOKALIKE_MAP: Readonly<Record<string, string>> = Object.freeze({
  "а": "a", "А": "a", "в": "b", "В": "b", "с": "c", "С": "c",
  "е": "e", "Е": "e", "һ": "h", "Һ": "h", "і": "i", "І": "i",
  "ј": "j", "Ј": "j", "к": "k", "К": "k", "м": "m", "М": "m",
  "н": "h", "Н": "h", "о": "o", "О": "o", "р": "p", "Р": "p",
  "т": "t", "Т": "t", "х": "x", "Х": "x", "у": "y", "У": "y",
  "ѕ": "s", "Ѕ": "s", "ԁ": "d", "Ԁ": "d", "α": "a", "Α": "a",
  "ε": "e", "Ε": "e", "ι": "i", "Ι": "i", "κ": "k", "Κ": "k",
  "ο": "o", "Ο": "o", "ρ": "p", "Ρ": "p", "τ": "t", "Τ": "t",
  "υ": "y", "Υ": "y", "χ": "x", "Χ": "x",
});

export function normalizeSecurityText(value: string): string {
  return value
    .normalize("NFKC")
    .replace(INVISIBLE_FORMAT_CONTROLS, "")
    .replace(/[\u0400-\u052f\u0370-\u03ff]/gu, (character) => LATIN_LOOKALIKE_MAP[character] ?? character)
    .toLocaleLowerCase("und")
    .replace(/[\p{Z}\s]+/gu, " ")
    .trim();
}
