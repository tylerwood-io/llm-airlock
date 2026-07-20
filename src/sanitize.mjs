// Deterministic, model-free neutralization applied at the inner door.

// Codepoints that render invisibly (or nearly so) and are used to smuggle
// hidden instructions, spoof identifiers, or reorder rendered text:
//   - Cf (format): zero-width chars, bidi overrides, soft hyphen, Arabic
//     letter mark, word joiner, interlinear annotation anchors, and the whole
//     U+E0000 "Tags" block (the invisible-ASCII smuggling channel).
//   - Cc (control): everything except \t \n \r, which capText collapses as
//     ordinary whitespace.
//   - Variation selectors (U+FE00–FE0F, U+E0100–E01EF): invisible, and a
//     known steganographic carrier.
// Text is NFKC-normalized first, folding fullwidth/compatibility forms
// (e.g. ｐａｙｐａｌ → paypal) so they can't dodge downstream checks.
const HIDDEN = /(?![\t\n\r])[\p{Cf}\p{Cc}\u{FE00}-\u{FE0F}\u{E0100}-\u{E01EF}]/gu;

export function stripHidden(s) {
  return String(s).normalize('NFKC').replace(HIDDEN, '');
}

export function capText(s, n) {
  const t = stripHidden(String(s)).replace(/\s+/g, ' ').trim();
  return t.length > n ? t.slice(0, Math.max(0, n - 1)) + '…' : t;
}

// Cross-script lookalikes of Latin letters (curated from the high-traffic
// rows of the Unicode confusables table: Cyrillic + Greek). Used two ways:
//   - foldConfusables: skeleton for COMPARISON (never for display — a folded
//     "pаypal" renders as "paypal", which HELPS the spoof).
//   - markConfusables: escape for DISPLAY, so a reader sees p{U+0430}ypal and
//     cannot misread the spoof as the real identifier.
const CONFUSABLES = new Map(Object.entries({
  // Cyrillic → Latin
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y',
  'ѕ': 's', 'і': 'i', 'ј': 'j', 'ԁ': 'd', 'ѵ': 'v', 'ѡ': 'w', 'һ': 'h',
  'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O',
  'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X', 'Ѕ': 'S', 'І': 'I', 'Ј': 'J',
  // Greek → Latin
  'ο': 'o', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ρ': 'p', 'τ': 't', 'υ': 'u',
  'α': 'a', 'ε': 'e', 'η': 'n', 'ω': 'w', 'ϲ': 'c', 'ϳ': 'j',
  'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K',
  'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
}));

const CONFUSABLE_CHARS = new RegExp(`[${[...CONFUSABLES.keys()].join('')}]`, 'gu');
const ASCII_LETTER = /[a-z]/i;

// Skeleton fold, for comparing an identifier against a known-good one.
export function foldConfusables(s) {
  return String(s).replace(CONFUSABLE_CHARS, (c) => CONFUSABLES.get(c));
}

// Display defense for spoofable surfaces (identifiers, URLs). If a string
// mixes ASCII letters with Latin-lookalike characters — the signature of a
// homoglyph spoof — every lookalike is rewritten as an explicit {U+XXXX}
// escape so it can't be visually mistaken for the real thing. Pure
// non-Latin strings (a legitimately Cyrillic handle) stay readable.
// Known limitation: whole-script confusables (a spoof written entirely in
// Cyrillic) need a reference set to detect and are documented out of scope.
export function markConfusables(s) {
  const t = String(s);
  if (!ASCII_LETTER.test(t)) return t;
  return t.replace(CONFUSABLE_CHARS, (c) =>
    `{U+${c.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}}`);
}

// Render a URL inert so it can't be auto-followed or clicked from a digest.
// Any scheme's trailing colon is bracketed (javascript:, data:, file:, …),
// http(s) additionally becomes hxxp(s) by convention, dots are broken, and
// mixed-script homoglyphs are made visible.
export function defangUrl(u) {
  return markConfusables(
    stripHidden(String(u))
      .trim()
      .replace(/^([a-z][a-z0-9+.-]*):/i, '$1[:]')
      .replace(/https/gi, 'hxxps')
      .replace(/http/gi, 'hxxp')
      .replace(/\./g, '[.]')
  );
}
