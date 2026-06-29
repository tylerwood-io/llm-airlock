// Deterministic, model-free neutralization applied at the inner door.

// Strip zero-width, bidi-override, and control characters used to smuggle
// hidden instructions or spoof identifiers / homoglyph tricks.
export function stripHidden(s) {
  return String(s)
    .replace(/[​-‏‪-‮⁠-⁯﻿]/g, '')
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
}

export function capText(s, n) {
  const t = stripHidden(String(s)).replace(/\s+/g, ' ').trim();
  return t.length > n ? t.slice(0, Math.max(0, n - 1)) + '…' : t;
}

// Render a URL inert so it can't be auto-followed or clicked from a digest.
export function defangUrl(u) {
  return stripHidden(String(u))
    .trim()
    .replace(/https/gi, 'hxxps')
    .replace(/http/gi, 'hxxp')
    .replace(/\./g, '[.]');
}
