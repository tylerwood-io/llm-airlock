// The inner door. Takes UNTRUSTED extractor output + TRUSTED probe provenance,
// validates against the schema, neutralizes every field, and reconstructs a
// clean digest (dropping any injected extra keys). Provenance is supplied by
// the probe here and can never be set by the extractor.
import { validateDigest } from './schema.mjs';
import { capText, defangUrl } from './sanitize.mjs';

// Real models often wrap JSON in ```json fences or add a stray sentence. The
// extractor output is untrusted text either way, so we locate the JSON object
// rather than demanding the model be perfectly clean. Schema validation below is
// the real gate — anything we parse still has to pass it, so this only adds
// robustness, never trust. Returns a parsed object or null.
function coerceToJson(text) {
  let s = text.trim();
  // Strip a single surrounding markdown code fence if present.
  const fenceMatch = s.match(/^```(?:json)?\s*\n([\s\S]*?)\n```$/i);
  if (fenceMatch) s = fenceMatch[1].trim();
  try {
    return JSON.parse(s);
  } catch {
    // Fall back to the outermost {...} span (handles leading/trailing prose).
    const first = s.indexOf('{');
    const last = s.lastIndexOf('}');
    if (first === -1 || last <= first) return null;
    try {
      return JSON.parse(s.slice(first, last + 1));
    } catch {
      return null;
    }
  }
}

const MAX_SUMMARY = 280;
const MAX_INTENT = 200;
const MAX_CHANNEL = 40;
const MAX_SENDER = 80;
const MAX_IDENT = 80;
const MAX_IDENTS = 20;
const MAX_LINKS = 20;

export function innerDoor(extractorOutputRaw, trustedProvenance) {
  let parsed;
  if (typeof extractorOutputRaw === 'string') {
    parsed = coerceToJson(extractorOutputRaw);
    if (parsed === null) {
      return { ok: false, reason: 'extractor output not valid JSON', digest: null };
    }
  } else {
    parsed = extractorOutputRaw;
  }

  const { ok, errors, value } = validateDigest(parsed);
  if (!ok) return { ok: false, reason: 'schema: ' + errors.join(','), digest: null };

  // Reconstruct from scratch: any injected extra fields are silently dropped.
  const digest = {
    source_channel: capText(value.source_channel, MAX_CHANNEL),
    apparent_sender: value.apparent_sender === null ? null : capText(value.apparent_sender, MAX_SENDER),
    claimed_intent: capText(value.claimed_intent, MAX_INTENT),
    addressed_to_principal_confidence: Math.max(0, Math.min(1, value.addressed_to_principal_confidence)),
    identifiers_found: value.identifiers_found.slice(0, MAX_IDENTS).map((s) => capText(s, MAX_IDENT)),
    links_defanged: value.links_defanged.slice(0, MAX_LINKS).map(defangUrl),
    risk_flags: [...new Set(value.risk_flags)],
    neutral_summary: capText(value.neutral_summary, MAX_SUMMARY),
    provenance: trustedProvenance, // TRUSTED — from the probe, not the extractor.
  };
  return { ok: true, reason: null, digest };
}
