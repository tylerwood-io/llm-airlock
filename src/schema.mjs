// The digest schema + a strict validator. Pure, no dependencies, un-injectable.

export const RISK_FLAGS = new Set([
  'injection_attempt',
  'exfil_lure',
  'consent_concern',
  'spam',
  'malware_link',
  'impersonation',
]);

const isStr = (x) => typeof x === 'string';

export function validateDigest(obj) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
    return { ok: false, errors: ['not an object'], value: null };
  }
  const errors = [];

  if (!isStr(obj.source_channel) || obj.source_channel.length === 0) errors.push('source_channel');
  if (!(obj.apparent_sender === null || isStr(obj.apparent_sender))) errors.push('apparent_sender');
  if (!isStr(obj.claimed_intent)) errors.push('claimed_intent');

  const c = obj.addressed_to_principal_confidence;
  if (typeof c !== 'number' || Number.isNaN(c) || c < 0 || c > 1) {
    errors.push('addressed_to_principal_confidence');
  }

  if (!Array.isArray(obj.identifiers_found) || obj.identifiers_found.some((x) => !isStr(x))) {
    errors.push('identifiers_found');
  }
  if (!Array.isArray(obj.links_defanged) || obj.links_defanged.some((x) => !isStr(x))) {
    errors.push('links_defanged');
  }
  if (!Array.isArray(obj.risk_flags) || obj.risk_flags.some((x) => !RISK_FLAGS.has(x))) {
    errors.push('risk_flags');
  }
  if (!isStr(obj.neutral_summary)) errors.push('neutral_summary');

  if (errors.length) return { ok: false, errors, value: null };
  return { ok: true, errors: [], value: obj };
}
