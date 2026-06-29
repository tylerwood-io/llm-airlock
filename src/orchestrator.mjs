// The trusted side. Consumes ONLY validated digests, ranks them, and flags
// items for human review. Fails closed if any raw payload field appears.
// There is intentionally NO send/reply/act function here: every outbound
// decision happens outside this module, by a human.

const FORBIDDEN_KEYS = new Set(['raw', 'fencedText', 'text', 'payload', 'fenced']);

export function assertNoRaw(digest) {
  if (!digest || typeof digest !== 'object') throw new Error('boundary violation: non-object digest');
  for (const k of Object.keys(digest)) {
    if (FORBIDDEN_KEYS.has(k)) {
      throw new Error(`boundary violation: digest carried raw field "${k}"`);
    }
  }
}

export function triage(digests) {
  digests.forEach(assertNoRaw);
  return [...digests]
    .map((d) => ({
      summary: d.neutral_summary,
      channel: d.source_channel,
      sender: d.apparent_sender,
      confidence: d.addressed_to_principal_confidence,
      flags: d.risk_flags,
      links: d.links_defanged,
      provenance: d.provenance,
      needs_human: d.addressed_to_principal_confidence >= 0.5 || d.risk_flags.length > 0,
    }))
    .sort((a, b) => b.confidence - a.confidence);
}
