// Owned-domain probe — the dumbest possible reader.
//
// It pulls the append-only intake queue written by the (separate, untrusted)
// intake endpoint and emits the probeResult[] shape the airlock already
// consumes: { channel, provenance, raw }. It does NOT know the selector, does
// NOT filter by target, does NOT touch the network. For owned-domain the
// haystack is small (a single controlled endpoint), so it forwards everything and relies on the
// generic volume cap downstream (runAirlockBatch).
//
// Provenance is taken from the queue RECORD (stamped by intake at receive time),
// never from the message body — the sender cannot forge it. The `body` field is
// untrusted and opaque here; it only ever leaves this module fenced, via the
// airlock.

import { readFileSync, existsSync } from 'node:fs';

const CHANNEL = 'owned-domain';

// One queue line, as written by the intake endpoint:
//   { seq, received_at, src_ip_hash, envelope: { v, from, reply_to, body, sent_at, sig? } }
function recordToProbeResult(rec) {
  return {
    channel: CHANNEL,
    // Trusted provenance: comes from intake, not from the message.
    provenance: {
      url: `beacon://owned-domain/intake#${rec.seq}`,
      fetched_at: rec.received_at,
      src_ip_hash: rec.src_ip_hash ?? null,
      seq: rec.seq,
    },
    // Untrusted, opaque. Forwarded only to be fenced by the airlock.
    raw: rec.envelope?.body ?? '',
  };
}

function parseJsonl(text) {
  const out = [];
  for (const line of text.split('\n')) {
    const t = line.trim();
    if (!t) continue;
    try {
      out.push(JSON.parse(t));
    } catch {
      // A malformed line is dropped, not fatal — intake should never write one,
      // but the probe must never throw on garbage in the untrusted queue.
    }
  }
  return out;
}

// Read the queue, skipping anything at or below `sinceSeq` (dedup / resume).
// Returns { probeResults, lastSeq } so the caller can persist the cursor.
export function probeOwnedDomain(queuePath, { sinceSeq = 0 } = {}) {
  if (!existsSync(queuePath)) return { probeResults: [], lastSeq: sinceSeq };

  const records = parseJsonl(readFileSync(queuePath, 'utf8'))
    .filter((r) => Number.isInteger(r?.seq) && r.seq > sinceSeq)
    .sort((a, b) => a.seq - b.seq);

  const lastSeq = records.length ? records[records.length - 1].seq : sinceSeq;
  return { probeResults: records.map(recordToProbeResult), lastSeq };
}

// Example wiring (kept out of the hot path):
//
//   import { probeOwnedDomain } from './probes/owned-domain.mjs';
//   import { runAirlockBatch } from '../airlock.mjs';
//   import { triage } from '../orchestrator.mjs';
//
//   const { probeResults, lastSeq } = probeOwnedDomain(QUEUE_PATH, { sinceSeq });
//   const { digests, rejected, dropped } = runAirlockBatch(probeResults, extractor);
//   const forHuman = triage(digests);
//   // persist lastSeq; log(dropped) if > 0; never silently truncate.
