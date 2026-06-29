// Orchestrates the airlock. The extractor only ever receives the fenced text
// and the channel name — never provenance, secrets, or trusted state.
import { fence } from './fence.mjs';
import { innerDoor } from './validator.mjs';

const DEFAULT_MAX_BATCH = 100;

// probeResult: { channel, provenance: { url, fetched_at }, raw }
export function runAirlockItem(probeResult, extractor) {
  const fenced = fence(probeResult.raw);
  const extractorOutput = extractor({
    fencedText: fenced.text,
    provenanceChannel: probeResult.channel,
  });
  return innerDoor(extractorOutput, probeResult.provenance);
}

// Batch with a hard volume cap so a flood can't bury the queue (DoS containment).
export function runAirlockBatch(probeResults, extractor, { maxBatch = DEFAULT_MAX_BATCH } = {}) {
  const capped = probeResults.slice(0, maxBatch);
  const dropped = Math.max(0, probeResults.length - capped.length);
  const digests = [];
  const rejected = [];
  for (const pr of capped) {
    const r = runAirlockItem(pr, extractor);
    if (r.ok) digests.push(r.digest);
    else rejected.push({ provenance: pr.provenance, reason: r.reason });
  }
  return { digests, rejected, dropped };
}
