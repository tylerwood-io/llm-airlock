// Append-only JSONL queue + a thin HTTP glue for the intake.
//
// The queue is the only state the untrusted zone holds: a flat, append-only log
// the probe reads. Monotonic seq comes from the existing file so a restart never
// reuses numbers. No DB, no creds — by design.

import { readFileSync, appendFileSync, existsSync, statSync } from 'node:fs';

// Current on-disk size of the queue in bytes (0 if absent). Cheap stat — used by
// the disk-fill guard so an unbounded writer can't fill the edge host's disk.
export function queueBytes(queuePath) {
  try {
    return statSync(queuePath).size;
  } catch {
    return 0; // absent or unreadable -> treat as empty, never throw on intake
  }
}

// Scan the existing queue for the highest seq so we resume monotonically.
export function lastSeqOf(queuePath) {
  if (!existsSync(queuePath)) return 0;
  let max = 0;
  for (const line of readFileSync(queuePath, 'utf8').split('\n')) {
    const t = line.trim();
    if (!t) continue;
    try {
      const seq = JSON.parse(t)?.seq;
      if (Number.isInteger(seq) && seq > max) max = seq;
    } catch {
      // tolerate garbage lines; never throw on the untrusted log
    }
  }
  return max;
}

// Append one record as a single JSONL line.
export function appendRecord(queuePath, record) {
  appendFileSync(queuePath, JSON.stringify(record) + '\n', 'utf8');
}

// Wire validate -> rate-limit -> stamp -> append into one accept() call.
// `deps` injects the impure bits (now, ip hashing, seq source) so the core
// stays testable. Returns { accepted, reason, seq }.
import { validateEnvelope, stampRecord, createRateLimiter, DEFAULT_MAX_BODY_BYTES } from './intake.mjs';

export function createIntake({
  queuePath,
  maxBytes = DEFAULT_MAX_BODY_BYTES,
  maxQueueBytes = 64 * 1024 * 1024, // disk-fill guard: backpressure, never fill disk
  rateLimit = {},
  hashIp = (ip) => ip, // inject a real keyed hash in production
} = {}) {
  const allow = createRateLimiter(rateLimit);
  let seq = lastSeqOf(queuePath);

  return function accept(rawBody, { ip, now }) {
    const srcKey = hashIp(ip ?? 'unknown');
    const gate = allow(srcKey, now);
    if (!gate.allowed) return { accepted: false, reason: gate.reason, seq: null };

    const v = validateEnvelope(rawBody, { maxBytes });
    if (!v.ok) return { accepted: false, reason: v.reason, seq: null };

    // Build the record at the tentative next seq, then run the disk-fill guard
    // BEFORE committing the write. A rejected write must not burn a seq number,
    // so `seq` is only advanced once the append actually lands.
    const record = stampRecord(v.envelope, {
      seq: seq + 1,
      received_at: new Date(now).toISOString(),
      src_ip_hash: srcKey,
    });
    const lineBytes = Buffer.byteLength(JSON.stringify(record) + '\n', 'utf8');
    if (queueBytes(queuePath) + lineBytes > maxQueueBytes) {
      return { accepted: false, reason: 'queue full', seq: null }; // never silent
    }

    appendRecord(queuePath, record);
    seq += 1;
    return { accepted: true, reason: null, seq };
  };
}

// The public HTTP front door lives in ./edge.mjs (createEdgeServer) — a hardened,
// tested module: method/content gates, socket-level body cap, slowloris timeouts,
// and status-only responses. Wire it to this intake's accept() at deploy time:
//
//   import { createEdgeServer } from './src/intake/edge.mjs';
//   import { createIntake } from './src/intake/queue.mjs';
//   const accept = createIntake({ queuePath: './queue.jsonl' });
//   createEdgeServer({ accept, manifest }).listen(8787);
