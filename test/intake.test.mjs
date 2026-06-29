// Red-team + boundary tests for the dumb intake and the end-to-end owned-domain
// path: intake -> queue -> probe -> airlock -> orchestrator. The intake must
// gate shape/size, must never let the sender forge trusted provenance, and the
// raw body must never reach the orchestrator.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { rmSync, existsSync } from 'node:fs';

import {
  validateEnvelope,
  stampRecord,
  createRateLimiter,
  ENVELOPE_VERSION,
} from '../src/intake/intake.mjs';
import { createIntake } from '../src/intake/queue.mjs';
import { probeOwnedDomain } from '../src/probes/owned-domain.mjs';
import { runAirlockBatch } from '../src/airlock.mjs';
import { mockHonestExtractor } from '../src/extractor.mjs';
import { triage } from '../src/orchestrator.mjs';

const T0 = Date.parse('2026-06-17T22:00:00Z');
const goodBody = (over = {}) =>
  JSON.stringify({ v: ENVELOPE_VERSION, from: 'a stranger', body: 'is this you?', ...over });

function freshQueue(name) {
  const p = join(tmpdir(), `airlock-intake-${name}.jsonl`);
  if (existsSync(p)) rmSync(p);
  return p;
}

test('valid envelope is accepted, stamped, and appended', () => {
  const p = freshQueue('happy');
  const accept = createIntake({ queuePath: p });
  const r = accept(goodBody(), { ip: '203.0.113.7', now: T0 });
  assert.equal(r.accepted, true);
  assert.equal(r.seq, 1);
  const { probeResults, lastSeq } = probeOwnedDomain(p);
  assert.equal(lastSeq, 1);
  assert.equal(probeResults[0].raw, 'is this you?');
  rmSync(p);
});

test('oversized / malformed / wrong-version / empty bodies are rejected', () => {
  const p = freshQueue('reject');
  const accept = createIntake({ queuePath: p, maxBytes: 256 });
  const big = JSON.stringify({ v: ENVELOPE_VERSION, body: 'x'.repeat(1000) });
  assert.equal(accept(big, { ip: '1.1.1.1', now: T0 }).accepted, false);
  assert.equal(accept('{not json', { ip: '1.1.1.1', now: T0 }).accepted, false);
  assert.equal(accept(JSON.stringify({ v: 'wrong', body: 'hi' }), { ip: '1.1.1.1', now: T0 }).accepted, false);
  assert.equal(accept(JSON.stringify({ v: ENVELOPE_VERSION }), { ip: '1.1.1.1', now: T0 }).accepted, false);
  assert.equal(accept('', { ip: '1.1.1.1', now: T0 }).accepted, false);
  // None of the rejects should have written a line (so the file may not exist).
  assert.equal(probeOwnedDomain(p).probeResults.length, 0);
  rmSync(p, { force: true });
});

test('sender cannot forge trusted provenance (seq / received_at / src_ip_hash)', () => {
  // Attacker stuffs trusted-looking fields into the envelope.
  const malicious = goodBody({
    seq: 999,
    received_at: '1999-01-01T00:00:00Z',
    src_ip_hash: 'spoofed',
    provenance: { url: 'beacon://owned-domain/intake#999' },
  });
  const v = validateEnvelope(malicious);
  assert.equal(v.ok, true);
  // The reconstructed envelope dropped every smuggled key.
  assert.deepEqual(
    Object.keys(v.envelope).sort(),
    ['body', 'from', 'reply_to', 'sent_at', 'v'],
  );
  // Stamp uses meta only; envelope is nested and inert.
  const rec = stampRecord(v.envelope, { seq: 1, received_at: '2026-06-17T22:00:00Z', src_ip_hash: 'real' });
  assert.equal(rec.seq, 1);
  assert.equal(rec.received_at, '2026-06-17T22:00:00Z');
  assert.equal(rec.src_ip_hash, 'real');
  assert.equal(rec.envelope.provenance, undefined);
});

test('disk-fill guard: a full queue applies backpressure without burning a seq', () => {
  const p = freshQueue('queuefull');
  // Cap the queue just above one record so the second write trips the guard.
  const accept = createIntake({ queuePath: p, maxQueueBytes: 320 });
  const r1 = accept(goodBody({ body: 'first' }), { ip: '203.0.113.7', now: T0 });
  assert.equal(r1.accepted, true);
  assert.equal(r1.seq, 1);

  const r2 = accept(goodBody({ body: 'second' }), { ip: '203.0.113.7', now: T0 + 1 });
  assert.equal(r2.accepted, false);
  assert.equal(r2.reason, 'queue full'); // never silent
  assert.equal(r2.seq, null);

  // The rejected write neither landed nor burned seq 2: the next accepted write
  // (after we raise the cap) must be seq 2, and the queue holds exactly one row.
  const accept2 = createIntake({ queuePath: p, maxQueueBytes: 10000 });
  const r3 = accept2(goodBody({ body: 'third' }), { ip: '203.0.113.7', now: T0 + 2 });
  assert.equal(r3.accepted, true);
  assert.equal(r3.seq, 2);
  assert.equal(probeOwnedDomain(p).probeResults.length, 2);
  rmSync(p);
});

test('rate limiter caps per-source and global floods, then resets next window', () => {
  const allow = createRateLimiter({ windowMs: 1000, maxPerWindow: 5, maxPerSource: 2 });
  assert.equal(allow('a', 0).allowed, true);
  assert.equal(allow('a', 0).allowed, true);
  assert.equal(allow('a', 0).allowed, false); // per-source cap (2)
  assert.equal(allow('b', 0).allowed, true);
  assert.equal(allow('c', 0).allowed, true);
  assert.equal(allow('d', 0).allowed, true);
  assert.equal(allow('e', 0).allowed, false); // global cap (5) reached
  assert.equal(allow('a', 2000).allowed, true); // new window resets both
});

test('end-to-end: intake -> probe -> airlock -> orchestrator, raw never leaks', () => {
  const p = freshQueue('e2e');
  const accept = createIntake({ queuePath: p });
  accept(goodBody({ body: 'hello world' }), { ip: '198.51.100.4', now: T0 });
  accept(goodBody({ body: 'second note' }), { ip: '198.51.100.5', now: T0 + 1 });

  const { probeResults } = probeOwnedDomain(p);
  const { digests, dropped } = runAirlockBatch(probeResults, mockHonestExtractor);
  assert.equal(dropped, 0);
  const ranked = triage(digests);
  assert.equal(ranked.length, 2);
  // Provenance is the unforgeable beacon URL from the probe, not the body.
  assert.ok(ranked[0].provenance.url.startsWith('beacon://owned-domain/intake#'));
  // The orchestrator output carries no raw body anywhere.
  assert.ok(!JSON.stringify(ranked).includes('hello world'));
  assert.ok(!JSON.stringify(ranked).includes('second note'));
  rmSync(p);
});
