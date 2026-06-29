// Trust-boundary guarantees: the extractor never sees secrets/provenance, the
// orchestrator never sees raw, and the honest end-to-end path works.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { runAirlockItem } from '../src/airlock.mjs';
import { mockHonestExtractor } from '../src/extractor.mjs';
import { triage, assertNoRaw } from '../src/orchestrator.mjs';

const PROV = { url: 'https://feed.example/note1', fetched_at: '2026-06-17T20:00:00Z' };
const probe = (raw, channel = 'feed') => ({ channel, provenance: PROV, raw });

test('extractor receives only fenced text + channel, never provenance/secrets', () => {
  let captured = null;
  const spy = (args) => {
    captured = args;
    return mockHonestExtractor(args);
  };
  runAirlockItem(probe('hello'), spy);
  assert.deepEqual(Object.keys(captured).sort(), ['fencedText', 'provenanceChannel']);
  assert.ok(!JSON.stringify(captured).includes(PROV.url));
});

test('orchestrator throws if a digest smuggles a raw field', () => {
  const tainted = {
    source_channel: 'feed',
    apparent_sender: null,
    neutral_summary: 'hi',
    addressed_to_principal_confidence: 0,
    risk_flags: [],
    links_defanged: [],
    raw: 'gotcha',
  };
  assert.throws(() => assertNoRaw(tainted), /boundary violation/);
});

test('honest end-to-end path produces a clean, triaged digest', () => {
  const r = runAirlockItem(probe('hello world'), mockHonestExtractor);
  assert.equal(r.ok, true);
  const ranked = triage([r.digest]);
  assert.equal(ranked.length, 1);
  assert.equal(ranked[0].provenance.url, PROV.url);
  assert.equal(ranked[0].needs_human, false);
});

test('orchestrator exposes no outbound/act function', async () => {
  const mod = await import('../src/orchestrator.mjs');
  const exported = Object.keys(mod);
  for (const name of exported) {
    assert.ok(!/send|reply|post|act|engage|execute/i.test(name), `unexpected outbound fn: ${name}`);
  }
});
