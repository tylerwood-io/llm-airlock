// Tests for the hardened edge server. Load-bearing
// invariants:
//   1. Surface is exactly two routes; everything else is 405.
//   2. Oversized bodies are killed at the socket (413) before buffering whole.
//   3. Wrong content-type on intake is refused (415).
//   4. Rejections leak a status code ONLY, never the validation reason.
//   5. Rate/volume backpressure maps to 429; other rejects to 400.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { rmSync, existsSync } from 'node:fs';
import { request } from 'node:http';

import {
  classifyRoute,
  statusForReject,
  createEdgeServer,
  MANIFEST_PATH,
} from '../src/intake/edge.mjs';
import { createIntake } from '../src/intake/queue.mjs';
import { ENVELOPE_VERSION } from '../src/intake/intake.mjs';

const T0 = Date.parse('2026-06-17T22:00:00Z');
const goodBody = (over = {}) =>
  JSON.stringify({ v: ENVELOPE_VERSION, from: 'a stranger', body: 'is this you?', ...over });

// --- Pure routing/policy helpers (no socket) ---

test('classifyRoute serves only POST /intake and GET the manifest', () => {
  assert.equal(classifyRoute('POST', '/intake'), 'intake');
  assert.equal(classifyRoute('POST', '/intake?x=1'), 'intake'); // query ignored
  assert.equal(classifyRoute('GET', MANIFEST_PATH), 'manifest');
  assert.equal(classifyRoute('GET', '/intake'), null);   // wrong verb
  assert.equal(classifyRoute('POST', '/'), null);        // wrong path
  assert.equal(classifyRoute('DELETE', '/intake'), null);
  assert.equal(classifyRoute('GET', '/../etc/passwd'), null);
});

test('statusForReject maps backpressure to 429, everything else to opaque 400', () => {
  assert.equal(statusForReject('global rate cap'), 429);
  assert.equal(statusForReject('source rate cap'), 429);
  assert.equal(statusForReject('queue full'), 429);
  assert.equal(statusForReject('not valid JSON'), 400);
  assert.equal(statusForReject('oversized (9>8)'), 400);
  assert.equal(statusForReject(null), 400);
});

// --- Live round-trip against an ephemeral server ---

function freshQueue(name) {
  const p = join(tmpdir(), `airlock-edge-${name}.jsonl`);
  if (existsSync(p)) rmSync(p);
  return p;
}

// Spin up the edge on an ephemeral port, run fn(port), then close. `accept` and
// limits are injected so each test gets an isolated, deterministic server.
async function withEdge({ accept, manifest, limits }, fn) {
  const server = createEdgeServer({ accept, manifest, now: () => T0, limits });
  await new Promise((res) => server.listen(0, '127.0.0.1', res));
  const { port } = server.address();
  try {
    return await fn(port);
  } finally {
    await new Promise((res) => server.close(res));
  }
}

// Minimal HTTP client: resolves { status } (and body for GET). Sends `body` raw.
function hit(port, { method = 'POST', path = '/intake', headers = {}, body = '' } = {}) {
  return new Promise((resolve, reject) => {
    const req = request(
      { host: '127.0.0.1', port, method, path, headers: { 'content-type': 'application/json', ...headers } },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => resolve({ status: res.statusCode, body: data }));
      },
    );
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

test('happy path: valid POST is accepted (202) and lands in the queue', async () => {
  const p = freshQueue('happy');
  const accept = createIntake({ queuePath: p });
  await withEdge({ accept }, async (port) => {
    const r = await hit(port, { body: goodBody() });
    assert.equal(r.status, 202);
    assert.equal(r.body, '', 'success leaks no body');
  });
  // Exactly one record landed.
  const { readFileSync } = await import('node:fs');
  assert.equal(readFileSync(p, 'utf8').trim().split('\n').length, 1);
  rmSync(p);
});

test('wrong method and wrong path are 405; manifest GET is served', async () => {
  const manifest = { schema: 'airlock.manifest/v0', kind: 'agent-mediated-inbound' };
  await withEdge({ accept: () => ({ accepted: true }), manifest }, async (port) => {
    assert.equal((await hit(port, { method: 'GET', path: '/intake' })).status, 405);
    assert.equal((await hit(port, { method: 'POST', path: '/' })).status, 405);
    const m = await hit(port, { method: 'GET', path: MANIFEST_PATH });
    assert.equal(m.status, 200);
    assert.deepEqual(JSON.parse(m.body), manifest);
  });
});

test('wrong content-type on intake is refused (415)', async () => {
  await withEdge({ accept: () => ({ accepted: true }) }, async (port) => {
    const r = await hit(port, { headers: { 'content-type': 'text/plain' }, body: goodBody() });
    assert.equal(r.status, 415);
  });
});

test('oversized body is killed at the socket (413)', async () => {
  // accept() should never even be called — the socket cap fires first.
  let accCalls = 0;
  const accept = () => { accCalls += 1; return { accepted: true }; };
  await withEdge({ accept, limits: { maxBodyBytes: 64 } }, async (port) => {
    const r = await hit(port, { body: 'x'.repeat(5000) });
    assert.equal(r.status, 413);
  });
  assert.equal(accCalls, 0, 'oversized stream must not reach accept()');
});

test('rejections leak only a status code; backpressure is 429, bad input 400', async () => {
  await withEdge({ accept: () => ({ accepted: false, reason: 'global rate cap' }) }, async (port) => {
    const r = await hit(port, { body: goodBody() });
    assert.equal(r.status, 429);
    assert.equal(r.body, '', 'rejection must not echo the reason');
  });
  await withEdge({ accept: () => ({ accepted: false, reason: 'not valid JSON' }) }, async (port) => {
    const r = await hit(port, { body: '{bad' });
    assert.equal(r.status, 400);
    assert.equal(r.body, '');
  });
});
