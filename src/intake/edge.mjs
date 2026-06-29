// Hardened edge server — the exposed, dumb front door.
//
// This is the only public listener. Its whole job is to terminate the connection,
// enforce the application-layer DoS posture, and hand a raw body to `accept()`
// (the dumb intake). It holds NO secrets, NO store key, NO agent, NO LLM. A fully
// popped edge yields the public queue and nothing else.
//
// Surface is exactly two routes: POST /intake and GET the static manifest. Every
// rejection returns a status code ONLY — never the validation reason — so a prober
// learns nothing about why a payload was refused.

import { createServer } from 'node:http';

export const EDGE_LIMITS = {
  maxBodyBytes: 64 * 1024,    // socket-level hard cap; validateEnvelope re-checks the 16k logical cap
  headersTimeoutMs: 5000,     // slowloris: max time to send headers
  requestTimeoutMs: 10000,    // slowloris: max time to complete the whole request
  keepAliveTimeoutMs: 5000,   // drop idle keep-alive sockets quickly
};

export const MANIFEST_PATH = '/.well-known/agent.json';

// Pure router: classify a request into the only routes we serve. Anything else is
// null -> 405. Query strings are ignored. Testable without a socket.
export function classifyRoute(method, url) {
  const path = String(url || '').split('?')[0];
  if (method === 'POST' && path === '/intake') return 'intake';
  if (method === 'GET' && path === MANIFEST_PATH) return 'manifest';
  return null;
}

// Map an intake rejection reason to a status code WITHOUT leaking it. Rate/volume
// backpressure is 429 (retry-able); everything else is an opaque 400.
export function statusForReject(reason) {
  return /rate cap|queue full/.test(String(reason || '')) ? 429 : 400;
}

// Build the hardened HTTP server. `accept` is the dumb intake's accept(rawBody,
// {ip, now}). `manifest` is the static beacon manifest object (or null -> {}).
// `now` is injected for determinism/resume-safety in tests.
export function createEdgeServer({ accept, manifest = null, now = () => Date.now(), limits = {} } = {}) {
  const L = { ...EDGE_LIMITS, ...limits };

  // Reject a request with a status code only, never a reason. We must NOT read the
  // (possibly hostile) body, but we also must let the response flush before the
  // socket dies — a synchronous req.destroy() here races the write and the client
  // sees ECONNRESET instead of the status. `Connection: close` tells Node to tear
  // the socket down cleanly once the response is on the wire, discarding any
  // unread inbound body without buffering it.
  const reject = (res, code) => res.writeHead(code, { Connection: 'close' }).end();

  const server = createServer((req, res) => {
    const route = classifyRoute(req.method, req.url);

    if (route === null) {
      reject(res, 405);
      return;
    }

    if (route === 'manifest') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(manifest ? JSON.stringify(manifest) : '{}');
      return;
    }

    // intake: gate content-type, then read the body under a hard byte cap so an
    // oversized stream is killed before it is ever buffered whole.
    const ctype = String(req.headers['content-type'] || '').toLowerCase();
    if (!ctype.startsWith('application/json')) {
      reject(res, 415);
      return;
    }

    let body = '';
    let killed = false;
    req.on('data', (chunk) => {
      if (killed) return;
      body += chunk;
      if (Buffer.byteLength(body, 'utf8') > L.maxBodyBytes) {
        killed = true;
        reject(res, 413);
      }
    });
    req.on('end', () => {
      if (killed) return;
      const r = accept(body, { ip: req.socket.remoteAddress, now: now() });
      if (r.accepted) {
        res.writeHead(202).end();
        return;
      }
      res.writeHead(statusForReject(r.reason)).end(); // status only, never the reason
    });
    req.on('error', () => {
      if (killed) return;
      try { res.writeHead(400).end(); } catch { /* socket already gone */ }
    });
  });

  // Slowloris defense at the server level.
  server.headersTimeout = L.headersTimeoutMs;
  server.requestTimeout = L.requestTimeoutMs;
  server.keepAliveTimeout = L.keepAliveTimeoutMs;

  return server;
}
