// Dumb intake — the untrusted zone in front of a public intake endpoint.
//
// This is what sits behind the public POST endpoint. It is deliberately stupid:
// no agent, no secrets, no LLM, no interpretation of the message. It validates
// the ENVELOPE SHAPE and SIZE only, stamps provenance the sender cannot forge,
// and hands a queue record to the append-only log. The message `body` is opaque
// here and stays untrusted all the way to the airlock, which fences it.
//
// Trust rule: every field the downstream pipeline trusts (seq, received_at,
// src_ip_hash) is supplied by US via `meta`. Nothing the sender puts in the
// envelope can override those — the envelope is nested, never spread.

export const ENVELOPE_VERSION = 'airlock.message/v0';
export const DEFAULT_MAX_BODY_BYTES = 16384; // matches the manifest's intake.max_bytes

const isStr = (x) => typeof x === 'string';
const isOptStr = (x) => x === undefined || typeof x === 'string';

// Pure: validate the raw POST body. Returns { ok, envelope, reason }.
// The body is NOT sanitized here (that is the airlock's job); we only gate
// shape and size so a malformed or oversized payload never reaches the queue.
export function validateEnvelope(rawBody, { maxBytes = DEFAULT_MAX_BODY_BYTES } = {}) {
  if (!isStr(rawBody)) return { ok: false, envelope: null, reason: 'body not a string' };

  const bytes = Buffer.byteLength(rawBody, 'utf8');
  if (bytes === 0) return { ok: false, envelope: null, reason: 'empty body' };
  if (bytes > maxBytes) return { ok: false, envelope: null, reason: `oversized (${bytes}>${maxBytes})` };

  let env;
  try {
    env = JSON.parse(rawBody);
  } catch {
    return { ok: false, envelope: null, reason: 'not valid JSON' };
  }
  if (!env || typeof env !== 'object' || Array.isArray(env)) {
    return { ok: false, envelope: null, reason: 'not an object' };
  }
  if (env.v !== ENVELOPE_VERSION) return { ok: false, envelope: null, reason: 'bad envelope version' };
  if (!isStr(env.body) || env.body.length === 0) return { ok: false, envelope: null, reason: 'missing body' };
  if (!isOptStr(env.from)) return { ok: false, envelope: null, reason: 'from not a string' };
  if (!isOptStr(env.reply_to)) return { ok: false, envelope: null, reason: 'reply_to not a string' };
  if (!isOptStr(env.sent_at)) return { ok: false, envelope: null, reason: 'sent_at not a string' };
  if (!isOptStr(env.sig)) return { ok: false, envelope: null, reason: 'sig not a string' };

  // Reconstruct the envelope from known keys only — drop anything the sender
  // tried to smuggle in (e.g. a forged `seq` / `received_at` / `provenance`).
  const envelope = {
    v: ENVELOPE_VERSION,
    from: env.from ?? null,
    reply_to: env.reply_to ?? null,
    body: env.body,
    sent_at: env.sent_at ?? null,
    ...(env.sig !== undefined ? { sig: env.sig } : {}),
  };
  return { ok: true, envelope, reason: null };
}

// Pure: build the queue record. TRUSTED fields come from `meta` only; the
// untrusted envelope is nested under `envelope` and can never poison them.
export function stampRecord(envelope, meta) {
  return {
    seq: meta.seq,
    received_at: meta.received_at,
    src_ip_hash: meta.src_ip_hash ?? null,
    envelope,
  };
}

// Stateful, dependency-free rate/volume guard. Time is injected (meta.now) so it
// is deterministic in tests and resume-safe. Caps both a global window and a
// per-source window — abuse containment, mirroring runAirlockBatch's volume cap.
export function createRateLimiter({ windowMs = 60000, maxPerWindow = 120, maxPerSource = 20 } = {}) {
  let windowStart = null;
  let globalCount = 0;
  const perSource = new Map();

  return function allow(srcKey, now) {
    if (windowStart === null || now - windowStart >= windowMs) {
      windowStart = now;
      globalCount = 0;
      perSource.clear();
    }
    if (globalCount >= maxPerWindow) return { allowed: false, reason: 'global rate cap' };
    const n = perSource.get(srcKey) ?? 0;
    if (n >= maxPerSource) return { allowed: false, reason: 'source rate cap' };
    globalCount += 1;
    perSource.set(srcKey, n + 1);
    return { allowed: true, reason: null };
  };
}
