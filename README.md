# Airlock

A fail-closed pipeline for feeding **untrusted content to LLM agents** — social
feeds, forums, web pages, inbound messages — without ever exposing a privileged
context to prompt injection, data exfiltration, or consent violations.

Raw inbound content never touches a context that can act, remember, or leak. It
is decontaminated in an **airlock** first; only a structured, sanitized **digest**
passes the inner door to the trusted side (and then to a human, who makes every
outbound decision).

```
  UNTRUSTED ZONE                                     |  TRUSTED ZONE
                                                     |
[source] -> Probe --raw--> [ AIRLOCK ] --digest--> Validator -> Orchestrator -> Human
           (dumb fetch,    (tool-less,             (pure code:   (consumes only   (all outbound
            read-only,      memory-less,            schema +      digests, never   decisions)
            provenance)     "data != instructions"  defang +      raw)
                            extractor)              caps)        |
                                                     |
        everything left of the inner door is assumed hostile  ←┘
```

## Why

Anything that puts model output back into a context that can take actions is a
prompt-injection target. The usual mitigations — "ask the model nicely not to
follow injected instructions," output filtering, allow-lists — all depend on the
model behaving. Airlock assumes the **extractor model is fully compromised** and
still holds the line, because the guarantees are enforced by *code* on the far
side of it, not by the model's good behavior.

## Design

- **The extractor is the only LLM, and it is powerless.** No tools, no memory, no
  secrets, no network. Its sole job is to read fenced, untrusted text and emit a
  strict JSON digest. If it is jailbroken, it can only emit *bad JSON* — which the
  next stage rejects.
- **The inner door is pure code.** It parses the extractor's output, schema-checks
  it, neutralizes it (URL defang, length caps, hidden/bidi/control-char stripping),
  and reconstructs the digest field-by-field so injected fields are dropped.
- **Provenance is stamped by the probe, never the model.** A compromised extractor
  cannot forge where a message came from.
- **The trusted side has no way to act.** The orchestrator consumes digests, ranks
  and flags them for a human, and *throws* if any raw payload ever reaches it.
  There is no send/act function on the trusted side by design.

## Threat model

**Trust boundary.** The split is the inner door (the validator). Everything to its
left — the raw content *and the extractor model that reads it* — is assumed hostile.
Everything to its right is trusted precisely because the only thing that can cross
is a reconstructed, schema-valid digest with provenance the model never touched.

**Core assumption.** We do not assume the extractor behaves. We assume it is fully
adversary-controlled — jailbroken, emitting whatever an attacker wants. Every
guarantee below is enforced by deterministic code *after* the model, so the
model's compliance is never load-bearing.

| Adversary | Capability | Primary mitigation |
|-----------|-----------|--------------------|
| **Injection author** | Crafts message `body` to hijack the model or break out of the fence | Nonce-delimited fences + "data ≠ instructions" prompt — but ultimately the *deterministic inner door*, which doesn't care whether the model fell for it |
| **Compromised extractor** | Emits arbitrary attacker-controlled output (assume fully popped) | Schema validation, field-by-field digest reconstruction (drops injected fields), URL defang, hidden/bidi/control-char stripping, provenance taken from the probe |
| **Forger** | Tries to forge provenance or other trust signals | Provenance is stamped by the probe/intake at receive time; senders and the model cannot forge `seq` / `received_at` / source hash |
| **Flooder / DoS** | Volume floods, oversized bodies, slow-drip connections | Batch volume caps (reported, never silently truncated), socket-level body cap, per-source + global rate limiting, append-queue disk-fill backpressure |
| **Exfiltration** | Tries to route data out through a digest field or the trusted side | Extractor has no network/tools; the orchestrator has no send/act function and throws if raw ever reaches it |

**Explicitly out of scope.** The library does **not** promise the extractor
extracts *well* — only that a bad extractor cannot escalate. Also out of scope:
TLS-layer interception, supply-chain compromise of Node or its toolchain, and
physical access to the host. The promise is narrow and total: **a fully
compromised extractor cannot do anything worse than emit a digest the inner door
rejects.**

## Components (`src/`)

- `fence.mjs` — wrap raw content in nonce-delimited UNTRUSTED fences; neutralize forged delimiters.
- `extractor.mjs` — the LLM seam: hardened system prompt + test doubles (honest / fully-compromised).
- `live-extractor.mjs` — a real extractor seam shelling out to a sandboxed, tool-less model process.
- `schema.mjs` — the digest schema + strict validator.
- `sanitize.mjs` — model-free neutralization: URL defang, length caps, hidden/bidi char stripping.
- `validator.mjs` — the inner door: parse untrusted output, schema-check, neutralize, attach TRUSTED provenance.
- `airlock.mjs` — orchestrates one item or a batch (with volume cap / DoS containment).
- `orchestrator.mjs` — trusted side: consumes digests, ranks, flags for a human. Fails closed if raw leaks.
- `redteam.mjs` — adversarial harness driving live injection attempts through the full pipeline.
- `intake/` — an optional hardened HTTP front door (`edge.mjs`) + dumb append-only queue (`intake.mjs`, `queue.mjs`) for inbound-message sources.
- `probes/owned-domain.mjs` — example probe: reads an inbound queue and emits the `probeResult[]` the airlock consumes.

## What the tests prove

28 tests, four suites, zero dependencies (`node --test`). They are written as
*guarantees*, not coverage — each asserts a boundary the pipeline must hold even
when the model is hostile.

**`adversarial.test.mjs` — the extractor is fully compromised and emits attacker output:**
- non-JSON output is rejected, not passed downstream
- output missing required fields is rejected
- injected extra fields (`raw`, `instructions`, …) are dropped by reconstruction
- live URLs are defanged (`https://evil.example` → `hxxps://evil[.]example`)
- oversized free text is length-capped and hidden/control chars stripped
- the extractor cannot forge provenance — it is overwritten from the probe
- made-up / invalid risk flags are rejected
- out-of-range confidence values are rejected
- a volume flood is capped **and reported**, never silently dropped
- hidden / homoglyph chars are stripped from extracted identifiers
- a payload cannot forge the fence delimiters to break out of the untrusted zone

**`boundary.test.mjs` — trust-zone separation holds:**
- the extractor receives only fenced text + channel — never provenance or secrets
- the orchestrator *throws* if a digest smuggles a raw field across the door
- the honest end-to-end path still produces a clean, triaged digest
- the orchestrator exposes no outbound / act function at all

**`intake.test.mjs` — the dumb intake and end-to-end inbound path:**
- a valid envelope is accepted, stamped, and appended
- oversized / malformed / wrong-version / empty bodies are rejected
- a sender cannot forge trusted provenance (`seq` / `received_at` / source hash)
- the disk-fill guard applies backpressure on a full queue without burning a seq
- the rate limiter caps per-source and global floods, then resets next window
- full path `intake → queue → probe → airlock → orchestrator` — raw never leaks

**`edge.test.mjs` — the hardened HTTP edge:**
- the surface is exactly two routes (`POST /intake`, `GET` the manifest); all else is 405
- oversized bodies are killed at the socket (413) before buffering the whole thing
- wrong content-type on intake is refused (415)
- rejections leak only a status code — backpressure is 429, bad input an opaque 400
- a valid POST is accepted (202) and lands in the queue

## Run

```
npm test        # node --test (auto-discovers test/*.test.mjs); zero dependencies
```

Node 20+. No runtime or dev dependencies — `node:` builtins only.

## License

MIT
