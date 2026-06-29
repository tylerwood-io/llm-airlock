# Airlock

A fail-closed pipeline for feeding **untrusted content to LLM agents** — social
feeds, forums, web pages, inbound messages — without ever exposing a privileged
context to prompt injection, data exfiltration, or consent violations.

Raw inbound content never touches a context that can act, remember, or leak. It
is decontaminated in an **airlock** first; only a structured, sanitized **digest**
passes the inner door to the trusted side (and then to a human, who makes every
outbound decision).

```
[source] -> Probe --raw--> [ AIRLOCK ] --digest--> Validator -> Orchestrator -> Human
           (dumb fetch,    (tool-less,             (pure code:   (consumes only   (all outbound
            read-only,      memory-less,            schema +      digests, never   decisions)
            provenance)     "data != instructions"  defang +      raw)
                            extractor)              caps)
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

## Fail-closed guarantee (what the tests prove)

Assume the extractor is FULLY compromised and emits attacker-controlled output.
The pipeline still guarantees:

1. Non-JSON / schema-violating output is rejected, not passed.
2. Live URLs are defanged.
3. Free text is length-capped; hidden/bidi/control chars stripped.
4. Provenance comes from the probe, not the extractor — it cannot be forged.
5. Extra/injected fields (e.g. `raw`, `instructions`) are dropped by reconstruction.
6. The orchestrator throws if any raw payload field reaches it.
7. Volume floods are capped and reported, never silently truncated.

## Run

```
npm test        # node --test (auto-discovers test/*.test.mjs); zero dependencies
```

Node 20+. No runtime or dev dependencies — `node:` builtins only.

## License

MIT
