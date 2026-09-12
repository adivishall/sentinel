# Architecture

```
             cardholder submission (UNTRUSTED)
                        │
        ┌───────────────▼────────────────┐
        │  L1  Provenance tagging         │  wrap + label as data
        └───────────────┬────────────────┘
        ┌───────────────▼────────────────┐
        │  L2  Injection detection        │  score untrusted span;
        └───────────────┬────────────────┘  block early, name the trigger
                        │
        ┌───────────────▼────────────────┐
        │      back-office LLM agent       │  runs on the SANITISED prompt
        │   (dispute_triage / kyb_review)  │
        └───────────────┬────────────────┘
        ┌───────────────▼────────────────┐
        │  L3  Structured adjudication ★  │  decide on VERIFIED facts only;
        └───────────────┬────────────────┘  attacker prose never reaches here
        ┌───────────────▼────────────────┐
        │  L4  Capability limits          │  hard-gate irreversible / high value
        └───────────────┬────────────────┘
                        ▼
                final effect + full audit trail
```

## Why layer 3 is the core idea

Layers 1–2 fight *injection*. But the honest threat is **adjudication gaming**: a
narrative with no injection at all, written purely to exploit the decision model's
heuristics (loyalty, urgency, sympathy). No detector catches that, because there
is nothing anomalous in the text.

Sentinel defeats it by construction. The authoritative decision is never made over
the narrative. We extract **structured facts from the bank's own trusted records**
(`delivery_status`, `duplicate_confirmed`, `amount`, `policy_auto_limit`, …) and a
second adjudicator decides using only those. The claim must be backed by verified
evidence. The attacker can write anything; it changes no fact the adjudicator sees.

## Trust boundary

- **Trusted:** system prompt, bank ledger facts.
- **Untrusted:** cardholder narrative, uploaded documents, merchant-supplied copy.

The whole design is an enforcement of that one boundary. `Observation` given to the
adjudicator carries facts, not prose — so the boundary is structural, not a matter
of the model "being careful".

## Dual mode

`llm.py` routes completions. Live: Claude. Offline: a deterministic simulator that
models the failure mode faithfully (obeys in-context imperatives / authority claims).
The **firewall is identical in both modes** — only the agent's cognition is swapped.

## The trust boundary as types (`firewall/trust.py`)

The boundary above is not just a convention — it is a type contract mypy checks:

- `UntrustedText` — attacker-controllable text. Opaque: it yields only a coarse
  `ClaimType` and a content hash. It has **no** accessor that returns evidence.
- `TrustedFacts` → `DisputeFacts` / `KYBFacts` — immutable records built only from
  the bank/acquirer data. `supports(ClaimType) -> bool` is the sole evidence check
  and is a pure function of the trusted facts; the `ClaimType` only selects *which*
  field to read, it never supplies evidence.

So you cannot pass a narrative where evidence is expected. `tests/test_trust_boundary.py`
proves prose cannot flip a verdict and never reaches the adjudicator's input.

## The canonical Decision + audit (`firewall/pipeline.py`, `audit.py`)

Every evaluation produces one serialisable `Decision` (request_id, session_id,
surface, input_hash, threat_level, detection, agent_result, adjudication,
capability_decision, final_action, reason, model metadata, timestamp, audit_id,
full trail). The **same object** drives the CLI, the HTTP API response, the audit
trail and test assertions — no parallel representations. `audit.py` appends one
JSON-lines event per decision (opt-in), storing a **hash** of the raw submission,
never the prose.

## Layer 4 as a policy engine (`firewall/limits.py`)

Capability limits are a small data-driven policy engine with explainable outcomes
— `ALLOW` / `REQUIRE_HUMAN_REVIEW` / `BLOCK` — considering action type, amount,
reversibility and risk. The first matching non-ALLOW rule transforms the effect
and records a human-readable reason (e.g. "Auto-refund ₹X exceeds ₹Y auto-limit").

## Multi-turn sessions (`firewall/session.py`)

A `Session` accumulates untrusted turns and re-evaluates the **whole transcript**
against the fixed trusted ledger each turn, tracking a cumulative risk level. A
payload split across turns is visible at the transcript level, and L3 still decides
on facts — so security never depends on the attack being in the latest message.

## Application surface (`sentinel_api.py`)

A zero-dependency stdlib HTTP API wraps the same pipeline: `POST /api/evaluate`
(dispute + KYB, optional untrusted `document`, optional multi-turn `messages`),
`GET /health`, `GET /version`, `GET /api/audit/<id>`. See [API.md](API.md).
