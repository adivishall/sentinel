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
