# Sentinel — Technical Report

**An AI firewall for high-stakes back-office LLM agents.**
Mastercard Innovation Challenge @ GFF 2026. All results reproduce with
`make offline` (no API key).

## Abstract

Banks are quietly placing their own LLMs in decision paths — triaging chargebacks,
reviewing merchant onboarding (KYB), drafting AML narratives. These agents read
**attacker-controlled text through legitimate channels** (a dispute narrative, an
uploaded invoice) and can trigger **irreversible effects** such as an auto-refund.
Prompt-injection defences and hardened system prompts address *instructions*
smuggled into that text, but not **adjudication gaming**: a submission with no
injection at all, merely *lying* about the facts. Sentinel is a four-layer control
whose central idea is that the authoritative decision is **never computed from
attacker prose** — it is computed from structured facts held in the bank's own
records. Offline, against 60 attacks across six classes, Sentinel reduces attack
success from **83.3% to 0.0%** with **0.0% false positives**, and on an
independently authored held-out set (unseen wording) it holds **0.0%** attack
success and **0.0%** false positives. An ablation shows detection alone still
leaks 6.7% and that fact-based adjudication (L3) is the load-bearing layer.

## Problem statement

The industry defends against attacks *made with* GenAI (deepfake KYC, synthetic
identities). The neglected exposure is the **defender's own AI**: an agent that is
authorised and trusted, then reads hostile content and acts on it. A single
crafted paragraph can talk a triage agent into a refund that was never owed — no
account is breached; the AI is *persuaded*.

## Threat model

Summarised here; full version in [THREAT_MODEL.md](THREAT_MODEL.md). The adversary
can write arbitrary text/documents through legitimate channels but cannot alter the
bank's records, call tools directly, or breach accounts. Assets: money movement,
merchant onboarding, decision integrity, the audit trail. Six attack classes:
direct injection, authority spoofing, document-borne, rule-citation forgery,
multi-turn escalation, and adjudication gaming (the honest hard case). Explicitly
out of scope: ledger integrity, model/tool compromise, binary document parsing,
and any claim of universal security.

## Design goals

1. The authoritative decision must not read attacker prose.
2. Make the trust boundary enforceable by types, not discipline.
3. Every block must be explainable (name the layer and trigger).
4. Fail safe — unusable or ambiguous input escalates to a human.
5. Reproducible with no API key; identical firewall in offline and live modes.
6. Generalise across surfaces (dispute + KYB) with one architecture.

## Architecture

```
UNTRUSTED submission
   -> L1  Provenance      delimit + label untrusted spans as data
   -> L2  Detection       lexical/structural injection scoring (explainable)
   -> Agent (victim LLM)  runs on the sanitised prompt
   -> L3  Adjudication ★  decide on TRUSTED FACTS only; prose never reaches here
   -> L4  Capability policy  ALLOW / REQUIRE_HUMAN_REVIEW / BLOCK on effects
   -> Final effect + structured audit record
```

Full diagram and rationale in [ARCHITECTURE.md](ARCHITECTURE.md).

## Implementation

- `firewall/normalize.py` — NFKC + homoglyph folding + zero-width stripping;
  validation with a fail-safe (`InvalidSubmission` → escalate).
- `firewall/provenance.py` — L1 wrapping of untrusted spans.
- `firewall/detect.py` — L2, six weighted regex signals, threshold 0.6.
- `firewall/trust.py` — the **structural trust boundary**: `UntrustedText`,
  `DisputeFacts`, `KYBFacts`, `ClaimType`.
- `firewall/adjudicate.py`, `kyb_adjudicate.py` — L3 for each surface.
- `firewall/limits.py` — L4 data-driven capability policy engine.
- `firewall/pipeline.py` — orchestration + the canonical `Decision`.
- `firewall/audit.py`, `firewall/session.py`, `firewall/logging_config.py`.
- `llm.py` — dual-mode client (live Claude | deterministic offline simulator).
- `sentinel_api.py` — zero-dependency HTTP API over the same pipeline.

## The trust boundary

The decision idea is only as strong as the boundary that enforces it, so the
boundary is a **type contract** (see [DECISIONS.md](DECISIONS.md) D2):

- `UntrustedText` is opaque — it yields only a coarse `ClaimType` and a hash. It
  has no accessor that returns evidence.
- `TrustedFacts` (`DisputeFacts` / `KYBFacts`) is immutable and built only from
  records. `supports(ClaimType)` is the sole evidence check and is a pure function
  of the trusted facts; the `ClaimType` only selects *which* field to read.
- The adjudicator is handed the structured facts JSON, never the prose.

`tests/test_trust_boundary.py` proves: changing attacker prose cannot flip a
verdict; the narrative never appears in the adjudicator's input; forged claims and
documents cannot overwrite records; and evidence lives only on `TrustedFacts`.

## Security layers and the attack taxonomy

| Class | Stopped by |
|---|---|
| Direct injection | L2 (caught) → L3 (backstop) |
| Authority spoofing | L2 → L3 |
| Document-borne | L1 (data) → L3 (records) |
| Rule-citation forgery | L2 / L3 |
| Multi-turn escalation | transcript-level L2 → L3 |
| **Adjudication gaming** | **L3 only** |

## Evaluation methodology

Attack success = an irreversible `approve_refund` the records do not support.
False positive = a deserved refund the firewall fails to approve. Metrics are
computed by `eval/harness.py` (dev), `eval/ablation.py`, `eval/baselines.py`,
`eval/kyb_harness.py`, `eval/heldout.py`, `eval/bench.py`. Full write-up:
[EVALUATION.md](EVALUATION.md).

## Results

| Setting | ASR (no firewall) | ASR (Sentinel) | FP |
|---|---:|---:|---:|
| Development corpus (60 attacks, 18 controls) | 83.3% | **0.0%** | **0.0%** |
| Held-out (12 unseen attacks) | 16.7%* | **0.0%** | **0.0%** |
| KYB onboarding (8 attacks, 5 controls) | 87.5% | **0.0%** | **0.0%** |

\* The offline victim agent is itself lexical, so it under-fires on novel wording;
the held-out set validates the firewall's generalisation and false-positive
behaviour, not the unguarded baseline's realism.

## Ablation

| Configuration | ASR | FP |
|---|---:|---:|
| No firewall | 83.3% | 25.0% |
| Detection only (L1+L2+L4) | 6.7% | 25.0% |
| Adjudication only (L3) | 0.0% | 0.0% |
| Full (L1–L4) | 0.0% | 0.0% |

Detection alone leaks the adjudication-gaming attacks; **L3 is necessary and here
sufficient.** Against the "obvious defence", prompt-hardening cuts overall attack
success to 16.7% but fails **100%** on adjudication gaming.

## KYB generalisation

The same four layers defend merchant onboarding via a KYB adjudicator over
verified acquirer records. A document that *says* "review complete, approve" is
rejected because the decision is made on the records, not the document.

## Performance

Firewall overhead only (offline; agent/LLM cognition excluded), 1,560 decisions:
mean ≈ 0.08 ms, p95 ≈ 0.11 ms, ≈ 12k decisions/sec single-core (machine-dependent;
`make bench`). Linear in input size, constant in policy size; no cross-request
state. ~4 orders of magnitude below the 300–2000 ms LLM call it protects. Details:
[PERFORMANCE.md](PERFORMANCE.md).

## Limitations

The offline agent is a simulation; corpora are synthetic and partly templated; L2
is lexical; the ledger is assumed trustworthy; there is no real integration; and
no universal security is claimed. Full list: [LIMITATIONS.md](LIMITATIONS.md).

## Future work

Real ledger/records integration; a learned or hybrid detector for L2 (keeping L3
as the backstop); binary document parsing (PDF/OCR) with the same untrusted
treatment; an AML-narration third surface; per-tenant policy configuration; and a
larger, external adversarial evaluation.

## Conclusion

Injection detection and prompt-hardening treat the symptom (bad instructions in
text). Sentinel treats the cause: it removes attacker prose from the authoritative
decision and makes that boundary a type the compiler checks. The result closes the
class of attacks — adjudication gaming — that the obvious defences cannot, at
negligible cost, across two surfaces, with a held-out set to keep the claim honest.

## References

- Repository: https://github.com/adivishall/sentinel
- Live demo: https://adivishall.github.io/sentinel/
- Evaluation: [EVALUATION.md](EVALUATION.md) · Architecture: [ARCHITECTURE.md](ARCHITECTURE.md) · Threat model: [THREAT_MODEL.md](THREAT_MODEL.md)
