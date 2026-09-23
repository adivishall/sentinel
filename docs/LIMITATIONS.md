# Limitations (read before judging, and before presenting)

We would rather state these than have them found.

## What is simulated

1. **The dataset is synthetic.** `sentinel/data/generator.py` produces a
   coherent, correlated world (segments, baselines, favourite merchants,
   devices, home countries, merchant risk tiers) with labelled fraud
   scenarios woven in. It is deterministic and honest, but it is not real
   payment data, and the financial metrics characterise the rule model *on
   this generator*, nothing more.
2. **The agents are simulated offline.** `OfflineProvider` models the
   documented failure mode of a naive tool-calling LLM: it obeys in-context
   instructions and authority claims, believes stated reasons, and calls any
   tool it knows about. Its gullibility is deliberately not keyed to the
   gateway's detector. This makes the evaluation reproducible and fair, but it
   is not proof that a specific production model fails identically. The
   identical suite runs against a real model with `sentinel eval run --suite
   models` when a key is present; without one it records `not_run`. No live
   number is quoted anywhere in this repository.
3. **Transaction monitoring is an educational simulation.** Structuring-like,
   rapid-movement, circular-transfer and dormant-activation indicators are
   structured heuristics over synthetic activity. Sentinel claims no
   regulatory compliance, no sanctions screening, no filing capability and no
   production AML effectiveness.
4. **KYB records are synthetic** (registration status, domain/business age,
   prior flags, MCC tier). A real acquirer's records would be
   `VERIFIED_EXTERNAL` evidence from an integration that does not exist here.
5. **Documents are plain text.** Uploads are treated as untrusted text (which
   is the point); there is no PDF/OCR parser.

## What is coarse

6. **The injection detector is lexical.** Transparent and explainable, but
   evadable by paraphrase; held-out detection recall is reported and is well
   below 100%. The security case does not depend on it: the ablation shows
   detection alone leaks the false-claim classes, and trusted-evidence
   adjudication + policy is what carries the 0% result.
7. **The claim classifier is lexical.** An unrecognised legitimate phrasing
   degrades to a fail-safe human review -- a false positive. The held-out set
   exists to find these; in v2 it found "called off the booking" and the
   *general* cancellation pattern was broadened (not the string). More will
   exist.
8. **Risk is a rule model, not ML.** Weights are Sentinel demo values. The
   financial evaluation shows exactly how coarse it is: transaction-level
   recall on scenarios that are only visible at the account level (bursts) is
   inherently partial, which is why the evaluation is reported per level.
   Precision is high and false-positive rates are low because the baselines
   are clean synthetic history.
9. **The corpora are hand-authored and templated.** Development corpus: 24
   seeds × 5 amounts = 120 attacks + 21 controls across 12 classes. Held-out:
   16 attacks + 6 controls, authored independently and kept disjoint by test.
   KYB: 10 + 5. The taxonomy and the invariants are the claim, not the counts.
10. **Policy values are demo values.** ₹50,000 refund auto-limit, ₹1,50,000
    transaction auto-limit, risk thresholds -- all illustrative, all
    versioned so they can be changed and replayed.

## What is not production

11. **No real integrations.** The context builders read SQLite where a real
    deployment would call ledger, history, device and authentication services.
12. **The API is a threaded stdlib server** with body caps, a per-client rate
    limit, optional bearer auth and request ids -- a sensible baseline, not an
    edge. No TLS, roles, tenants or key management.
13. **The event bus is in-process.** Clean separation of event / processing /
    decision / side effect, but not a distributed system and not claimed as one.
14. **The graph is in memory.** Fine at this scale; the query surface is the
    seam for a real adjacency store.
15. **Determinism has one caveat.** Identifiers and timestamps are not
    deterministic; everything that affects an outcome is, and replay compares
    outcomes, not ids.

## What is genuinely solid

- The trust boundary and the composer: the authoritative decision is computed
  from a view that has no field for prose or for the model's recommendation.
  The integrity suite measures the consequence directly: **0%** of protected
  decisions made more permissive by attacker text or by any of six model
  recommendations, against **77.9%** with no controls.
- **0%** unauthorised capability executions across the development corpus,
  the held-out set and KYB, with **0%** false positives on deserved refunds --
  including the urgent-but-legitimate phrasings.
- Model output is typed untrusted and cannot become evidence; an agent
  pushed off its tool surface produces a CRITICAL event, a BLOCK and a P1
  case, never an execution.
- Every block is explainable (evidence, contradictions, matched rules,
  authorization reason, blocked-by list) and every decision is replayable and
  hash-chained.
