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
16. **The API's trust contract is by convention.** `ledger`, `records`,
    `transaction` and `session` in a request body are treated as the
    institution's records because the caller is meant to be the system of
    record. Nothing in the protocol proves that; auth is optional and the
    server warns when it starts open on a non-loopback address. Ablation
    controls (`unguarded`, `options.controls`) are refused on the evaluate
    routes unless `SENTINEL_ALLOW_UNGUARDED=1`.
17. **The audit chain has no external anchor.** Modification, deletion,
    insertion and reordering are detected; a storage attacker who rewrites
    the *entire* chain consistently from genesis is not. Production would
    anchor the head hash externally (a signed timestamp, a second store).

## Known weaknesses found in the v2.0.1 review (deliberately not tuned away)

18. **The unguarded baseline is the simulator's.** 83.3% (dev), 37.5%
    (held-out) and 100% (KYB) describe how often the deterministic offline
    agent obeys the corpus; the corpus and the agent share an author. They are
    a contrast for the protected path, not a claim about any real model.
19. **The guarded 0% is structural.** Every attack ledger is unsupporting and
    every KYB attack record is bad, so under the design no attack *can*
    execute; those rows are regression checks. The empirical content of the
    security suite is the false-positive rate on deserved claims, the
    detection recall, and the held-out claim-classifier coverage.
20. **Risk weights were tuned on seed 42.** The financial suite now also runs
    two held-out seeds and reports the range; the account-level scenarios are
    the mirror image of the monitoring rules (structuring = 3 transfers at
    80–100% of the threshold in 7 days; the generator emits 4 in 4 days), so
    100% account-level recall is by construction, not evidence of generality.
21. **Account-level false positives come from a time-unbounded cycle finder.**
    All four seed-42 false positives are legitimate accounts whose random
    baseline transfers happen to form a cycle somewhere in 240 days; the
    circular-transfer indicator does not bound the cycle to the monitoring
    window. On the two held-out seeds there are no false positives. Left as
    is and documented rather than fixed in a metrics-reporting pass.
22. **Transaction-level recall is low by construction.** The first several
    transactions of a burst carry no velocity yet; the second account-takeover
    transaction is in the same country as the first, so impossible travel does
    not fire; and the generator registers the attacker's device as a known
    account device, so `new_device` never fires on takeover transactions. The
    account-level monitor exists for the first two; the third is a generator
    realism bug that *depresses* recall and is documented, not patched.
23. **Entity profiles are as-of the dataset date, not the transaction time.**
    A merchant's dispute ratio and an account's profile read every record,
    including ones after the transaction being scored. The per-transaction
    baseline is now point-in-time (disputes filed after the transaction no
    longer enter its chargeback rate); the entity profiles are not.
24. **Merchant-level metrics have n=3 positives**, two of which are defined by
    fields the profile reads directly (shell registration, prior flags). They
    are reported for completeness, not as a result.
25. **Detection recall mixes two mechanisms.** A "detected" attack is one the
    merged assessment flagged, whether by the lexical text scan or by the
    structural model-output check (an off-surface capability request). The
    held-out rows show which: lexical misses that the structural check caught.

<!-- gen:limitations-solid -->
## What is genuinely solid

- The trust boundary and the composer: the authoritative decision is computed
  from a view that has no field for prose or for the model's recommendation.
  The integrity suite measures the property as it is enforced: across 136
  attacks, **0.0%** exceeded the ledger-supported ceiling and **0.0%**
  executed without ledger support, against **77.9%** permissive influence with
  no controls; 360 model-recommendation replays changed nothing.
- **0.0%** unauthorised capability executions across the development corpus,
  the held-out set and KYB (structural, by construction), with **0.0%** false
  positives on deserved refunds -- including the urgent-but-legitimate
  phrasings -- which is the empirical part.
- Model output is typed untrusted and cannot become evidence; an agent
  pushed off its tool surface produces a CRITICAL event, a BLOCK and a P1
  case, never an execution.
- Policy is fail-closed (a missing input can never switch a rule off) and
  content-hashed (a replay knows whether "v2" is still the v2 the decision
  saw).
- Every block is explainable (evidence, contradictions, matched rules,
  authorization reason, blocked-by list) and every decision is replayable and
  hash-chained.
<!-- /gen:limitations-solid -->
