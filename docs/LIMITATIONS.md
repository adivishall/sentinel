# Limitations (read before judging, and before presenting)

We would rather state these than have them found. Every number in this file
is rendered from `results/` by `make docs`; none is typed by hand.

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
   attack simulator's WITHOUT / WITH comparison is that same simulator on
   both sides -- a demonstration of what the architecture prevents, not a
   real-world LLM experiment. The identical suite runs against a real model
   with `sentinel eval run --suite models` when a key is present; without one
   it records `not_run`. No live number is quoted anywhere in this repository.
3. **Transaction monitoring is a synthetic investigation simulation.**
   Structuring-like, rapid-movement, circular-transfer and dormant-activation
   indicators are structured heuristics over synthetic activity. Sentinel
   claims no regulatory compliance, no sanctions screening, no filing
   capability and no production AML effectiveness.
4. **KYB records are synthetic** (registration status, domain/business age,
   prior flags, MCC tier). A real acquirer's records would be
   `VERIFIED_EXTERNAL` evidence from an integration that does not exist here.
5. **Documents are plain text.** Uploads are treated as untrusted text (which
   is the point); there is no PDF/OCR parser.

## What is coarse

6. **The injection detector is lexical.** Transparent and explainable, but
   evadable by paraphrase; held-out detection recall is reported and is well
   below 100%. The security case does not depend on it: the ablation shows
   detection alone leaks the classes with nothing to detect, and
   trusted-evidence adjudication + policy is what carries the 0% result.
7. **The claim classifier is lexical.** An unrecognised legitimate phrasing
   degrades to a fail-safe human review -- a false positive. The held-out set
   exists to find these; in v2 it found "called off the booking" and the
   *general* cancellation pattern was broadened (not the string). More will
   exist.
8. **Risk is a rule model, not ML.** Point values are Sentinel heuristics,
   not industry standards; `docs/RISK_ENGINE.md` lists every factor,
   condition and value. The financial evaluation shows exactly how coarse it
   is, per scenario and per level. Precision is high and false-positive rates
   are low because the baselines are clean synthetic history.
9. **The corpora are hand-authored and templated.**
   <!-- gen:corpus-counts -->
   Development corpus: 150 attacks + 21 controls across 15
   classes. Held-out: 20 attacks + 6 controls, authored independently and
   kept disjoint by test. Other surfaces: 30 attacks. KYB: 47 balanced
   applications (24 with a hostile document, 23 without). The taxonomy and the
   invariants are the claim, not the counts.
   <!-- /gen:corpus-counts -->
10. **Policy values are demo values.** ₹50,000 refund auto-limit, ₹1,50,000
    transaction auto-limit, risk thresholds -- all illustrative, all
    versioned so they can be changed and replayed.

## What is not production

11. **No real integrations.** The context builders read SQLite where a real
    deployment would call ledger, history, device and authentication services.
12. **The API is a threaded stdlib server** with body caps, a per-client rate
    limit, optional bearer auth (constant-time compare), request ids and
    static path containment -- a sensible baseline, not an edge. No TLS,
    roles, tenants or key management.
13. **The event bus is in-process.** Clean separation of event / processing /
    decision / side effect, but not a distributed system and not claimed as one.
14. **The graph is in memory.** Time-aware and fine at this scale; the query
    surface is the seam for a real adjacency store. The console renders a
    bounded neighbourhood (structural entities first) and says when it
    truncated.
15. **Determinism has one caveat.** Identifiers and timestamps are not
    deterministic; everything that affects an outcome is, and replay compares
    outcomes, not ids. Because engine drift is detected by re-deriving the
    original from its snapshot, a deliberate engine change reports drift on
    every earlier decision until they are re-baselined -- which is the point,
    but it is noisy.
16. **The API's trust contract is by convention.** `ledger`, `records`,
    `transaction` and `session` in a request body are treated as the
    institution's records because the caller is meant to be the system of
    record. Nothing in the protocol proves that; auth is optional and the
    server warns when it starts open on a non-loopback address. Ablation
    controls (`unguarded`, `options.controls`) are refused on the evaluate
    routes unless `SENTINEL_ALLOW_UNGUARDED=1`.
17. **The audit chain's external anchor is the operator's job.** It is a
    tamper-evident application audit chain -- not a blockchain, not an
    immutable ledger. Modification, deletion, insertion and reordering are
    detected and the first bad record is named; a storage attacker who
    rewrites the *entire* chain consistently from genesis is detected only
    against a checkpoint (`sentinel audit checkpoint`, HMAC-signed with
    `SENTINEL_AUDIT_KEY`) that must be stored outside the audit store and
    whose key must be managed.

## Known weaknesses (deliberately not tuned away)

18. **The unguarded baseline is the simulator's.**
    <!-- gen:unguarded-baseline -->
    90.0% (dev), 35.0% (held-out), 60.0% (other surfaces) and
    62.5% (KYB) describe how often the deterministic offline agent obeys the
    corpus; the corpus and the agent share an author. They are a contrast for
    the protected path, not a claim about any real model; the live-model row in
    `results/models.json` is `not_run`.
    <!-- /gen:unguarded-baseline -->
19. **The guarded 0% is structural.** Every attack ledger is unsupporting and
    every hostile KYB application either sits on bad records or is held by
    the security finding, so under the design no attack *can* execute; those
    rows are regression checks. The empirical content of the security suite
    is the false-positive rate on deserved claims, the detection recall, the
    held-out claim-classifier coverage and the KYB any-input cost.
20. **The financial figures are development figures with an honest range.**
    <!-- gen:financial-caveats -->
    The point values were tuned on seed 42; the suite also runs seeds
    7 and 2024 and reports the range (transaction precision 91.5%–95.6%,
    recall 76.8%–79.6%; account recall 80.0%–90.0%). Transaction-level recall
    on seed 42 is 79.6%: all 11 misses are burst transactions (63.3% burst
    recall, n=30) whose short-window velocity signals had not yet formed -- the
    account-level monitor is where a burst is meant to be caught, and its burst
    recall is 66.7% (n=3). Account-level recall is 80.0% (2 misses of
    10 labelled accounts; 0 false positives). Merchant level has n=3 positives and is
    reported for completeness only. Account-level scenarios remain the mirror
    image of the monitoring rules, so their recall says little about generality.
    <!-- /gen:financial-caveats -->
21. **KYB has a real false-positive cost on hostile-but-clean applications.**
    <!-- gen:kyb-caveat -->
    The KYB any-input false-positive rate is 26.3%: 5 of the 12
    clean merchants whose upload carried an injection were held for a human
    rather than approved, because a CRITICAL security finding blocks automatic
    approval. On benign input the rate is 0.0% and no merchant the records
    say to reject went live (0.0% FN). This is the cost of the design and is
    reported, not tuned away.
    <!-- /gen:kyb-caveat -->
22. **The temporal-leakage suite is a spot check.** It samples a subset of
    transactions and three future offsets over the generator; the per-feature
    tests (`test_temporal_leakage.py`, `test_entity_pointintime.py`,
    `test_graph_temporal.py`) cover the mechanisms, but the suite does not
    re-score every record under every possible future.
23. **Detection recall mixes two mechanisms.** A "detected" attack is one the
    merged assessment flagged, whether by the lexical text scan or by the
    structural model-output check (an off-surface capability request). The
    held-out rows show which: lexical misses that the structural check caught.
24. **The static console snapshot is read-only** and frozen at the time
    `make snapshot` ran; custom attacks, case actions and the policy sandbox
    need the live API.

<!-- gen:limitations-solid -->
## What is genuinely solid

- The trust boundary and the composer: the authoritative decision is computed
  from a view that has no field for prose or for the model's recommendation.
  The integrity suite measures the property as it is enforced: across 170
  attacks, **0.0%** exceeded the ledger-supported ceiling and **0.0%**
  executed without ledger support, against **83.5%** permissive influence with
  no controls; 360 model-recommendation replays changed nothing.
- **0.0%** unauthorised capability executions across the development corpus,
  the held-out set, the other surfaces and KYB (structural, by construction),
  with **0.0%** false positives on deserved refunds -- including the
  urgent-but-legitimate phrasings -- which is the empirical part.
- **0.0%** temporal leakage on the benchmark: a decision at T1 reads only
  records at or before T1, per feature and per entity profile.
- Model output is typed untrusted and cannot become evidence; an agent
  pushed off its tool surface produces a CRITICAL event, a BLOCK and a P1
  case, never an execution.
- Policy is fail-closed (a missing input can never switch a rule off),
  content-hashed (a replay knows whether "v3" is still the v3 the decision
  saw) and linted.
- Every block is explainable (evidence, contradictions, matched rules,
  authorization reason, blocked-by list) and every decision is replayable and
  recorded in a tamper-evident chain with an exportable signed checkpoint.
<!-- /gen:limitations-solid -->
