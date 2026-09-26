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
7. **The claim classifier is deterministic patterns, not language
   understanding.** An unrecognised legitimate phrasing abstains and is held
   for a human -- a false positive that costs review time, never money. Two
   incompatible claims in one message also abstain.
   <!-- gen:claims -->
   The claim classifier is deterministic and explainable (weighted pattern
   families, a negation guard, a hedge detector) and reports a confidence. On a
   117-phrasing benchmark that shares its author it reads 100.0% of ordinary legitimate
   paraphrases and never reads attack prose as a claim it does not assert
   (0.0%); ambiguous and contradictory messages abstain. On a **held-out**
   set of 21 uncommon legitimate phrasings it recognised 7 on the first run and
   17 after the patterns were extended against a separate development set
   (optimistic: the author had seen the misses); every miss abstains, i.e. goes
   to a human -- a cost, not a breach. False negatives 4 / 56, false
   positives 0 / 28 (`docs/EVALUATION.md` §L).
   <!-- /gen:claims -->
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
13. **There is no event stream.** Workflows are synchronous functions; the
    audit chain is the durable record of each decision and the case service
    is the review queue. A streaming deployment would put a log in front of
    the same functions -- not built and not claimed.
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
16. **Sentinel does not verify the facts it adjudicates against.** The
    "system of record" is a synthetic SQLite store, and `ledger`, `records`,
    `transaction` and `session` objects in a request body are demo /
    simulation input trusted by contract -- every decision says which it was
    (`facts_source`) and the audit event records it, but nothing in the
    protocol proves the caller is a system of record. A caller-supplied
    transaction also chooses its own timestamp, i.e. the moment its risk is
    computed as of. Auth is optional and the server warns when it starts open
    on a non-loopback address. What-if
    switches (controls, policy version, risk model, `as_of`) are refused on
    the evaluate routes, and the engine never records a run that used one.
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
    7 and 2024 and reports the range (transaction precision 77.3%–87.8%,
    recall 65.4%–67.2%; account recall 90.0%–100.0%). Transaction-level recall
    on seed 42 is 67.2%: the 19 misses are burst transactions (44.1% burst
    recall, n=34); a burst's first transactions carry no short-window velocity signal
    and, since the generator stopped emitting fixed three-minute gaps, a burst spread
    over more than the ten-minute window carries fewer of them -- the account-level
    monitor is where a burst is meant to be caught, and its burst recall is
    100.0% (n=3). Account-level recall is 90.0% (1 misses of
    10 labelled accounts; 1 false positives). Merchant level has n=3 positives and is
    reported for completeness only. Account-level scenarios remain the mirror
    image of the monitoring rules, so their recall says little about generality.
    Legitimate accounts now burst, travel, switch phones and fail MFA at realistic
    rates, so every signal also fires on legitimate transactions; the per-signal
    table in `docs/EVALUATION.md` §G shows how often.
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
22. **The temporal-leakage suite is a deterministic check, not a proof.** It
    samples 192 transactions over two generator worlds and nine kinds of
    future record at four offsets; the per-feature tests
    (`test_temporal_leakage.py`, `test_entity_pointintime.py`,
    `test_graph_temporal.py`) cover the mechanisms, but the suite does not
    re-score every record under every possible future. Its 2.2.0 extension
    found two current-state reads the earlier suite could not see (account
    status, payout destination), which is the argument for extending it
    further, not for trusting its zero. Two fields remain current-state by
    nature: an account status with no recorded start (legacy data) and a
    merchant's `prior_flags`, which are the flags reported at registration --
    a flag raised later would need its own dated record, which the data model
    does not have.
23. **Detection recall mixes two mechanisms.** A "detected" attack is one the
    merged assessment flagged, whether by the lexical text scan or by the
    structural model-output check (an off-surface capability request). The
    held-out rows show which: lexical misses that the structural check caught.
24. **The static console snapshot is read-only** and frozen at the time
    `make snapshot` ran; custom attacks, case actions and the policy sandbox
    need the live API.
25. **A vague attacker reaches a human.** On an unsupporting ledger a message
    the classifier cannot read is held for review rather than denied; that is
    the designed fail-safe, and it means the human reviewer -- with the packet
    that puts the ledger facts first and marks the model output untrusted --
    is the last control against social engineering. No execution is possible
    on that path.
26. **Per-signal precision is low for several factors.** On the synthetic
    world several point-bearing factors fire far more often on legitimate
    transactions than on fraud (`docs/EVALUATION.md` §G lists every one);
    they were left as they are rather than re-weighted to look better.
27. **The human path has structure but no identity.** Only a human decision
    resolves a case, reserved system / model names are refused, and approving
    needs the level the case's capability requires -- but the reviewer's name
    and level are declared by the caller. Without per-user authentication and
    four-eyes enforcement, "a senior reviewer approved it" means "someone who
    called the API said so".
28. **The claim classifier's held-out score is optimistic after the change.**
    The held-out set scored 7/21 on the first run; the patterns were then
    extended against a separate development set by an author who had seen the
    14 misses, and it now scores 17/21. An honest estimate of unseen wording
    lies somewhere between, and every miss still goes to a human.
29. **The policy manifest guards against accidents, not insiders.** Pinned
    digests stop a shipped version being edited in place or deleted; someone
    who can edit both the policy and `MANIFEST.json` can still change it. That
    needs signed releases and code review, which a repository cannot supply.

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
- **0 of 3,648** decisions changed by future records on the
  temporal benchmark (nine record kinds, four offsets, two seeds): a decision at T1
  reads only records at or before T1, per feature and per entity profile.
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
