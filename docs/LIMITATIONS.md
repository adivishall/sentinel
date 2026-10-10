# Limitations (read before judging, and before presenting)

We would rather state these than have them found. The numbers inside the
generated blocks are rendered from `results/` by `make docs`; the few numbers
in the prose are configuration values (policy limits) or restate a generated
block.

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
   prior flags, MCC tier). In the demo they are signed by an ephemeral,
   in-process issuer. A real acquirer would sign them with a key the operator
   trusts, and no such integration exists here.
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
   for a human -- a classifier false negative that costs review time, never
   money. It is defence in depth, not the security foundation. Two
   incompatible claims in one message also abstain.
   <!-- gen:claims -->
   The claim classifier is defence in depth, not the security foundation: it
   only selects which trusted field is checked. It is deterministic and
   explainable (weighted pattern families, a negation guard, a hedge detector)
   and reports a confidence. On a
   117-phrasing benchmark that shares its author it reads 100.0% of ordinary legitimate
   paraphrases and never reads attack prose as a claim it does not assert
   (0.0%); ambiguous and contradictory messages abstain. On a **held-out**
   set of 21 uncommon legitimate phrasings it recognised 7 on the first, blind run
   and 17 after the patterns were extended against a separate development set --
   partially informed (the author had seen the misses), so 17/21 is not a clean
   independent benchmark; every miss abstains, i.e. goes to a human -- a cost,
   not a breach. False negatives 4 / 56, false
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
   classes. Held-out: 20 attacks + 6 controls, written after the
   development corpus by the same author and kept disjoint by test. Other surfaces: 30 attacks. KYB: 47 balanced
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
16. **Sentinel verifies who stated a fact, not whether the fact is true.**
    Record facts carry a provenance status (`docs/SECURITY_MODEL.md`).
    - An issuer's signed statement is `VERIFIED_EXTERNAL` only when it
      verifies against the operator's trust store.
    - Record facts in a request body are `UNTRUSTED` and never execute a
      capability.
    - A record read from the store is `TRUSTED_LOCAL`: trusted for where it is
      kept, so a DB-write attacker could change it unless signed facts are
      required.

    Two scope limits apply. The demo's issuer is an ephemeral in-process key,
    and no real issuer is integrated. The risk context around a record
    (history, graph, account status) is read from the store and is at most
    `TRUSTED_LOCAL`; only the primary record is signed.

    A caller-supplied (unsigned) transaction or session no longer chooses the
    moment it is assessed as of. It is evaluated at the system's time, so
    backdating it past a freeze or before a burst changes nothing. Being
    `UNTRUSTED`, the system never executes on it; only an authenticated
    reviewer's recorded approval can (item 27). A signed statement's timestamp
    is the issuer's and is used as stated.

    Rollback protection is as strong as the audit chain. A database writer
    who also rewrites the chain after the last checkpoint (item 17) could
    replay an older, unexpired statement. Statement expiry
    (`max_validity_days`) bounds that window, as it does for a statement older
    than the issuer's latest that this deployment never acted on.

    The workflow functions (`run_*`) are internal: whoever calls them is
    inside the boundary and states how the facts arrived. The public
    `SentinelApp`, API and CLI derive that themselves.

    Auth is optional, and the server warns when it starts open on a
    non-loopback address. What-if switches (controls, policy version, risk
    model, `as_of`) are refused on the evaluate routes, and the engine never
    records a run that used one.
17. **The audit chain's external anchor is the operator's job.** It is a
    tamper-evident application audit chain, not a blockchain and not an
    immutable ledger. Modification, deletion, insertion and reordering are
    detected, and the first bad record is named, **when the rewriter cannot
    recompute the chain**.

    A storage attacker can recompute it. A consistent rewrite of every event
    after the last checkpoint passes both `verify` and checkpoint
    verification. Only the prefix up to a checkpoint the operator stores
    outside the audit store is protected (`sentinel audit checkpoint`). That
    checkpoint is HMAC-signed with `SENTINEL_AUDIT_KEY`, so anyone who can
    verify it can also forge one. Asymmetric, externally anchored checkpoints
    are roadmap issue #17.

## Known weaknesses (deliberately not tuned away)

18. **The unguarded baseline is the simulator's.**
    <!-- gen:unguarded-baseline -->
    90.0% (dev), 35.0% (held-out), 60.0% (other surfaces) and
    62.5% (KYB) describe how often the deterministic offline agent obeys the
    corpus; the corpus and the agent share an author. They are a contrast for
    the protected path, not a claim about any real model; the live-model row in
    `results/models.json` is `not_run`.
    <!-- /gen:unguarded-baseline -->
19. **The guarded 0% is structural.** Every attack ledger in the dispute and
    surface corpora is unsupporting, so under the design no attack *can*
    execute; those rows are regression checks. In KYB, a hostile upload on
    clean records is approved when its finding is below HIGH -- correctly,
    since the records support the merchant and the text changes nothing (7 of
    12 in the suite) -- and held or blocked otherwise (5 of 12); a hostile
    upload on bad records is never approved. The empirical content of the
    security suite is the false-positive rates, the detection recall, the KYB
    any-input cost and the claim classifier's held-out coverage (partially
    informed: 7/21 on the first, blind run, 17/21 after changes).
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
    The KYB any-input false-positive rate is 26.3%: of the 19 applications
    whose acquirer records alone say *approve*, 5 were not approved because their upload
    carried an injection (3 blocked by the CRITICAL security finding, 2 held for
    review). The other 7 of the 12 clean-record applications with a hostile upload were
    approved -- correctly: the records supported them and the text changed nothing.
    On benign input the rate is 0.0%, and no merchant the records say to reject
    went live (0.0% FN). This is the cost of the design and is reported, not
    tuned away.
    <!-- /gen:kyb-caveat -->
22. **The temporal-leakage suite is a deterministic check, not a proof.** Its
    result is "0 observed temporal leaks across the tested synthetic
    benchmark": a tested invariant, not a fully event-sourced history. It
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
27. **Reviewer identity is a Sentinel-issued bearer credential, not the
    institution's identity provider.** Who acts, their role and their
    authority limit come from an operator-configured reviewer registry, and
    four eyes is enforced where the capability registry asks. But:
    - the credential is a static bearer token with no expiry, sent in a
      header, so production needs TLS and SSO / OIDC (issue #20);
    - anyone who can write the registry file can mint a reviewer, so keep it
      outside the data directory;
    - Sentinel does not know which subjects a reviewer is conflicted on (for
      example their own account);
    - account-security cases (payout changes, fund releases, risk overrides)
      carry no amount, so authority limits do not bound them; their role
      requirement and four eyes do.
28. **The claim classifier's held-out score is optimistic after the change.**
    The held-out set scored 7/21 on the first run; the patterns were then
    extended against a separate development set by an author who had seen the
    14 misses, and it now scores 17/21. An honest estimate of unseen wording
    lies somewhere between, and every miss still goes to a human.
29. **A signed policy release proves who approved a policy, not that it is
    right.** A version decides only under a verified release and an explicit
    activation, so a writer of the policy directory cannot change what decides.
    But:
    - the shipped trust root is a file in the package: someone who can rewrite
      the installed package can replace it (a deployment sets
      `SENTINEL_POLICY_TRUST` to a root it controls, outside the package);
    - the shipped versions were signed with the maintainer's key, whose private
      half is held off the repository; there is no multi-party sign-off;
    - a signer can release and activate a bad policy; rollback protection
      covers activations recorded in this store's audit chain, which is as
      strong as the chain itself (item 17).

<!-- gen:limitations-solid -->
## What is genuinely solid

- The trust boundary and the composer: the authoritative decision is computed
  from a view that has no field for prose or for the model's recommendation.
  The integrity suite measures the property as it is enforced: across 170
  attacks (main and held-out corpora), **0.0%** exceeded the ledger-supported ceiling and **0.0%**
  executed without ledger support, against **83.5%** permissive influence with
  no controls; 360 model-recommendation replays changed nothing.
- **0.0%** unauthorised capability executions across the main corpus (150),
  the held-out corpus (20), the other surfaces (30) and KYB (24 hostile)
  (structural, by construction),
  with **0.0%** false positives on deserved refunds -- including the
  urgent-but-legitimate phrasings -- which is the empirical part.
- **0 observed leaks in 3,648 checks** on the temporal benchmark
  (9 kinds of later record, 4 offsets, two synthetic worlds): evidence
  for a tested invariant -- for the record kinds tested, a decision at T1 read
  only records at or before T1 -- not a proof, and not a fully event-sourced
  history (see the time-semantics limitation).
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
