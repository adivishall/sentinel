# Limitations (read before judging, and before we present)

We would rather state these than have them found.

1. **The offline agent is a simulation.** Offline, the "agent" is a deterministic
   instruction-follower, not an LLM. It is a faithful model of the *documented*
   failure mode (treating in-context text as instructions, and believing stated
   reasons), but it is not proof that a specific production LLM fails identically.
   Live mode (`make live`) runs the identical firewall behind real Claude agents to
   narrow this gap.

2. **The corpus is synthetic and partly templated.** The development set is 12
   hand-authored seeds × 5 transaction amounts = 60 attacks + 18 controls. Real
   attacker text is more varied. The taxonomy (six classes), not the count, is the
   claim.

3. **The offline agent's gullibility is not keyed to the detector.** An
   adjudication-gaming attack (a false claim with no injection) succeeds against it
   purely by asserting a false reason. That is why the win comes from L3 (facts),
   not from a detector matching its own trigger words — the ablation shows
   detection-only still leaks 6.7%.

4. **The injection detector (L2) is lexical.** Transparent and fully explainable,
   but evadable by obfuscation/paraphrase. On the held-out set its recall is only
   ~25%. The security case does **not** depend on it: L1, L3 and L4 do not rely on
   catching every injection, and L3 is the backstop that holds when L2 misses.

5. **The held-out set is still hand-authored and small.** 12 attacks + 5 controls,
   authored independently of the detector and kept disjoint from the dev corpus
   (a test asserts this). It is enough to show the *architecture* generalises and
   introduces no false positives — but it is not a large external benchmark. Note
   the offline victim agent's unguarded ASR on it (16.7%) is depressed by the
   agent itself being lexical; the held-out set validates the firewall, not the
   baseline's realism.

6. **The claim classifier is lexical too.** An unrecognised legitimate phrasing
   degrades to `unspecified` → `deny`/`escalate` (fail-safe), which can be a false
   positive. The held-out set already caught two such cases ("two identical
   charges", "has not reached me"); they are fixed and pinned by regression tests,
   but novel phrasings could surface more.

7. **Two surfaces are benchmarked (dispute + KYB).** The same firewall defends
   merchant onboarding as well as dispute triage (87.5% → 0%, 0% FP). AML
   narration remains a described-but-unbuilt third surface.

8. **The ledger is assumed trustworthy.** We defend the decision layer, not the
   integrity of the bank's own records. Poisoning the ledger is a different threat.

9. **Document handling is plain text.** Uploaded documents are treated as untrusted
   text (which is the point), but there is no binary PDF/OCR parser — that is
   deliberate scope, not an oversight.

10. **No real integration, and no universal security claim.** This is a lab
    prototype of a control that would sit in front of real back-office agents, not
    a deployment. It is not "100% secure"; it closes a specific, important class of
    attacks and is measured on synthetic corpora.

11. **The API is a minimal baseline.** It ships input-size caps, JSON validation,
    request IDs, optional bearer-token auth, and no-stack-trace errors — but not
    rate limiting, per-tenant roles, or a production WSGI/ASGI server. See
    [DEPLOYMENT.md](DEPLOYMENT.md).

## What is genuinely solid

- The trust-boundary architecture (L1) and the structured-adjudication backstop
  (L3) are real, general, framework-agnostic, and now **enforced by types**
  (`firewall/trust.py`) with tests proving prose cannot cross the boundary.
- The **0% false-positive** result matters as much as the **0% breach** result: the
  firewall does not block legitimate customers, including on held-out wording.
- The result **generalises to an independently authored held-out set** (0%/0%),
  which is the honest defence against a circular benchmark.
- Every block is explainable — it names the layer and the trigger.
