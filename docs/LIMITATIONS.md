# Limitations (read before judging, and before we present)

We would rather state these than have them found.

1. **The offline agent is a simulation.** Offline, the "agent" is a deterministic
   instruction-follower, not an LLM. It is a faithful model of the *documented*
   failure mode (treating in-context text as instructions), but it is not proof
   that a specific production LLM fails identically. Live mode (real Claude agents)
   exists precisely to close this gap; run `make all` with a key.

2. **The corpus is synthetic and partly templated.** 60 attacks + 18 controls,
   built from hand-authored seeds instantiated across amounts/merchants. Real
   attacker text is more varied. The taxonomy, not the corpus size, is the claim.

3. **The offline agent is a naive narrative-truster.** It fails two ways a real
   LLM does: it obeys embedded instructions/authority, and it believes a stated
   reason without checking records. Crucially, its gullibility is NOT keyed to the
   injection detector's patterns — an adjudication-gaming attack (a false claim
   with no injection) succeeds against it purely by asserting a false reason. That
   is why the win comes from layer 3 (facts), not from a detector matching its own
   trigger words. See the ablation: detection-only still leaks 6.7%.

4. **The injection detector is lexical.** Transparent and fully explainable, but
   evadable by obfuscation/paraphrase. The ablation shows why this is acceptable:
   layers 1, 3, 4 do not depend on catching every injection — layer 3 decides on
   verified facts and is the backstop that holds even when detection misses.

7. **Two surfaces are benchmarked (dispute + KYB).** The same firewall defends
   merchant onboarding (KYB) as well as dispute triage — 87.5% -> 0% with 0% false
   positives, via a KYB adjudicator that decides on verified acquirer records. AML
   narration remains a described-but-unbuilt third surface.

8. **"60 attacks" = 12 hand-authored seeds x 5 transaction amounts.** The taxonomy
   (six classes), not the count, is the claim. The live generator (`red/generate.py`)
   adds non-templated variants when an API key is present.

5. **The ledger is assumed trustworthy.** We defend the decision layer, not the
   integrity of the bank's own records. Poisoning the ledger is a different threat.

6. **No real integration.** This is a lab prototype of a control that would sit in
   front of real back-office agents, not a deployment.

## What is genuinely solid

- The trust-boundary architecture (L1) and the structured-adjudication backstop
  (L3) are real, general, and framework-agnostic.
- The 0% false-positive result matters as much as the 0% breach result: the
  firewall does not block legitimate customers.
- Every block is explainable — it names the layer and the trigger.
