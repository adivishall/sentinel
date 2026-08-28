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

3. **Adjudication gaming looks weakest offline.** A rule-based agent isn't swayed
   by an emotional narrative, so that class shows low unguarded success offline.
   That *understates* the threat — a real LLM is susceptible — and it is the exact
   case layer 3 is built for. Don't read the offline 0% as "not a problem".

4. **The injection detector is lexical.** Transparent and fully explainable, but
   evadable by obfuscation/paraphrase. In production, layer 2 would be an LLM/ML
   classifier; layers 1, 3, 4 do not depend on catching every injection — layer 3
   is the backstop that holds even when detection misses.

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
