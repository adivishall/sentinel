# Testing

```bash
make test        # pytest, offline, no key
make cov         # with the coverage gate (CI: --cov-fail-under=80)
make lint        # ruff + black --check + mypy over the whole package
```

`tests/conftest.py` forces offline mode; tests never touch the network.

## What each file protects

| File | Protects |
|---|---|
| `test_invariants.py` | **The ten security invariants** + property-based checks (Hypothesis): attacker text cannot change a trusted-fact verdict; model output cannot bypass capability policy; model output is never trusted evidence; unknown claims fail safe; malformed input never yields an irreversible action; high-value effects cannot bypass authorization; audit tampering is detected; policy versions are explicit and replayable; provenance is preserved end to end; API/CLI/UI/evaluation share one engine. |
| `test_trust_boundary.py` | prose never reaches the policy context or the audit log; forged claims and documents cannot overwrite records; untrusted keys are dropped; `UntrustedText` has no evidence accessor; malformed trusted numbers coerce safely |
| `test_hostile_vectors.py` | end-to-end: full-width / zero-width / homoglyph injections, document-borne approvals (dispute + KYB), over-limit legitimate → human, oversized input, multi-turn late attack, capability escalation through a document, descriptor cannot lower risk, replay cannot launder an outcome |
| `test_security_gateway.py` | normalisation, provenance, all signal classes, benign/urgent legit not flagged, hashed findings, document / third-party reclassification, split-payload and prior-turn multi-turn, model-output escalation, merge |
| `test_capabilities.py` | registry invariants, authorization matrix, human-only capabilities, `SKIP_REVIEW` has no actor |
| `test_evidence.py` | contradiction engine, dispute/KYB reconciliation verdicts, document claims, model evidence never verified |
| `test_policy_engine.py` | schema validation (unknown fields/ops/outcomes, type mismatches, duplicates), most-severe-wins, order independence, required fields, operators, file round-trip, registry versions |
| `test_composer.py` | flagship outcomes, ablation controls, policy context has no model output, fail-safe on malformed context, trail + serialisation |
| `test_risk_engine.py` | baselines, transaction factors, determinism + rescoring under another model, graph queries, entity profile order, account security, monitoring patterns, dispute risk |
| `test_workflows.py` | both flagship demos, invalid input, unguarded contrast, hardened prompt, sessions, transaction / KYB / account / investigation / AI-security paths, persistence flag |
| `test_cases.py` | opening rules, lifecycle guards, human-only resolution |
| `test_audit_chain.py` | link/verify, modification, deletion, reordering, truncation head, JSONL reload + disk tamper, redaction |
| `test_data_store_replay.py` | generator determinism and coherence, store round-trip, SQLite-backed audit/cases survive reopen and detect DB tamper, snapshot round-trip, replay by policy version / rule / model / recommendation |
| `test_app.py` | application layer: overview from real data, investigation view, entity risk + graph, every attack preset never executes, every scenario runs, cases/audit/replay |
| `test_api_v1.py` | real socket: every route family, validation errors, auth, 403 on control switches, rate limit, static console, capabilities / lint / review routes |
| `test_cli.py` | every command family end to end against a temp store, including `audit verify` and `ui snapshot` |
| `test_domain.py`, `test_providers_agents.py` | primitives; provider abstraction and the naive agents |
| `test_graph_temporal.py` | edges before / after creation, inside / outside the active window, exact boundaries, bounded transfer cycles, multiple cycles, bounded rendering |
| `test_entity_pointintime.py` | as-of device / merchant / account / customer profiles; records after `as_of` never enter; the takeover device is new at the takeover |
| `test_temporal_leakage.py` | a T1 decision is unchanged when records appear at T1 + 1, 30 and 90 days; truncation equivalence; the reusable temporal helper |
| `test_generator_scenarios.py`, `test_generator_profiles.py` | every labelled scenario is present and coherent (known device → no `new_device`, takeover device → `new_device`); generator profiles |
| `test_dispute_facts.py` | the richer ledger facts, `as_policy_facts`, refund policy v3 outcomes (already refunded, reversed, contested, strong auth) |
| `test_policy_lint.py` | every lint finding and the exhaustive boundary tests of the shipped policies |
| `test_model_output_separation.py` | model output never reaches the trusted view, the policy context, evidence or authorization; output-format mimicry is a finding, not a decision |
| `test_replay_determinism.py` | identical input / facts / configuration / policy / engine reproduce the decision; policy drift, engine drift and the field-level diff against the stored original |
| `test_audit_indexing.py` | indexed lookups return the same records as a full read; the indexed path never skips tamper detection; checkpoints and signatures |
| `test_api_path_containment.py` | static file serving cannot escape the console directory |
| `test_ui_api_contract.py` | the console holds no decision logic and every route it calls exists |
| `test_results_regression.py` | the headline claims recompute from the corpora at test time |
| `test_rc_hardening.py` | the final review's findings: no policy-version / risk-model override on the authoritative path (API and CLI), human-only resolution, unreadable / inserted / broken-link audit records, index cross-checks, fail-closed append on every backend, checkpoint failures name a record, replay diffs the stored decision and reports engine drift |
| `test_claims.py` | the claim classifier: kinds and types, conflicting claims abstain, abstain is INSUFFICIENT and a human review, non-claims are denied, attack prose never yields a wrong type on the corpora, the extended patterns and what they must not invent, benchmark floors incl. the held-out set (a miss is an abstain, never a wrong type) |
| `test_evaluation_authority.py` | evaluation authority: active vs historical versions; a persisting runtime refuses a downgraded run; what-if runs never persist; the check reads the inputs (an edited active policy is caught); a risk model only on its own surface; every evaluate route x every what-if switch is a 403; user options accepted, unknown ones a 400; the authoritative CLI commands have no what-if flags |
| `test_case_lifecycle.py` | the case state machine: RESOLVED absent from the table, every illegal move, OPEN -> RESOLVED both ways, system / agent reviewers refused, an agent recommending close_case end to end, the registry's review level, a resolved case is final, SQLite round-trip, API status codes |
| `test_replay_integrity.py` | replay: same inputs -> no diff; changed policy, engine and risk model -> explicit diffs with versions; later source changes do not move a replay; an edited snapshot and a consistent decision + snapshot rewrite are detected against the audit event; replay never overwrites the original; API fields |
| `test_policy_adversarial.py` | the policy engine and registry, adversarially: missing and mistyped fields fail closed, facts cannot overwrite computed fields, malformed documents refused (unknown keys, no default, impossible values), threshold edges, conflicting rules, every consequential capability closed to AI / external actors, unknown capability / actor denied, tampered / unpinned / deleted policy files and store hash mismatch, malformed ledger and KYB numbers |
| `test_audit_corruption.py` | audit corruption: malformed JSON, truncated line, missing field, wrong hash, wrong predecessor, deleted / inserted / reordered lines, cut last line -- each an AUDIT INTEGRITY ERROR (exit 2) through the library and the CLI; SQLite row edits; export -> verify |
| `test_capability_trace.py` | the consequential-capability trace: a model asking for each of the ten capabilities in every workflow never executes it; a caller's request gets the registry's answer; execution only with SUPPORTED evidence, a non-blocking policy and a GRANTED SYSTEM authorization |
| `test_generator_chronology.py` | the synthetic world on five seed / profile worlds: nothing before what it needs or after the clock, dormant accounts silent, scenario gaps and sizes vary, fraud timestamps not recognisable from the clock, legitimate behaviour varies, determinism |

## The regression tests that matter most

1. `test_invariants.py` (all)
2. `test_trust_boundary.py::test_narrative_never_reaches_the_policy_context_or_audit`
3. `test_hostile_vectors.py` (all)
4. `test_invariants.py::test_heldout_still_zero_breach_and_zero_fp`
5. `test_app.py::test_every_attack_preset_never_executes_a_consequential_capability`

## CI

`.github/workflows/ci.yml`: ruff → black → mypy → pytest with coverage gate →
invariants → evaluation smoke (security, held-out, surfaces, KYB, ablation,
integrity, temporal) → CLI + audit-chain smoke (generate, analyse, the
flagship attack, verify, checkpoint export and verification) → Docker build.
Live model calls are never made in CI.
