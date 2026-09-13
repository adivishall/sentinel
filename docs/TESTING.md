# Testing

Sentinel ships **83 tests** at **~91% coverage** (security-critical firewall modules
90–100%). Tests are the contract that protects the important behaviour — the trust
boundary, the 0%/0% result, and the fail-safe.

```bash
make test          # SENTINEL_FORCE_OFFLINE=1 python3 -m pytest tests/ -q   (no key, no network)
make lint          # ruff + black --check + mypy

# with coverage:
SENTINEL_FORCE_OFFLINE=1 python3 -m pytest tests/ \
  --cov=firewall --cov=agents --cov=sentinel_api --cov-report=term-missing
```

`tests/conftest.py` forces offline mode, so tests never hit the network.

## What each file protects

| File | Protects |
|---|---|
| `test_trust_boundary.py` | **The core claim.** Prose cannot flip a verdict; the narrative never reaches the adjudicator input; forged claims/documents cannot overwrite records; evidence lives only on `TrustedFacts`; malformed trusted numbers coerce safely. |
| `test_security_review.py` | **End-to-end hostile vectors:** fullwidth/homoglyph/zero-width injections, document-borne fabricated approvals (dispute + KYB), over-limit legitimate → escalate, oversized fail-safe, multi-turn late attack. |
| `test_heldout.py` | Held-out generalisation (0% ASR, 0% FP on unseen wording), dev/held-out disjointness, and the specific fixed false-positive phrasings. |
| `test_results_regression.py` | Locks the headline: full firewall = 0% breach / 0% FP; ablation shows L3 is necessary and sufficient. |
| `test_pipeline.py` | Layer orchestration, empty/None fail-safe, audit-trail population, layer toggling. |
| `test_adjudicate.py` | L3 verdicts come from ledger facts, not text. |
| `test_kyb.py` | KYB adjudication on acquirer records. |
| `test_detect.py` | L2 injection signals + threshold. |
| `test_normalize.py` | NFKC + homoglyph fold + zero-width strip + validation. |
| `test_session.py` | Multi-turn: last-turn attack blocked, split payload caught, false claim over turns denied, cumulative risk. |
| `test_policy.py` | L4 policy engine: ALLOW / REQUIRE_HUMAN_REVIEW / BLOCK + reasons. |
| `test_audit.py` | Decision record completeness/serialisability; audit stores hash-not-prose; off by default. |
| `test_api.py` | Pure `evaluate()` + real HTTP (health/version/evaluate, auth, 400/404/413, multi-turn). |

## Coverage policy

CI enforces `--cov-fail-under=85`. We do **not** chase 100% — the bar is high on
security-critical modules and pragmatic on the API's `serve()` loop and unreachable
defensive branches. Current per-module highlights: `pipeline.py`, `detect.py`,
`normalize.py`, `audit.py`, `session.py` at **100%**; `trust.py` ~91%; `limits.py`
~90%.

## The regression tests that matter most

If you change the firewall, these are the ones that catch a security regression:

1. `test_trust_boundary.py::test_narrative_never_reaches_adjudicator_input`
2. `test_results_regression.py::test_full_firewall_zero_breach_and_zero_fp`
3. `test_results_regression.py::test_ablation_shows_l3_is_necessary`
4. `test_heldout.py::test_heldout_zero_breach_and_zero_fp`
5. `test_security_review.py` (all — the hostile vectors)

## CI

`.github/workflows/ci.yml` runs, on every push/PR: ruff → black → mypy → pytest +
coverage gate → an **offline evaluation smoke test** (`harness`, `ablation`,
`heldout`). A security regression therefore fails the build, not just a local run.
Live Claude calls are never made in CI.
