# Final validation

Every row was actually executed on this machine (macOS, Python 3.13, offline mode).
Nothing is marked PASS without evidence. Reproduce with the command shown.

Last run: final resume-ready pass (branch `release/final-resume-ready`).

| # | Check | Command | Result | Evidence |
|---|---|---|---|---|
| 1 | Unit + integration tests | `make test` | ✅ PASS | 83 passed |
| 2 | Coverage gate (≥85%) | `pytest --cov ... --cov-fail-under=85` | ✅ PASS | 91.26% total (firewall/agents/api) |
| 3 | Lint — ruff | `python3 -m ruff check .` | ✅ PASS | All checks passed |
| 4 | Format — black | `python3 -m black --check .` | ✅ PASS | 50 files unchanged |
| 5 | Types — mypy | `python3 -m mypy` | ✅ PASS | no issues in 13 source files |
| 6 | Offline pipeline | `make offline` | ✅ PASS | ASR 83.3%→0%, FP 0%; 6 charts written |
| 7 | Ablation | `python3 eval/ablation.py` | ✅ PASS | detection-only 6.7%, L3 0%, full 0% |
| 8 | Baselines | `python3 eval/baselines.py` | ✅ PASS | hardened 16.7%, sentinel 0%; hardened fails 100% on gaming |
| 9 | KYB surface | `python3 eval/kyb_harness.py` | ✅ PASS | 87.5%→0%, FP 0% |
| 10 | Held-out evaluation | `python3 eval/heldout.py` | ✅ PASS | guarded 0%, FP 0% on 12 unseen attacks |
| 11 | Benchmark | `make bench` | ✅ PASS | mean ~0.087 ms, p95 ~0.111 ms, ~11.5k dec/s |
| 12 | Security regression suite | `pytest tests/test_security_review.py tests/test_trust_boundary.py tests/test_heldout.py tests/test_session.py tests/test_policy.py tests/test_audit.py` | ✅ PASS | 8 end-to-end hostile vectors + boundary/session/policy/audit |
| 13 | Hostile security review (15 vectors) | manual probe (see below) | ✅ PASS | all safe (see list) |
| 14 | API — pure + HTTP tests | `pytest tests/test_api.py` | ✅ PASS | 14 tests incl. auth, bad JSON, 404, 413 |
| 15 | API — production startup smoke | `python3 sentinel_api.py` + curl | ✅ PASS | GET /health → 200, POST /api/evaluate → 200 |
| 16 | Interactive console | `make demo` | ✅ PASS | all 6 attacks BREACH off / denied on; 2 legit approved (verified in browser) |
| 17 | Fresh clone from GitHub → offline | `git clone <repo> --branch release/final-resume-ready && make offline` | ✅ PASS | clean checkout reproduced all metrics + charts |
| 18 | Fresh clone → tests / bench / lint | in clean checkout | ✅ PASS | 83 passed; bench ~0.087 ms; mypy clean |
| 19 | Charts without matplotlib | simulated ImportError | ✅ PASS | `make offline` still succeeds, prints skip message, exit 0 |
| 20 | Live Claude mode | `make live-check` / `make live` | ⚠️ NOT AVAILABLE | no `ANTHROPIC_API_KEY` here; code + preflight present, not run |
| 21 | Docker build | `make docker-build` | ⚠️ NOT AVAILABLE | Docker not installed here; `Dockerfile` + `.dockerignore` written, not built |
| 22 | Live site (GitHub Pages) | https://adivishall.github.io/sentinel/ | ✅ PASS | HTTP 200 (tracks `main`) |

## Hostile security review (row 13)

15 vectors run end-to-end through the pipeline/API/session; **all safe**:
direct injection, authority spoof, fullwidth-unicode injection, Cyrillic-homoglyph
injection, zero-width-split injection, document-borne fabricated approval
(dispute + KYB), multi-turn escalation (harmless → trust → attack), adjudication
gaming, false duplicate-charge claim, over-limit legitimate claim (→ escalate, not
auto-pay), and malformed/empty/None/oversized input (→ fail-safe escalate). No new
failures were found this pass; the two bugs from the prior pass (claim-classifier
false positive; malformed-number coercion) remain fixed and are pinned by tests.

## Notes on the NOT AVAILABLE rows

- **Live mode (20):** requires a real Anthropic API key, intentionally absent here.
  `scripts/live_check.py` (one-call preflight) and `scripts/live_run.py` (identical
  firewall behind real Claude) are written and type-checked but not executed. No
  live numbers are quoted anywhere in the repo for this reason.
- **Docker (21):** the Docker CLI is not installed on this machine, so `docker build`
  could not run. The `Dockerfile` is standard (`python:3.11-slim`, non-root user,
  `HEALTHCHECK`, offline by default, `--build-arg LIVE=1` for live) with a
  `.dockerignore`; the build itself is unverified here.

## Reproduce the whole battery

```bash
make test && make lint && make bench && make offline
python3 eval/heldout.py
make api   # then: curl localhost:8000/health
```
