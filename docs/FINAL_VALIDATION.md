# Final validation

Every row was actually executed on this machine (macOS, Python 3.13, offline mode).
Nothing is marked PASS without evidence. Reproduce with the command shown.

| # | Check | Command | Result | Evidence |
|---|---|---|---|---|
| 1 | Unit + integration tests | `make test` | ✅ PASS | 74 passed |
| 2 | Coverage gate (≥85%) | `pytest --cov ... --cov-fail-under=85` | ✅ PASS | 91.26% total (firewall/agents/api) |
| 3 | Lint — ruff | `python3 -m ruff check .` | ✅ PASS | All checks passed |
| 4 | Format — black | `python3 -m black --check .` | ✅ PASS | 49 files unchanged |
| 5 | Types — mypy | `python3 -m mypy` | ✅ PASS | no issues in 13 source files |
| 6 | Offline pipeline | `make offline` | ✅ PASS | ASR 83.3%→0%, FP 0%; 6 charts written |
| 7 | Ablation | `python3 eval/ablation.py` | ✅ PASS | detection-only 6.7%, L3 0%, full 0% |
| 8 | Baselines | `python3 eval/baselines.py` | ✅ PASS | hardened 16.7%, sentinel 0%; hardened fails 100% on gaming |
| 9 | KYB surface | `python3 eval/kyb_harness.py` | ✅ PASS | 87.5%→0%, FP 0% |
| 10 | Held-out evaluation | `python3 eval/heldout.py` | ✅ PASS | guarded 0%, FP 0% on 12 unseen attacks |
| 11 | Benchmark | `make bench` | ✅ PASS | mean ~0.087 ms, p95 ~0.111 ms, ~11.5k dec/s |
| 12 | Security regression suite | `pytest tests/test_trust_boundary.py tests/test_session.py tests/test_policy.py tests/test_heldout.py tests/test_audit.py` | ✅ PASS | trust boundary, sessions, policy, held-out, audit |
| 13 | API — pure + HTTP tests | `pytest tests/test_api.py` | ✅ PASS | 14 tests incl. auth, bad JSON, 404, 413 |
| 14 | API — production startup smoke | `python3 sentinel_api.py` + curl | ✅ PASS | GET /health → 200, POST /api/evaluate → 200 |
| 15 | Interactive console | `make demo` | ✅ PASS | all 6 attacks BREACH off / denied on; 2 legit approved (verified in browser) |
| 16 | Fresh clone → offline | `git clone <repo> && make offline` | ✅ PASS | clean checkout reproduced all metrics + charts |
| 17 | Fresh clone → tests | `make test` in clean checkout | ✅ PASS | 74 passed |
| 18 | Live Claude mode | `make live-check` / `make live` | ⚠️ NOT AVAILABLE | no `ANTHROPIC_API_KEY` in this environment; code + preflight present, not run |
| 19 | Docker build | `make docker-build` | ⚠️ NOT AVAILABLE | Docker not installed here; `Dockerfile` + `.dockerignore` written (offline-by-default, non-root, HEALTHCHECK), not built |
| 20 | Live site (GitHub Pages) | https://adivishall.github.io/sentinel/ | ✅ PASS | HTTP 200 after repo rename |

## Notes on the NOT AVAILABLE rows

- **Live mode (18):** requires a real Anthropic API key, which is intentionally not
  present in this environment. `scripts/live_check.py` is a one-call preflight and
  `scripts/live_run.py` runs the identical firewall behind real Claude; both are
  written and type-checked but were not executed here. No live numbers are quoted
  anywhere in the repo for this reason.
- **Docker (19):** the Docker CLI is not installed on this machine, so `docker build`
  could not be executed. The `Dockerfile` is standard (`python:3.11-slim`, non-root
  user, container `HEALTHCHECK`, offline by default, `--build-arg LIVE=1` for live)
  and `.dockerignore` is present, but the build itself is unverified here.

## Reproduce the whole battery

```bash
make test && make lint && make bench && make offline
python3 eval/heldout.py
make api   # then: curl localhost:8000/health
```
