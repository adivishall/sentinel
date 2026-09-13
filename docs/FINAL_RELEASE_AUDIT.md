# Final release audit

Release-readiness verdict for Sentinel, from the final audit pass
(`release/final-audit`). Every verdict below reflects a command actually run on
this machine (macOS, Python 3.13, offline mode) — not a claim copied from docs.
For the full command-by-command matrix see [FINAL_VALIDATION.md](FINAL_VALIDATION.md).

| Area | Verdict | Evidence |
|---|---|---|
| **Functionality** | ✅ PASS | End-to-end pipeline runs offline; `make offline` reproduces every metric. Harness and API produce identical decisions through the same `pipeline.run_guarded` (no integration drift). |
| **Security** | ✅ PASS | 15-vector hostile review + audit-integrity probe all safe. One real finding this pass (raw trigger snippets in the persisted audit) was reproduced → fixed → regression-tested → documented. |
| **Evaluation** | ✅ PASS | Dispute 83.3%→0% (FP 0%); ablation detection-only 6.7%, L3 0%; hardened-prompt baseline 16.7% and fails 100% on gaming; KYB 87.5%→0% (FP 0%). |
| **Held-out** | ✅ PASS | Independently authored, disjoint from dev corpus (asserted); no held-out literals in `firewall/`; reproduces 0% guarded ASR, 0% FP on 12 unseen attacks + 5 controls. |
| **Live LLM** | ⚠️ NOT AVAILABLE | No `ANTHROPIC_API_KEY` in this environment. `make live-check` correctly reports the missing key; `scripts/live_run.py` is written and type-checked but unrun. No live numbers are quoted anywhere. |
| **API** | ✅ PASS | 14 tests (pure + HTTP): `POST /api/evaluate`, `/health`, `/version`, `/api/audit/<id>`; bad JSON 400, invalid surface 400, oversized 413, unknown route 404, bearer-token auth. Production-startup smoke: health→200, evaluate→200. |
| **Demo** | ✅ PASS | Browser console verified: 8 presets, each showing L1→L2→Agent→L3→L4; all 6 attacks BREACH with firewall off / denied on; both legitimate cases approved either way. |
| **Testing** | ✅ PASS | **83 tests pass** offline (no key); security-critical behaviour covered by trust-boundary, held-out, security-review, session, policy and audit tests. |
| **Coverage** | ✅ PASS | **91.46%** (firewall/agents/api); CI gate `--cov-fail-under=85`. pipeline/detect/normalize/audit/session at 100%. |
| **Fresh clone** | ✅ PASS | Cloned from GitHub into a clean dir, followed only the README: `make test` (83), `make lint`, `make offline` (0%/0%), `make bench`, API smoke (200/200) — all green. `make offline` needs zero dependencies (charts skip gracefully without matplotlib). |
| **Docker** | ⚠️ NOT AVAILABLE | Docker CLI not installed here, so `docker build` could not run. `Dockerfile` (non-root, HEALTHCHECK, offline-by-default) + `.dockerignore` present but the build is unverified on this machine. |
| **Documentation** | ✅ PASS | README claims cross-checked against reproduced output; test count is a single source of truth (83); ARCHITECTURE/THREAT_MODEL/EVALUATION/API/DEPLOYMENT/DECISIONS/TESTING/LIMITATIONS/PERFORMANCE/RESUME/DEMO current. |
| **Resume readiness** | ✅ PASS | A stranger can clone, run `make offline`, open the demo, run 83 tests, read the evaluation, and inspect a trust boundary that is real in code and proven by tests — with no missing setup. |

## Bug found and fixed this pass

**Audit privacy leak (fixed).** The audit trail documented "stores a hash, never
the prose", but L2 detection's matched-trigger `span` snippets (bounded raw
untrusted text) were persisted — e.g. `"refund me"` appeared on disk. The prior
test only checked non-trigger text. Fix: `firewall/audit._redact()` hashes any
`span` to `span_sha256` + `span_len` before writing; the trigger name/score stay
auditable. The audit log was already injection-safe (`json.dumps` escapes
newlines, so attacker text cannot forge a log line or field). Regression test
strengthened to assert a triggering phrase does not leak.

## Honest gaps (unchanged, by design)

- Offline agent is a deterministic **simulation** of the failure mode, not an LLM.
- Corpora are small and synthetic; L2 is lexical (deliberately not the backstop).
- Live mode and Docker build were not executed here (no key / no Docker).

## Verdict

**Release-ready for a resume/portfolio.** No blocking issues remain. The one real
finding was fixed with a regression test. Live-LLM numbers and a verified Docker
build are the only optional items, and both are honestly marked NOT AVAILABLE
rather than faked.
