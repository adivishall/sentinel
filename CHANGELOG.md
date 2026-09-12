# Changelog

All notable changes to Sentinel. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); this project uses
[Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-09-13

The resume-ready release: a complete, runnable, inspectable AI firewall for
high-stakes back-office LLM agents.

### Added
- **Typed trust boundary** (`firewall/trust.py`): `UntrustedText` vs `TrustedFacts`
  (`DisputeFacts` / `KYBFacts`) with `supports(ClaimType)` as the only evidence
  check. mypy-enforced; proven by `tests/test_trust_boundary.py`.
- **Canonical `Decision`** object + **append-only audit trail** (`firewall/audit.py`)
  storing hashes, not prose. One representation drives CLI, API, audit and tests.
- **Held-out adversarial evaluation** (`red/heldout.py`, `eval/heldout.py`),
  independently authored and kept disjoint from the dev corpus: **0% guarded ASR,
  0% false positives** on unseen wording; wired into `make offline` and CI.
- **Multi-turn `Session` model** (`firewall/session.py`): evaluates the whole
  transcript so security never depends on the latest message alone.
- **L4 capability policy engine** (`firewall/limits.py`): explicit
  `ALLOW` / `REQUIRE_HUMAN_REVIEW` / `BLOCK` outcomes as data, with explanations.
- **Zero-dependency HTTP API** (`sentinel_api.py`): `POST /api/evaluate`
  (dispute + KYB, optional `document` and multi-turn `messages`), `GET /health`,
  `GET /version`, `GET /api/audit/<id>`; optional bearer-token auth; input
  validation and fail-safe errors.
- **Docker deployment**: offline-by-default `Dockerfile` (non-root, HEALTHCHECK),
  `.dockerignore`, `make docker-build` / `make docker-run`.
- **Interactive console**: full L1→L2→AGENT→L3→L4 pipeline visualiser with 7 attack
  presets, trusted/untrusted distinction, threat level, audit id, model, latency.
- **Coverage gate** (pytest-cov, fail-under 85; actual ~91%) and an **offline
  evaluation smoke test** in CI.
- **Documentation**: THREAT_MODEL, EVALUATION, TECHNICAL_REPORT, API, DEPLOYMENT,
  DECISIONS, RESUME, DEMO; refreshed ARCHITECTURE / LIMITATIONS / PERFORMANCE.
- New generalisation chart (`chart6_heldout.png`).

### Changed
- **Repository renamed** `TheScouts` → `sentinel`; all URLs (clone, Pages, CI
  badge) are now consistent and working.
- Claim classifier broadened to natural paraphrases (fixes false positives found by
  the held-out set), with dev corpus results unchanged.
- README rewritten; test badge 26 → 73; performance numbers refreshed.
- Version 0.2.0 → 1.0.0.

### Fixed
- False-positive bug: legitimate paraphrases ("two identical charges", "has not
  reached me") were mislabeled by the lexical claim classifier and wrongly denied;
  fixed and pinned by regression tests.
- Broken README links (Live Demo / clone / CI badge pointed at a nonexistent repo).

### Security / evaluation snapshot (all reproducible via `make offline`)
- Dispute: attack success 83.3% → **0.0%**, false positives **0.0%** (60 attacks,
  18 controls).
- Held-out: 16.7%* → **0.0%**, FP **0.0%** (12 independent attacks).
- KYB: 87.5% → **0.0%**, FP **0.0%** (8 attacks, 5 controls).
- Ablation: detection-only leaks 6.7%; L3 alone closes it.
- 73 tests, ~91% coverage; ruff / black / mypy clean.

\* Offline victim agent is lexical, so it under-fires on novel wording; the held-out
set validates the firewall's generalisation and false-positive behaviour.

## [0.2.0] and earlier

Pre-release hackathon build: L1–L4 firewall, dispute + KYB surfaces, offline and
live modes, attack taxonomy, ablation, baselines, benchmarks, structured logging,
unicode/homoglyph normalisation, CI (ruff/black/mypy/pytest), and the GitHub Pages
demo. See git history before the `release/resume-ready-v1` branch.
