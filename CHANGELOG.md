# Changelog

All notable changes to Sentinel. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); this project uses
[Semantic Versioning](https://semver.org/).

## [2.0.0] — 2026-09-23

**Sentinel becomes Financial Decision Security Infrastructure.** The v1
four-layer LLM firewall is generalised into a platform where every financial
surface -- transactions, disputes, merchant onboarding, account security,
investigations, AI-agent inputs and outputs -- flows through one pipeline:

```text
untrusted information → AI Security Gateway → risk intelligence → AI recommendation
→ trusted-evidence adjudication → deterministic policy → capability authorization
→ human review → action → case → tamper-evident audit → replay
```

### Added
- **Domain model** (`sentinel/domain`): typed, immutable entities, Evidence
  with a structural claim-vs-verified-fact distinction, RiskAssessment,
  SecurityEvent, the canonical Decision, Case, an in-process typed event bus.
- **Trust / provenance model**: seven `TrustClass` values; only
  `TRUSTED_INTERNAL` and `VERIFIED_EXTERNAL` can authorize; model output is
  `MODEL_GENERATED` and can never become VERIFIED evidence.
- **AI Security Gateway** (`sentinel/security`): 12-class threat taxonomy,
  expanded explainable signal set (context poisoning, tool manipulation,
  capability requests, social pressure, indirect/document reclassification),
  unicode-obfuscation accounting, multi-turn split-payload detection, and
  inspection of model output for off-surface capability requests.
- **Capability registry**: per-capability risk, reversibility, monetary
  impact, allowed actors, required authorization, human-review thresholds;
  `AI_AGENT` allowed on no consequential capability; `SKIP_REVIEW` on none.
- **Policy-as-code** (`sentinel/policy`): versioned JSON policies validated
  against a field catalog; deterministic, order-independent evaluation with
  complete explanations; fail-safe on missing required fields. Ships
  `dispute-refund` v1/v2, `transaction-authorization` v1/v2,
  `merchant-onboarding`, `account-security`, `investigation`.
- **Evidence reconciliation + contradiction engine** (`sentinel/evidence`):
  SUPPORTED / UNSUPPORTED / CONTRADICTED / INSUFFICIENT with first-class
  Contradiction objects.
- **Decision composer** (`sentinel/decision/composer.py`): the one place an
  outcome is computed, from a `_TrustedView` with no model-recommendation
  field; controls toggles for the ablation.
- **Risk engine** (`sentinel/risk`): versioned weight tables, behavioural
  baselines, an entity relationship graph, entity profiles (device → merchant
  → account → customer), transaction risk with 13 signal families, account
  security, and a labelled transaction-monitoring simulation (structuring-like,
  rapid movement, velocity, 24h bursts, geography shifts, exposure, circular
  transfers, dormant activation, shared-device rings, linked-entity risk).
- **Workflows** for disputes, transactions, KYB, account security,
  investigations and AI-security-only evaluation; multi-turn dispute sessions.
- **Cases** with deterministic opening rules, a guarded lifecycle and
  human-only resolution.
- **Tamper-evident audit chain** (`hash_n = SHA256(event_n ‖ hash_n-1)`) with
  memory / JSONL / SQLite backends and `sentinel audit verify`.
- **Deterministic synthetic data generator** with correlated behaviour and
  nine labelled scenarios; **SQLite store** with decision input snapshots.
- **Replay engine**: rerun a decision under another policy version, rule
  threshold, risk model version, model recommendation or control set, with a
  field-level diff and explanation; replays are audited.
- **Application layer** (`sentinel/app.py`), **versioned API** (`/v1/...`),
  **CLI** (`sentinel ...`), and a **console** (`ui/`) that only renders engine
  output, with a static snapshot mode for hosting.
- **Unified evaluation**: security (ASR = unauthorised capability executed,
  detection recall, false positives, escalation), held-out, KYB, baselines,
  8-configuration ablation, multi-level financial risk metrics on labelled
  data, decision-integrity suite, component benchmarks, provider comparison,
  charts; `sentinel eval run --suite full`.
- **Ten security invariants** with property-based tests (Hypothesis), a
  hostile-vector suite, trust-boundary proofs re-pinned against the new
  modules; CI runs lint, types, coverage gate, invariants, evaluation smoke,
  CLI + audit smoke and a Docker build.
- Documentation rewritten: README, ARCHITECTURE, THREAT_MODEL, EVALUATION,
  DECISIONS, INTERVIEW, API, DEPLOYMENT, TESTING, DEMO, LIMITATIONS,
  PERFORMANCE, RESUME.

### Changed
- The v1 `firewall/`, `agents/`, `red/`, `eval/`, `llm.py`, `sentinel_api.py`
  and `console/` are retired; their ideas and their test pins live on in the
  new package and suite. The v1 console's JavaScript re-implementation of the
  firewall is gone: the UI has no decision logic.
- "Attack success" now means an unauthorised consequential capability
  executed, not "the detector flagged the sentence".
- Held-out evaluation surfaced a false positive on a novel cancellation
  phrasing ("called off the booking"); the general pattern was broadened.
- v1 reports archived under `docs/archive/`.

## [1.0.1] — 2026-09-13
Final-audit patch: audit redaction of matched-trigger snippets; test count
corrections. See `docs/archive/`.

## [1.0.0] — 2026-09-13
The v1 four-layer AI firewall (typed trust boundary, structured adjudication,
capability limits, held-out evaluation, zero-dependency API, interactive
console). See `docs/archive/`.
