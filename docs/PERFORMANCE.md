# Performance & complexity

All figures are the platform's **own** overhead in offline mode (no model
latency), measured by `sentinel bench` / `sentinel eval run --suite performance`
and written to `results/performance.json`; this file is rendered from it by
`make docs`. Sequential, single-threaded, persistence excluded;
machine-dependent -- reproduce locally.

## Measured (macOS-26.5.2-arm64-arm-64bit-Mach-O, Python 3.13.7)

| Component | Workload | p50 ms | p95 ms | p99 ms | ops/s |
|---|---|---:|---:|---:|---:|
| `normalize` | 310-char narrative | 0.0178 | 0.0187 | 0.0209 | 55,706 |
| `gateway_inspect` | same narrative, 13 signals | 0.233 | 0.2664 | 0.3281 | 4,181 |
| `claim_classify` | same narrative | 0.264 | 0.317 | 0.3919 | 3,672 |
| `evidence_reconcile` | ledger facts + claim | 0.0361 | 0.0413 | 0.1019 | 26,009 |
| `fact_verify` | Ed25519 fact envelope: canonical JSON, digest, signature, times | 0.177 | 0.2302 | 0.4146 | 5,277 |
| `risk_score_transaction` | 40-txn baseline, 33 rules | 0.0149 | 0.0174 | 0.0608 | 61,828 |
| `graph_linked_accounts` | 8,403-node graph | 0.004 | 0.0047 | 0.0069 | 234,666 |
| `graph_neighborhood_d2` | depth-2 neighbourhood | 0.0578 | 0.0642 | 0.2271 | 16,499 |
| `policy_evaluate` | 14 rules, 26-field context (the composer's real context) | 0.0149 | 0.0173 | 0.0377 | 63,593 |
| `decision_compose` | full DecisionInputs | 0.0398 | 0.0482 | 0.0883 | 23,885 |
| `audit_append` | in-memory chain | 0.009 | 0.0114 | 0.0288 | 102,580 |
| `e2e_dispute_pipeline` | fact verification → gateway → agent → evidence → policy → authorization | 0.9452 | 1.1244 | 1.2266 | 1,025 |

Context: a real back-office LLM call is 300–2,000 ms. The full protected
pipeline adds ≈1.1244 ms at p95 -- about three orders of magnitude
below the decision it protects. The per-decision SQLite writes (risk
assessment, evidence, decision + snapshot, audit event) are not in this
figure; the API's in-process metrics (`GET /v1/system`) report them live.
"ops/s" is 1000 / mean over a sequential loop, not a concurrency figure.

## Complexity

Let `n` = untrusted text length, `s` = detector signals (13, constant), `h` =
account history size read for the baseline (capped at 500), `r` = policy
rules (constant), `d` = graph degree, `w` = edges inside a time window.

| Stage | Work | Complexity |
|---|---|---|
| validate + normalise | scan, fold, NFKC | O(n) |
| gateway | `s` bounded-quantifier regexes; no `.*` across alternations | O(s·n) = O(n) |
| claim classification | weighted pattern families (~60 patterns), negation and hedge guards | O(n) |
| baseline | statistics over the account's history before the transaction | O(h) |
| transaction features | 1-hour / 10-minute window scans over recent history; 24 h session window | O(h) |
| entity profiles | indexed per merchant / account, cached per (entity, as-of) | O(1) amortised |
| graph queries | adjacency lookups filtered by edge timestamp; depth-2 neighbourhood bounded to 200 nodes; the API/console rendering bounded to 80 nodes | O(d) / O(d²) bounded |
| cycle search (monitoring) | DFS through transfer edges, path length ≤ 5, **every hop inside the last 30 days** (`cycle_window_days`) | O(w⁵) worst case, w ≪ d |
| policy | all rules over a flat context | O(r) = O(1) |
| compose + authorize | constant | O(1) |
| audit append | one hash over canonical JSON | O(record) |
| audit lookup by id / decision | indexed (`find`) on the JSONL and SQLite backends | O(1) / O(log n) |
| audit verify | recompute from genesis | O(n) |

The protected path holds no cross-request state except the audit chain
head, so it scales horizontally per account partition; the chain would be
sharded per tenant at scale. `verify()` is a full re-computation by design;
a checkpoint (`docs/AUDIT_MODEL.md`) lets an operator confirm that the stored
prefix still hashes to a known-good head.

## Reproduce

```bash
make bench
make docs
```
