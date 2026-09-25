# Performance & complexity

All figures are the platform's **own** overhead in offline mode (no model
latency), measured by `sentinel bench` / `sentinel eval run --suite performance`
and written to `results/performance.json`; this file is rendered from it by
`make docs`. Sequential, single-threaded, persistence excluded;
machine-dependent -- reproduce locally.

## Measured (macOS-26.5.2-arm64-arm-64bit-Mach-O, Python 3.13.7)

| Component | Workload | p50 ms | p95 ms | p99 ms | ops/s |
|---|---|---:|---:|---:|---:|
| `normalize` | 310-char narrative | 0.0176 | 0.0182 | 0.0243 | 56,195 |
| `gateway_inspect` | same narrative, 13 signals | 0.2223 | 0.2308 | 0.246 | 4,481 |
| `claim_classify` | same narrative | 0.0186 | 0.0189 | 0.0228 | 53,282 |
| `evidence_reconcile` | ledger facts + claim | 0.0343 | 0.0357 | 0.0424 | 28,793 |
| `risk_score_transaction` | 40-txn baseline, 33 rules | 0.0145 | 0.0152 | 0.0205 | 67,001 |
| `graph_linked_accounts` | 8,219-node graph | 0.0045 | 0.0046 | 0.0047 | 218,168 |
| `graph_neighborhood_d2` | depth-2 neighbourhood | 0.1205 | 0.1261 | 0.1577 | 8,171 |
| `policy_evaluate` | 14 rules, 26-field context (the composer's real context) | 0.0132 | 0.0135 | 0.0169 | 70,650 |
| `decision_compose` | full DecisionInputs | 0.0366 | 0.038 | 0.0441 | 27,088 |
| `audit_append` | in-memory chain | 0.0088 | 0.0101 | 0.0132 | 110,118 |
| `e2e_dispute_pipeline` | gateway → agent → evidence → policy → authorization | 0.4847 | 0.5025 | 0.526 | 2,050 |

Context: a real back-office LLM call is 300–2,000 ms. The full protected
pipeline adds ≈0.5025 ms at p95 -- about three orders of magnitude
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
| claim classification | a handful of regexes | O(n) |
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
