# Performance & complexity

All figures are the platform's **own** overhead in offline mode (no model
latency), measured by `sentinel bench` / `sentinel eval run --suite performance`
and written to `results/performance.json`; this file is rendered from it by
`make docs`. Sequential, single-threaded, persistence excluded;
machine-dependent -- reproduce locally.

## Measured (macOS-27.0.1-arm64-arm-64bit-Mach-O, Python 3.13.7)

| Component | Workload | p50 ms | p95 ms | p99 ms | ops/s |
|---|---|---:|---:|---:|---:|
| `normalize` | 310-char narrative | 0.0171 | 0.0185 | 0.0233 | 57,487 |
| `gateway_inspect` | same narrative, 13 signals | 0.2238 | 0.2401 | 0.2609 | 4,425 |
| `claim_classify` | same narrative | 0.2569 | 0.2734 | 0.2927 | 3,850 |
| `evidence_reconcile` | ledger facts + claim | 0.0365 | 0.0402 | 0.0485 | 26,604 |
| `fact_verify` | Ed25519 fact envelope: canonical JSON, digest, signature, times | 0.1807 | 0.192 | 0.2126 | 5,462 |
| `risk_score_transaction` | 40-txn baseline, 33 rules | 0.0235 | 0.0254 | 0.0312 | 41,804 |
| `graph_linked_accounts` | 8,403-node graph | 0.004 | 0.0042 | 0.0051 | 243,140 |
| `graph_neighborhood_d2` | depth-2 neighbourhood | 0.0541 | 0.0576 | 0.0612 | 18,112 |
| `policy_evaluate` | 17 rules, 27-field context (the composer's real context) | 0.0187 | 0.0194 | 0.0241 | 52,648 |
| `decision_compose` | full DecisionInputs | 0.0493 | 0.055 | 0.069 | 19,867 |
| `audit_append` | in-memory chain | 0.0088 | 0.0104 | 0.0159 | 108,423 |
| `e2e_dispute_pipeline` | fact verification → gateway → agent → evidence → policy → authorization | 0.317 | 0.3412 | 0.4072 | 3,111 |

Context: the full protected pipeline adds ≈0.3412 ms at p95 on this
machine. A live model call's latency is not measured here (the live rows are
NOT RUN), so no comparison with it is claimed. The per-decision SQLite writes (risk
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
