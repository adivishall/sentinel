# Performance & complexity

All figures are the platform's **own** overhead in offline mode (no model
latency), measured by `sentinel bench` / `sentinel eval run --suite performance`
and written to `results/performance.json`; this file is rendered from it by
`make docs`. Sequential, single-threaded, persistence excluded;
machine-dependent -- reproduce locally.

## Measured (macOS-26.5.2-arm64-arm-64bit-Mach-O, Python 3.13.7)

| Component | Workload | p50 ms | p95 ms | p99 ms | ops/s |
|---|---|---:|---:|---:|---:|
| `normalize` | 310-char narrative | 0.0178 | 0.0184 | 0.0187 | 56,809 |
| `gateway_inspect` | same narrative, 13 signals | 0.2226 | 0.2258 | 0.2295 | 4,490 |
| `claim_classify` | same narrative | 0.2557 | 0.26 | 0.2672 | 3,907 |
| `evidence_reconcile` | ledger facts + claim | 0.0342 | 0.0347 | 0.0391 | 28,995 |
| `risk_score_transaction` | 40-txn baseline, 33 rules | 0.0145 | 0.0147 | 0.0168 | 68,335 |
| `graph_linked_accounts` | 8,403-node graph | 0.0039 | 0.004 | 0.0041 | 250,753 |
| `graph_neighborhood_d2` | depth-2 neighbourhood | 0.053 | 0.0555 | 0.0586 | 18,562 |
| `policy_evaluate` | 14 rules, 26-field context (the composer's real context) | 0.0145 | 0.0147 | 0.0174 | 65,707 |
| `decision_compose` | full DecisionInputs | 0.0372 | 0.0385 | 0.0431 | 26,672 |
| `audit_append` | in-memory chain | 0.0086 | 0.0098 | 0.0107 | 113,888 |
| `e2e_dispute_pipeline` | gateway → agent → evidence → policy → authorization | 0.7163 | 0.7267 | 0.7677 | 1,392 |

Context: a real back-office LLM call is 300–2,000 ms. The full protected
pipeline adds ≈0.7267 ms at p95 -- about three orders of magnitude
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
