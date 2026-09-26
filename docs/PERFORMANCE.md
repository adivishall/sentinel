# Performance & complexity

All figures are the platform's **own** overhead in offline mode (no model
latency), measured by `sentinel bench` / `sentinel eval run --suite performance`
and written to `results/performance.json`; this file is rendered from it by
`make docs`. Sequential, single-threaded, persistence excluded;
machine-dependent -- reproduce locally.

## Measured (macOS-26.5.2-arm64-arm-64bit-Mach-O, Python 3.13.7)

| Component | Workload | p50 ms | p95 ms | p99 ms | ops/s |
|---|---|---:|---:|---:|---:|
| `normalize` | 310-char narrative | 0.0172 | 0.0185 | 0.0188 | 57,449 |
| `gateway_inspect` | same narrative, 13 signals | 0.222 | 0.2267 | 0.2329 | 4,495 |
| `claim_classify` | same narrative | 0.2567 | 0.2629 | 0.2725 | 3,884 |
| `evidence_reconcile` | ledger facts + claim | 0.0347 | 0.0355 | 0.0399 | 28,421 |
| `risk_score_transaction` | 40-txn baseline, 33 rules | 0.0147 | 0.015 | 0.0162 | 67,375 |
| `graph_linked_accounts` | 8,403-node graph | 0.0039 | 0.004 | 0.0042 | 254,748 |
| `graph_neighborhood_d2` | depth-2 neighbourhood | 0.0529 | 0.0548 | 0.0597 | 18,635 |
| `policy_evaluate` | 14 rules, 26-field context (the composer's real context) | 0.0148 | 0.0152 | 0.0168 | 66,868 |
| `decision_compose` | full DecisionInputs | 0.0386 | 0.0393 | 0.044 | 25,748 |
| `audit_append` | in-memory chain | 0.0088 | 0.0102 | 0.0135 | 110,537 |
| `e2e_dispute_pipeline` | gateway → agent → evidence → policy → authorization | 0.7185 | 0.734 | 0.7529 | 1,387 |

Context: a real back-office LLM call is 300–2,000 ms. The full protected
pipeline adds ≈0.734 ms at p95 -- about three orders of magnitude
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
