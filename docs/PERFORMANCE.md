# Performance & complexity

All figures are the platform's **own** overhead in offline mode (no model
latency), measured by `sentinel bench` / `sentinel eval run --suite performance`
and written to `results/performance.json`; this file is rendered from it by
`make docs`. Sequential, single-threaded, persistence excluded;
machine-dependent -- reproduce locally.

## Measured (macOS-26.5.2-arm64-arm-64bit-Mach-O, Python 3.13.7)

| Component | Workload | p50 ms | p95 ms | p99 ms | ops/s |
|---|---|---:|---:|---:|---:|
| `normalize` | 310-char narrative | 0.0174 | 0.0184 | 0.0211 | 56,869 |
| `gateway_inspect` | same narrative, 11 signals | 0.1736 | 0.1832 | 0.2002 | 5,716 |
| `claim_classify` | same narrative | 0.019 | 0.0202 | 0.0241 | 51,935 |
| `evidence_reconcile` | 8 ledger facts + claim | 0.0216 | 0.0241 | 0.0304 | 45,546 |
| `risk_score_transaction` | 40-txn baseline, 26 rules | 0.0117 | 0.0126 | 0.0149 | 83,930 |
| `graph_linked_accounts` | 8,144-node graph | 0.0041 | 0.0042 | 0.0051 | 239,075 |
| `graph_neighborhood_d2` | depth-2 neighbourhood | 0.1567 | 0.1735 | 0.1934 | 6,258 |
| `policy_evaluate` | 9 rules, 10-field context | 0.0088 | 0.0094 | 0.0153 | 109,427 |
| `decision_compose` | full DecisionInputs | 0.0317 | 0.0349 | 0.0431 | 31,082 |
| `audit_append` | in-memory chain | 0.0085 | 0.0101 | 0.0142 | 112,422 |
| `e2e_dispute_pipeline` | gateway → agent → evidence → policy → authorization | 0.4181 | 0.4556 | 0.5725 | 2,354 |

Context: a real back-office LLM call is 300–2,000 ms. The full protected
pipeline adds ≈0.4556 ms at p95 -- about three orders of magnitude
below the decision it protects. The per-decision SQLite writes (risk
assessment, evidence, decision + snapshot, audit event) are not in this
figure; the API's in-process metrics (`GET /v1/system`) report them live.
"ops/s" is 1000 / mean over a sequential loop, not a concurrency figure.

## Complexity

Let `n` = untrusted text length, `s` = detector signals (11, constant), `h` =
account history size read for the baseline (capped at 500), `r` = policy
rules (constant), `d` = graph degree.

| Stage | Work | Complexity |
|---|---|---|
| validate + normalise | scan, fold, NFKC | O(n) |
| gateway | `s` bounded-quantifier regexes; no `.*` across alternations | O(s·n) = O(n) |
| claim classification | 5 regexes | O(n) |
| baseline | statistics over recent history | O(h) |
| transaction features | 1-hour window scan over recent history | O(h) |
| entity profiles | indexed per merchant / account, cached per snapshot | O(1) amortised |
| graph queries | adjacency lookups; depth-2 neighbourhood bounded to 200 nodes | O(d) / O(d²) bounded |
| cycle search (monitoring) | DFS through transfer edges, path length ≤ 5, **not time-bounded** | O(d⁵) worst case |
| policy | all rules over a flat context | O(r) = O(1) |
| compose + authorize | constant | O(1) |
| audit append | one hash over canonical JSON | O(record) |

The protected path holds no cross-request state except the audit chain
head, so it scales horizontally per account partition; the chain would be
sharded per tenant at scale. The audit backends re-read the whole log for
`events()`, `get()` and `verify()` (O(n) per call), which is fine for a lab
store and would be an indexed lookup in production.

## Reproduce

```bash
make bench
make docs
```
