# Performance & complexity

All figures are the platform's **own** overhead in offline mode (no model
latency), measured by `sentinel bench` / `sentinel eval run --suite performance`
and written to `results/performance.json`. Machine-dependent; reproduce locally.

## Measured (macOS-26.5.2-arm64-arm-64bit-Mach-O, Python 3.13.7)

| Component | Workload | p50 ms | p95 ms | p99 ms | ops/s |
|---|---|---:|---:|---:|---:|
| `normalize` | 310-char narrative | 0.0175 | 0.0187 | 0.0215 | 56,204 |
| `gateway_inspect` | same narrative, 11 signals | 0.175 | 0.1858 | 0.2044 | 5,658 |
| `claim_classify` | same narrative | 0.0191 | 0.0214 | 0.0325 | 51,114 |
| `evidence_reconcile` | 8 ledger facts + claim | 0.0219 | 0.0245 | 0.0418 | 44,316 |
| `risk_score_transaction` | 40-txn baseline, 26 rules | 0.0117 | 0.0131 | 0.0193 | 81,802 |
| `graph_linked_accounts` | 8,144-node graph | 0.0041 | 0.0043 | 0.0046 | 238,229 |
| `graph_neighborhood_d2` | depth-2 neighbourhood | 0.1592 | 0.1707 | 0.2171 | 6,192 |
| `policy_evaluate` | 9 rules, 10-field context | 0.0077 | 0.008 | 0.0097 | 127,761 |
| `decision_compose` | full DecisionInputs | 0.0306 | 0.0342 | 0.0638 | 31,375 |
| `audit_append` | in-memory chain | 0.0088 | 0.0113 | 0.0336 | 102,985 |
| `e2e_dispute_pipeline` | gateway → agent → evidence → policy → authorization | 0.4246 | 0.5501 | 1.3747 | 2,200 |

Context: a real back-office LLM call is 300–2,000 ms. The full protected
pipeline adds ≈0.5501 ms at p95 -- about three orders of magnitude
below the decision it protects. The per-decision SQLite writes (risk
assessment, evidence, decision + snapshot, audit event) are not in this
figure; the API's in-process metrics (`GET /v1/system`) report them live.

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
| policy | all rules over a flat context | O(r) = O(1) |
| compose + authorize | constant | O(1) |
| audit append | one hash over canonical JSON | O(record) |

The protected path holds no cross-request state except the audit chain
head, so it scales horizontally per account partition; the chain would be
sharded per tenant at scale.

## Reproduce

```bash
make bench
```
