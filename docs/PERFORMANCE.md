# Performance & complexity

The firewall is designed to be negligible next to the LLM call it wraps. All
figures below are the firewall's **own** overhead (offline mode, agent/LLM
cognition excluded), measured by `python3 eval/bench.py` on the 78-case corpus.

## Measured overhead

| Metric | Value |
|---|---|
| Decisions measured | 1,560 |
| Mean latency | **0.074 ms** |
| p50 / p95 / p99 | 0.072 / 0.097 / 0.104 ms |
| Throughput (single core) | **~13,500 decisions/sec** |

Context: a real back-office LLM call is 300–2000 ms. The firewall adds well under
0.1 ms — **~4–5 orders of magnitude smaller than the decision it protects.** It is
never the bottleneck.

## Complexity

Let `n` = length of the submission (chars), `s` = number of detector signals
(constant, 6), `k` = number of ledger fields (constant).

| Layer | Work | Complexity |
|---|---|---|
| L0 validate | length + type check | `O(n)` |
| normalise | NFKC + homoglyph fold + zero-width strip | `O(n)` |
| L1 provenance | wrap/delimit untrusted span | `O(n)` |
| L2 detection | `s` regex scans over the span | `O(s·n)` = `O(n)` |
| L3 adjudication | extract `k` facts from ledger, compare | `O(k)` = `O(1)` |
| L4 limits | threshold checks | `O(1)` |
| **Pipeline total** | | **`O(n)`** in the submission size |

The firewall is **linear in input size and constant in policy size** — it holds no
graph and no cross-request state, so it scales horizontally without coordination.
Each regex is linear (no catastrophic backtracking: the patterns use bounded
quantifiers like `.{0,40}`, not unbounded `.*` across alternations).

## Why L3 is cheap *and* decisive

L3 does `O(1)` work — it reads a handful of verified fields from the bank's own
records and compares them to the claim type. It never parses the attacker's prose.
That is exactly why it is both the cheapest layer and the one immune to text-level
attacks: there is nothing in the untrusted input for it to be fooled by.

## Reproduce

```bash
make bench      # or: python3 eval/bench.py
```
