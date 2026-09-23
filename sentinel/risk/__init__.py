"""Deterministic financial risk intelligence.

    transaction.py    transaction risk: feature extraction over trusted records
    behavioral.py     per-entity behavioural baselines and deviations
    entity.py         customer / account / merchant / device risk profiles
    graph.py          lightweight entity relationship graph used by the above
    scoring.py        versioned weight tables: features -> explainable score
    account_security.py  login / session risk and the account-security decision
    monitoring.py     synthetic transaction-monitoring (AML-style) patterns
    dispute.py        dispute-level risk

Every score is a sum of named factors, each pointing at the evidence it read.
The bands (0-24 LOW, 25-49 MEDIUM, 50-74 HIGH, 75-100 CRITICAL) are Sentinel's
internal scale, not an industry standard. No ML is claimed: this is a
transparent, replayable rule model over deterministic synthetic history.
"""
