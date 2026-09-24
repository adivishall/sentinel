"""Sentinel -- Financial Decision Security Infrastructure for AI-native finance.

    AI may recommend. Trusted evidence, deterministic risk controls and explicit
    policy authorize.

The package is a modular monolith. Each sub-package owns one concern and the
dependency direction is strictly downward:

    domain      typed primitives (entities, evidence, risk, security, decisions, cases)
    security    provenance, normalisation, injection detection, trust boundary,
                capability registry, the AI Security Gateway
    risk        transaction / behavioural / entity / graph risk, account security,
                transaction monitoring
    evidence    claim <-> trusted-fact reconciliation, contradiction engine
    policy      versioned policy-as-code and the deterministic engine
    agents      LLM provider abstraction + the (deliberately naive) agents
    decision    the canonical decision composer and workflows
    cases       investigation / case management
    audit       tamper-evident hash chain
    data        deterministic synthetic data generator + SQLite repositories
    replay      re-run a decision under a different policy / risk model
    evaluation  security, financial, integrity and performance benchmarks
    api / cli / app   the application layer (one engine, three surfaces)
"""

__version__ = "2.0.1"
