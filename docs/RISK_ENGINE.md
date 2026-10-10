# Risk engine

Rendered by `make docs` from `sentinel/risk/scoring.py`, `transaction.py`,
`monitoring.py`, `account_security.py`, `dispute.py` and `entity.py`. The
point values and conditions below **are** the model; the prose explains it.

## What this is, and is not

A **deterministic, versioned, factor-level explainable rule model**. Each
factor is a named condition over trusted records; a factor that fires
contributes its point value; the total is capped at 0–100 and banded. Every
assessment stores its feature snapshot so it can be re-scored under another
model version (`sentinel replay run … --risk-model`) without re-reading any
source system. The score is a *recommendation to policy*, never an action.

It is **not** a trained model and the point values are **not industry
standards**. They are Sentinel heuristics chosen while looking at the
development seed of the synthetic generator; `docs/EVALUATION.md` §G reports
how they behave on that seed and on two held-out seeds (not used to set the values,
though their results were visible before txn-2.0 was designed). Nothing here is
calibrated on real payment data.

| Band | Score | Recommended action (risk engine's own suggestion; policy decides) |
|---|---|---|
| LOW | 0–24 | ALLOW |
| MEDIUM | 25–49 | STEP_UP |
| HIGH | 50–74 | REQUIRE_REVIEW |
| CRITICAL | 75–100 | BLOCK |

## Model versions (`scoring.MODELS`)

| Version | Surface | Status | Factors | Thresholds | Description |
|---|---|---|---:|---:|---|
| `txn-1.0` | transaction | historical (replay / what-if only) | 28 | 5 | Initial transaction model. |
| `txn-1.1` | transaction | historical (replay / what-if only) | 28 | 5 | Geography weighted up, device weighted down, moderate-amount threshold 2.5σ. |
| `txn-2.0` | transaction | **active** | 33 | 10 | v1 plus short-window velocity, inter-arrival timing, recent trusted account-security events and shared payout instruments. |
| `acct-1.0` | login | **active** | 10 | 1 | — |
| `mon-1.0` | account | **active** | 10 | 4 | Single strong pattern -> HIGH; combinations -> CRITICAL. Sentinel demo values. |
| `disp-1.0` | dispute | **active** | 7 | 0 | — |

Authoritative evaluation always scores with the active model of its surface
(`scoring.ACTIVE`); a request cannot select another, and a model is only ever
applied to its own surface (`scoring.model_for`). Historical models exist for
replay and what-if comparison (`docs/SECURITY_MODEL.md`, evaluation authority).

`txn-1.0` → `txn-1.1` exists so replay can show a *model* change (geography
weighted up, device weighted down, moderate-amount threshold raised).
`txn-2.0`, the default, adds short-window velocity and inter-arrival timing
(a burst becomes visible on the 4th transaction, once 3 precede it inside 10 minutes, instead of the 9th),
trusted account-security events in the 24 h before a transaction (the takeover
pattern: a payout change or a failed second factor shortly before a purchase)
and payout-instrument sharing across accounts (the ring pattern).

## Point-in-time invariant

Every feature is computed **as of the transaction** (or the monitoring
window's end): the behavioural baseline reads only earlier transactions and
only disputes filed earlier; device knowledge asks the time-aware graph
whether the device was used on the account at least 24 h *before*; entity
profiles are cached per `(entity, as_of)` and read only records at or before
`as_of`; every graph edge carries a timestamp and queries take `as_of`; the
monitoring cycle finder accepts only hops inside its window; an account's
status counts from when it took effect (`Account.status_at`) and payout
sharing reads the bank accounts held at T, not the current payout field (both
were current-state reads until the 2.2.0 temporal extension found them).

**What this is and is not.** It is a *tested temporal invariant*: every field
the engines read is either timestamped and read as of the decision, or a
static attribute, or deliberately current state -- and the benchmark checks
that nine kinds of later record never move an earlier decision. It is **not**
a fully event-sourced historical model: several fields have no history in the
data model, so a later change to them would not be visible as a change.

| Record field read by the engines | Time semantics | Consequence |
|---|---|---|
| transactions, disputes (`submitted_at`), login sessions | timestamped; read as of the decision | a later record is invisible to an earlier decision (benchmarked) |
| device `first_seen`, instrument `added_at`, graph edges | timestamped; read as of the decision | a later device, instrument or relationship is invisible (benchmarked) |
| account `opened_at`, merchant `registered_at` | timestamped; ages measured to the decision | -- |
| account `status` | as of the decision via `status_since` (2.2.0); a status with no recorded start is read as current | a later freeze is invisible (benchmarked); legacy data without a start date is current state |
| account payout destination | the bank accounts held at the decision time | a later payout change is invisible (benchmarked) |
| merchant `registration_status`, `prior_flags`, `mcc_risk` | static attributes set at registration; no history | a later re-classification would move earlier merchant scores -- not modelled; would need dated merchant events |
| dispute `refund_state`, `merchant_response`, transaction `status` | current state at the time the dispute is decided | correct for a live decision; replay uses the snapshot taken then, not today's values |
| stored risk assessments, AI-security events | never read by scoring | cannot leak (benchmarked) |

`results/temporal.json` measures it ("0 observed temporal leaks across the
tested synthetic benchmark" -- evidence for the invariant, not a proof); `tests/test_temporal_leakage.py` and
`tests/test_entity_pointintime.py` pin it.

## Transaction model (33 factors)

Inputs: the transaction; the account's baseline over its earlier history
(`risk/behavioral.py`: mean / stddev / median amount, daily count, median gap,
usual countries / devices / merchants / instruments, usual hours,
point-in-time chargeback rate); the last 24 h of trusted sessions; the
merchant's entity profile; device and instrument sharing from the graph as of
the transaction; the worst linked-entity profile.

| Factor | Label | Condition (`txn-2.0` thresholds) | Group | `txn-1.0` | `txn-1.1` | `txn-2.0` |
|---|---|---|---|---:|---:|---:|
| `amount_anomaly_extreme` | Amount far above account baseline | amount z-score ≥ 4σ above the account baseline mean | anomaly | 22 | 22 | 22 |
| `amount_anomaly_high` | Amount well above account baseline | 3σ ≤ z < 4σ | anomaly | 16 | 16 | 16 |
| `amount_anomaly_moderate` | Amount above account baseline | 2σ ≤ z < 3σ | anomaly | 10 | 10 | 10 |
| `amount_ratio_small_baseline` | Amount far above thin baseline | baseline has < 5 transactions and the amount is ≥ 10× its mean | anomaly | 12 | 12 | 12 |
| `velocity_burst` | Transaction burst | ≥ 8 transactions in the previous hour | velocity | 30 | 30 | 30 |
| `velocity_spike` | Transaction velocity spike | transactions in the previous hour ≥ max(5, 5 × baseline daily count) | velocity | 20 | 20 | 20 |
| `velocity_elevated` | Elevated transaction velocity | ≥ max(3, 3 × baseline daily count) in the previous hour, below the spike threshold | velocity | 10 | 10 | 10 |
| `rapid_fire` | Rapid-fire transactions | ≥ 3 transactions in the previous 10 minutes | velocity | — | — | 20 |
| `rapid_succession` | Unusually short gap since previous transaction | gap since the previous transaction < 15 min while the account's median gap is ≥ 6 h | velocity | — | — | 15 |
| `recent_account_changes` | Security-sensitive account change shortly before | a payout, credential or MFA change on a trusted session in the 24 h before the transaction | security | — | — | 20 |
| `recent_failed_mfa` | Failed second factor shortly before | a trusted session in the 24 h before did not pass the second factor | security | — | — | 8 |
| `shared_payout_instrument` | Payout instrument shared across accounts | ≥ 2 accounts share a bank account this account held at the time of the transaction | entity | — | — | 20 |
| `new_device` | New device | device not registered on the account (24 h rule) and first seen < 24 h ago, or never | device_geo | 17 | 12 | 17 |
| `young_account_shared_device` | Young account on a shared device | account < 30 days old on a device shared by ≥ 3 accounts | device_geo | 14 | 14 | 14 |
| `shared_device` | Device shared across accounts | device shared by ≥ 3 accounts (as of the transaction) | device_geo | 8 | 8 | 8 |
| `impossible_travel` | Impossible travel | any transaction from a different country within the previous 2 hours | device_geo | 20 | 24 | 20 |
| `new_country` | Unusual geography | country not among the baseline's usual countries | device_geo | 15 | 18 | 15 |
| `merchant_risk_critical` | Critical-risk merchant | merchant entity score ≥ 75 | entity | 15 | 15 | 15 |
| `merchant_risk_high` | High-risk merchant | merchant entity score 50–74, or a high-risk MCC with a score < 50 | entity | 10 | 10 | 10 |
| `merchant_risk_medium` | Medium-risk merchant | medium-risk MCC with a merchant score < 50 | entity | 5 | 5 | 5 |
| `account_age_new` | Very new account | account < 7 days old | entity | 10 | 10 | 10 |
| `account_age_young` | Young account | account 7–29 days old | entity | 5 | 5 | 5 |
| `new_instrument` | New payment instrument | payment instrument added < 1 day ago | device_geo | 6 | 6 | 6 |
| `auth_none` | No authentication | no customer authentication on the transaction | security | 12 | 12 | 12 |
| `auth_weak` | Weak authentication | password-only authentication | security | 8 | 8 | 8 |
| `chargeback_high` | High chargeback history | account chargeback rate ≥ 10% (disputes filed before the transaction only) | entity | 10 | 10 | 10 |
| `chargeback_some` | Some chargeback history | chargeback rate 3–10% | entity | 5 | 5 | 5 |
| `unusual_hour` | Unusual time of day | hour outside the baseline's usual hours (baseline ≥ 10 transactions) | anomaly | 6 | 6 | 6 |
| `new_merchant` | First transaction at this merchant | merchant never used by this account before (non-empty baseline) | anomaly | 4 | 4 | 4 |
| `repeat_merchant_burst` | Repeated merchant burst | ≥ 3 transactions at the same merchant in the previous hour | anomaly | 6 | 6 | 6 |
| `linked_entity_critical` | Linked entity critical risk | worst linked-entity risk ≥ 75 | entity | 12 | 12 | 12 |
| `linked_entity_high` | Linked entity high risk | worst linked-entity risk 50–74 | entity | 8 | 8 | 8 |
| `linked_entity_medium` | Linked entity medium risk | worst linked-entity risk 25–49 | entity | 4 | 4 | 4 |

Where each feature comes from and what point in time it reads. Every source
is a trusted record; prose never enters. Point values are heuristics and every
one of them is a design choice, not a measurement: `docs/EVALUATION.md` §G
reports how often each factor fires on fraud-labelled and on legitimate
transactions, which is the honest measure of how much each one is worth.

| Factor | Source (trusted record) | Time semantics | Reads |
|---|---|---|---|
| `amount_anomaly_extreme` | account baseline (earlier transactions) | as of the transaction | z-score, unbounded |
| `amount_anomaly_high` | account baseline | as of the transaction | z-score |
| `amount_anomaly_moderate` | account baseline | as of the transaction | z-score |
| `amount_ratio_small_baseline` | account baseline (< 5 transactions) | as of the transaction | ratio to mean |
| `velocity_burst` | account's earlier transactions | previous 60 minutes | count |
| `velocity_spike` | account's earlier transactions + baseline daily count | previous 60 minutes | count vs baseline |
| `velocity_elevated` | account's earlier transactions + baseline daily count | previous 60 minutes | count vs baseline |
| `rapid_fire` | account's earlier transactions | previous 10 minutes | count |
| `rapid_succession` | previous transaction + baseline median gap | gap to the previous transaction | minutes vs hours |
| `recent_account_changes` | authentication service sessions | previous 24 hours | event set |
| `recent_failed_mfa` | authentication service sessions | previous 24 hours | boolean |
| `shared_payout_instrument` | entity graph (account -> bank-account instrument, by identity) | instruments added and edges dated at or before the transaction; not the account's current payout field | account count |
| `new_device` | entity graph (account -> device) | registered or used >= 24 h before the transaction | boolean + hours |
| `young_account_shared_device` | account record + entity graph | as of the transaction | days, account count |
| `shared_device` | entity graph (device -> accounts) | edges dated at or before the transaction | account count |
| `impossible_travel` | account's earlier transactions | previous 2 hours | country change |
| `new_country` | account baseline (usual countries) | as of the transaction | boolean |
| `merchant_risk_critical` | merchant entity profile | as of the transaction | 0-100 |
| `merchant_risk_high` | merchant entity profile + MCC tier | as of the transaction | 0-100 / tier |
| `merchant_risk_medium` | merchant entity profile + MCC tier | as of the transaction | 0-100 / tier |
| `account_age_new` | account record | as of the transaction | days |
| `account_age_young` | account record | as of the transaction | days |
| `new_instrument` | payment instrument record | as of the transaction | days |
| `auth_none` | payment-switch record | the transaction itself | enum |
| `auth_weak` | payment-switch record | the transaction itself | enum |
| `chargeback_high` | disputes filed before the transaction | as of the transaction | rate 0-1 |
| `chargeback_some` | disputes filed before the transaction | as of the transaction | rate 0-1 |
| `unusual_hour` | account baseline (usual hours, >= 10 transactions) | as of the transaction | hour |
| `new_merchant` | account baseline (merchants seen) | as of the transaction | boolean |
| `repeat_merchant_burst` | account's earlier transactions | previous 60 minutes | count |
| `linked_entity_critical` | worst linked device / account profile | as of the transaction, account status included (Account.status_at) | 0-100 |
| `linked_entity_high` | worst linked device / account profile | as of the transaction, account status included (Account.status_at) | 0-100 |
| `linked_entity_medium` | worst linked device / account profile | as of the transaction | 0-100 |

Thresholds:

| Threshold | `txn-1.0` | `txn-1.1` | `txn-2.0` |
|---|---:|---:|---:|
| `z_extreme` | 4.0 | 4.0 | 4.0 |
| `z_high` | 3.0 | 3.0 | 3.0 |
| `z_moderate` | 2.0 | 2.5 | 2.0 |
| `velocity_x` | 3.0 | 3.0 | 3.0 |
| `velocity_spike_x` | 5.0 | 5.0 | 5.0 |
| `rapid_window_minutes` | — | — | 10 |
| `rapid_fire_count` | — | — | 3 |
| `rapid_gap_minutes` | — | — | 15 |
| `baseline_gap_hours` | — | — | 6 |
| `security_event_hours` | — | — | 24 |

Components (the auditable breakdown shown on every assessment):

| Component | Factors |
|---|---|
| anomaly | `amount_anomaly_extreme`, `amount_anomaly_high`, `amount_anomaly_moderate`, `amount_ratio_small_baseline`, `unusual_hour`, `new_merchant`, `repeat_merchant_burst` |
| velocity | `velocity_spike`, `velocity_elevated`, `velocity_burst`, `rapid_fire`, `rapid_succession` |
| device_geo | `new_device`, `shared_device`, `young_account_shared_device`, `impossible_travel`, `new_country`, `new_instrument` |
| entity | `merchant_risk_critical`, `merchant_risk_high`, `merchant_risk_medium`, `linked_entity_critical`, `linked_entity_high`, `linked_entity_medium`, `shared_payout_instrument`, `chargeback_high`, `chargeback_some`, `account_age_new`, `account_age_young` |
| security | `auth_none`, `auth_weak`, `recent_account_changes`, `recent_failed_mfa` |

## Transaction monitoring model (`mon-1.0`, 10 indicators)

Account-level, over a 30-day window ending at `as_of` (`MonitoringContext.window_days`).
Single strong pattern -> HIGH; combinations -> CRITICAL. Sentinel demo values. **This is a synthetic transaction-monitoring / investigation
simulation**; it claims no regulatory compliance, no sanctions screening and
no filing capability.

| Indicator | Label | Condition | Points |
|---|---|---|---:|
| `structuring_like` | Structuring-like transfers below threshold | ≥ 3 transfers between 80% and 100% of the ₹50,000 reporting threshold within 7 days | 55 |
| `rapid_movement` | Rapid movement of funds | ≥ 80% of an inbound transfer moved out by transfer within 24 h | 40 |
| `velocity` | Unusual transaction velocity | daily count in the window ≥ 3× the account's baseline daily count | 20 |
| `velocity_burst_24h` | Burst of activity within 24 hours | densest 24 h in the window ≥ max(6, 4 × baseline daily count) | 30 |
| `geo_shift` | Sudden geography shifts | ≥ 3 countries within any 7-day span of the window | 15 |
| `high_risk_merchant_exposure` | High-risk merchant exposure | ≥ 40% of non-transfer spend in the window at high-risk-MCC merchants | 15 |
| `circular_transfers` | Circular transfers | a transfer cycle back to the account, path length ≤ 5, **every hop inside the last 30 days** | 45 |
| `dormant_activation` | Dormant account activation | ≥ 90 days of silence before the window, then ≥ 5 transactions in the first 3 days | 50 |
| `shared_device_ring` | Shares a device with other accounts | ≥ 3 accounts on a device this account uses (as of the window end) | 20 |
| `linked_entity_risk` | Linked entity risk | worst precomputed risk among linked accounts / devices ≥ 50 | 20 |

| Threshold | Value |
|---|---:|
| `reporting_threshold` | 50,000 |
| `structuring_band` | 0.8 |
| `dormant_days` | 90 |
| `cycle_window_days` | 30 |

## Account-security model (`acct-1.0`, 10 factors)

Over one trusted login session and the account's device / country history.

| Factor | Label | Condition | Points |
|---|---|---|---:|
| `new_device` | New device | login device not among the account's known devices | 17 |
| `new_country` | New country | login country not among the account's known countries | 15 |
| `impossible_travel` | Impossible travel | country differs from the previous login and that login was < 2 h ago | 25 |
| `credential_change` | Credential change | password / email changed in this session | 12 |
| `mfa_change` | MFA change | second factor changed in this session | 15 |
| `payout_change` | Payout destination change | payout / settlement destination changed in this session | 25 |
| `session_anomaly` | Session anomaly | the authentication service flagged the session | 8 |
| `velocity` | Login velocity | ≥ 5 logins in the previous hour | 10 |
| `mfa_not_passed` | MFA not passed | second factor not completed | 15 |
| `device_history_thin` | Thin device history | a new device on an account with ≤ 1 known device | 5 |

## Dispute model (`disp-1.0`, 7 factors)

Over the ledger facts, the contradiction verdict and the account's entity
profile; the claim text never enters.

| Factor | Label | Condition | Points |
|---|---|---|---:|
| `prior_disputes_many` | Multiple prior disputes | ≥ 2 disputes in the previous 90 days | 20 |
| `prior_disputes_some` | A prior dispute | exactly 1 dispute in the previous 90 days | 8 |
| `amount_over_auto_limit` | Amount over auto-approval limit | amount above the ledger's auto-approval limit | 15 |
| `claim_contradicted` | Claim contradicted by ledger | the trusted record disagrees with the claim (contradiction engine) | 25 |
| `account_risk_high` | High account risk | account entity risk ≥ 50 | 15 |
| `account_risk_medium` | Medium account risk | account entity risk 25–49 | 6 |
| `security_flagged` | AI-security finding on submission | the gateway flagged the submission (severity ≥ MEDIUM) | 10 |

## Entity profiles (`entity-1.1`)

Computed in a fixed order -- device → merchant → account → customer -- so
nothing is circular, each as of a given time and cached per `(entity, as_of)`.
Point values are in the code; this table is parsed from it.

| Factor | Label | Condition | Points |
|---|---|---|---:|
| `shared_device_many` | Device shared by many accounts | ≥ 5 accounts use the device (as of) | 35 |
| `shared_device` | Device shared across accounts | 3–4 accounts use the device (as of) | 20 |
| `linked_frozen_account` | Linked account is frozen | an account on the device is frozen | 15 |
| `device_new` | Device first seen < 7 days ago | device first seen < 7 days before as-of | 5 |
| `merchant_unknown` | Merchant not in records | merchant not in records | 20 |
| `dispute_ratio_high` | High dispute ratio | ≥ 5% of the merchant's transactions before as-of were disputed before as-of (≥ 5 transactions) | 40 |
| `dispute_ratio_elevated` | Elevated dispute ratio | 2–5% disputed (≥ 5 transactions) | 25 |
| `mcc_high` | High-risk merchant category | high-risk merchant category | 15 |
| `mcc_medium` | Medium-risk merchant category | medium-risk merchant category | 5 |
| `registration_shell` | Shell registration | registration status `shell` | 40 |
| `registration_unverified` | Registration unverified | registration status not `verified` | 15 |
| `prior_flags` | Prior fraud flags | prior fraud flags (10 per flag, capped at 30) | 10 per flag, max 30 |
| `merchant_young` | Merchant registered < 90 days ago | registered < 90 days before as-of | 10 |
| `owner_linked_flagged` | Owner linked to a flagged merchant | the owner controls another merchant with prior flags | 15 |
| `account_unknown` | Account not in records | account not in records | 20 |
| `prior_disputes_many` | Multiple disputes in 90 days | ≥ 2 disputes in the 90 days before as-of | 15 |
| `prior_disputes_some` | A recent dispute | 1 dispute in the 90 days before as-of | 5 |
| `recent_security_events` | Recent security-sensitive changes | a payout, MFA or credential change among the recent trusted session events | 15 |
| `account_young` | Account opened < 30 days ago | opened < 30 days before as-of | 10 |
| `account_frozen` | Account is frozen | account status frozen | 30 |
| `linked_device_high` | Uses a high-risk device | a device the account uses (as of) scores ≥ 50 | 20 |
| `linked_device_medium` | Uses a medium-risk device | a device the account uses (as of) scores 25–49 | 10 |
| `high_risk_merchant_exposure` | Heavy spend at high-risk merchants | ≥ 30% of the account's spend before as-of at high-risk-MCC merchants | 10 |
| `worst_account` | Worst account risk | the customer's worst account profile (its score, as points) | score of the worst account |

## How the score is used

Transaction: the assessment's score and level enter the policy context
(`risk_score`, `risk_level`, `risk_factors`) and the merchant / account
profiles feed `merchant_risk_score`, `account_risk_score`. Investigation: the
monitoring indicators enter as `monitoring_patterns`. Policy decides the
outcome; the registry decides who may execute it; the risk engine only ever
recommends. Every factor carries its label, points, detail and evidence ids,
so a block is explainable to the factor.
