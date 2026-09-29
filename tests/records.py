"""Complete records for tests that sign statements as an issuer.

A signed statement must state every field its kind requires
(``sentinel.decision.workflows.STATEMENT_FIELDS``): an unstated field is not the issuer's
word, and Sentinel does not fill one in. These builders are the issuer's side -- the test
states the ordinary values explicitly and overrides what the scenario is about."""

from __future__ import annotations

from typing import Any


def ledger(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "amount": 18000,
        "merchant": "QuickCart",
        "delivery_status": "delivered",
        "prior_disputes_90d": 0,
        "duplicate_confirmed": False,
        "cancellation_confirmed": False,
        "cardholder_present": True,
        "refund_state": "none",
        "transaction_status": "settled",
        "merchant_response": "none",
        "auth_strength": "unknown",
        "customer_tenure_days": 365,
    }
    base.update(over)
    return base


def kyb_record(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "registration_status": "verified",
        "domain_age_days": 900,
        "business_age_days": 1600,
        "prior_flags": 0,
        "mcc_risk": "low",
    }
    base.update(over)
    return base
