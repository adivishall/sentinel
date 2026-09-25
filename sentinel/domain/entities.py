"""Financial entities. Immutable value objects built from *trusted* records.

Amounts are integer INR (whole rupees) throughout, matching the original
firewall's ledger convention. ``label`` fields carry synthetic ground truth for
evaluation only and are never read by any risk or decision code.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sentinel.domain.enums import RiskLevel


@dataclass(frozen=True)
class Customer:
    customer_id: str
    name: str
    home_country: str
    segment: str  # e.g. "retail", "premium", "small_business"
    created_at: str  # ISO date
    risk_level: RiskLevel = RiskLevel.LOW


@dataclass(frozen=True)
class Account:
    account_id: str
    customer_id: str
    opened_at: str
    status: str = "active"  # active | frozen | closed
    payout_instrument_id: str | None = None
    mfa_enabled: bool = True


@dataclass(frozen=True)
class Merchant:
    merchant_id: str
    name: str
    mcc: str
    mcc_risk: str  # low | medium | high
    country: str
    owner_id: str
    domain: str
    registered_at: str
    registration_status: str = "verified"  # verified | unverified | shell
    prior_flags: int = 0


@dataclass(frozen=True)
class Device:
    device_id: str
    fingerprint: str
    first_seen: str
    platform: str = "web"


@dataclass(frozen=True)
class PaymentInstrument:
    instrument_id: str
    account_id: str
    kind: str  # card | bank_account | wallet
    last4: str
    added_at: str
    country: str = "IN"
    # Identity of the underlying instrument (a bank account / card token) that several
    # accounts may share; the graph links accounts to THIS, so a payout destination
    # shared by a ring is one node with three edges. Defaults to the instrument id.
    external_ref: str | None = None

    @property
    def identity(self) -> str:
        return self.external_ref or self.instrument_id


@dataclass(frozen=True)
class Transaction:
    transaction_id: str
    account_id: str
    merchant_id: str
    instrument_id: str
    device_id: str
    amount: int
    currency: str
    timestamp: str  # ISO datetime, UTC
    country: str
    channel: str = "ecommerce"  # ecommerce | pos | transfer
    auth_strength: str = "otp"  # none | password | otp | biometric
    delivery_status: str = "delivered"
    counterparty_account_id: str | None = None  # for transfers
    label: str = "legit"  # synthetic ground truth (evaluation only)
    status: str = "settled"  # settled | pending | reversed


@dataclass(frozen=True)
class Dispute:
    dispute_id: str
    transaction_id: str
    account_id: str
    amount: int
    submitted_at: str
    claim_type_declared: str = "unspecified"
    label: str = "legit"
    refund_state: str = "none"  # none | pending | refunded
    merchant_response: str = "none"  # none | accepted | contested


@dataclass(frozen=True)
class KYBApplication:
    application_id: str
    merchant_id: str
    submitted_at: str
    registration_status: str
    domain_age_days: int
    business_age_days: int
    prior_flags: int
    mcc_risk: str
    label: str = "legit"


@dataclass(frozen=True)
class LoginSession:
    """An authenticated session on an account (an *account* event, not an LLM
    conversation -- see ``sentinel.security.session`` for that)."""

    session_id: str
    account_id: str
    device_id: str
    ip: str
    country: str
    started_at: str
    mfa_passed: bool = True
    events: tuple[str, ...] = field(default_factory=tuple)  # credential_change, payout_change...
