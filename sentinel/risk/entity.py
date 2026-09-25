"""Entity-level risk profiles, computed in a fixed order so nothing is circular:

    device  <- how many accounts share it, any of them frozen
    merchant <- its own dispute ratio, registration, flags, age, owner links
    account <- its own disputes / security events / age + the risk of its devices
    customer <- the worst of its accounts

**Point-in-time.** Every profile is computed *as of* a timestamp: only
transactions, disputes, device links and instrument links that existed at that
moment are read, and ages are measured to that moment. A transaction scored at
T1 therefore sees the merchant and device the way they looked at T1, and a
dispute filed a week later cannot change how T1 was scored. The default
``as_of`` is the dataset's "now". An account's ``status`` is read as of the time
(``Account.status_at``: a freeze counts from ``status_since``). A merchant's
``prior_flags`` are the flags the acquirer reported at registration, a static
attribute; a flag raised later would need its own dated record, which the data
model does not have (``docs/LIMITATIONS.md``).

A transaction's ``linked_entity_risk`` reads the *precomputed* device / account
profiles at the same as-of, which never depend on the transaction being scored.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from sentinel.domain.entities import Account, Customer, Device, Dispute, Merchant, Transaction
from sentinel.domain.enums import RiskLevel
from sentinel.domain.risk import EntityRiskProfile, RiskFactor
from sentinel.risk.graph import EntityGraph

ENTITY_MODEL_VERSION = "entity-1.1"


def _days_between(a: str, b: str) -> int:
    return max(0, (datetime.fromisoformat(b) - datetime.fromisoformat(a)).days)


def _profile(
    entity_type: str,
    entity_id: str,
    factors: list[RiskFactor],
    linked: tuple[str, ...] = (),
    as_of: str = "",
) -> EntityRiskProfile:
    score = max(0, min(100, sum(f.points for f in factors)))
    return EntityRiskProfile(
        entity_type,
        entity_id,
        score,
        RiskLevel.from_score(score),
        tuple(factors),
        linked,
        ENTITY_MODEL_VERSION,
        as_of,
    )


@dataclass
class EntityRiskEngine:
    """Computes and caches profiles over one dataset snapshot, per as-of time."""

    graph: EntityGraph
    customers: dict[str, Customer]
    accounts: dict[str, Account]
    merchants: dict[str, Merchant]
    devices: dict[str, Device]
    transactions: dict[str, Transaction]
    disputes: dict[str, Dispute]
    as_of: str
    _cache: dict[tuple[str, str, str], EntityRiskProfile] = field(default_factory=dict)
    _by_merchant: dict[str, list[Transaction]] = field(default_factory=dict)
    _by_account: dict[str, list[Transaction]] = field(default_factory=dict)
    _disp_by_account: dict[str, list[Dispute]] = field(default_factory=dict)
    _disp_by_merchant: dict[str, list[Dispute]] = field(default_factory=dict)
    _indexed: bool = False

    def _index(self) -> None:
        if self._indexed:
            return
        for t in sorted(self.transactions.values(), key=lambda x: x.timestamp):
            self._by_merchant.setdefault(t.merchant_id, []).append(t)
            self._by_account.setdefault(t.account_id, []).append(t)
        for d in sorted(self.disputes.values(), key=lambda x: x.submitted_at):
            self._disp_by_account.setdefault(d.account_id, []).append(d)
            txn = self.transactions.get(d.transaction_id)
            if txn is not None:
                self._disp_by_merchant.setdefault(txn.merchant_id, []).append(d)
        self._indexed = True

    def _at(self, as_of: str | None) -> str:
        return as_of or self.as_of

    # ---- device ---------------------------------------------------------------------
    def device_risk(self, device_id: str, as_of: str | None = None) -> EntityRiskProfile:
        at = self._at(as_of)
        key = ("device", device_id, at)
        if key in self._cache:
            return self._cache[key]
        factors: list[RiskFactor] = []
        accts = self.graph.accounts_sharing_device(device_id, as_of=at)
        if len(accts) >= 5:
            factors.append(
                RiskFactor(
                    "shared_device_many",
                    "Device shared by many accounts",
                    35,
                    f"{len(accts)} accounts use this device",
                )
            )
        elif len(accts) >= 3:
            factors.append(
                RiskFactor(
                    "shared_device",
                    "Device shared across accounts",
                    20,
                    f"{len(accts)} accounts use this device",
                )
            )
        frozen = [
            a for a in accts if self.accounts.get(a) and self.accounts[a].status_at(at) == "frozen"
        ]
        if frozen:
            factors.append(
                RiskFactor(
                    "linked_frozen_account", "Linked account is frozen", 15, ", ".join(frozen[:3])
                )
            )
        dev = self.devices.get(device_id)
        if dev and dev.first_seen <= at and _days_between(dev.first_seen, at) < 7:
            factors.append(
                RiskFactor("device_new", "Device first seen < 7 days ago", 5, dev.first_seen)
            )
        p = _profile("device", device_id, factors, tuple(accts), at)
        self._cache[key] = p
        return p

    # ---- merchant -------------------------------------------------------------------
    def merchant_risk(self, merchant_id: str, as_of: str | None = None) -> EntityRiskProfile:
        at = self._at(as_of)
        key = ("merchant", merchant_id, at)
        if key in self._cache:
            return self._cache[key]
        m = self.merchants.get(merchant_id)
        factors: list[RiskFactor] = []
        if m is None:
            factors.append(RiskFactor("merchant_unknown", "Merchant not in records", 20))
            return _profile("merchant", merchant_id, factors, as_of=at)
        self._index()
        txns = [t for t in self._by_merchant.get(merchant_id, []) if t.timestamp <= at]
        disp = [d for d in self._disp_by_merchant.get(merchant_id, []) if d.submitted_at <= at]
        ratio = len(disp) / len(txns) if txns else 0.0
        if ratio >= 0.05 and len(txns) >= 5:
            factors.append(
                RiskFactor(
                    "dispute_ratio_high",
                    "High dispute ratio",
                    40,
                    f"{ratio:.1%} of {len(txns)} transactions disputed",
                )
            )
        elif ratio >= 0.02 and len(txns) >= 5:
            factors.append(
                RiskFactor(
                    "dispute_ratio_elevated",
                    "Elevated dispute ratio",
                    25,
                    f"{ratio:.1%} of {len(txns)} transactions disputed",
                )
            )
        if m.mcc_risk == "high":
            factors.append(RiskFactor("mcc_high", "High-risk merchant category", 15, m.mcc))
        elif m.mcc_risk == "medium":
            factors.append(RiskFactor("mcc_medium", "Medium-risk merchant category", 5, m.mcc))
        if m.registration_status == "shell":
            factors.append(RiskFactor("registration_shell", "Shell registration", 40))
        elif m.registration_status != "verified":
            factors.append(RiskFactor("registration_unverified", "Registration unverified", 15))
        if m.prior_flags:
            factors.append(
                RiskFactor(
                    "prior_flags",
                    "Prior fraud flags",
                    min(30, 10 * m.prior_flags),
                    f"{m.prior_flags} flags",
                )
            )
        age = _days_between(m.registered_at, at)
        if age < 90:
            factors.append(
                RiskFactor("merchant_young", "Merchant registered < 90 days ago", 10, f"{age} days")
            )
        siblings = [x for x in self.graph.merchants_for_owner(m.owner_id) if x != merchant_id]
        flagged = [
            s for s in siblings if self.merchants.get(s) and self.merchants[s].prior_flags > 0
        ]
        if flagged:
            factors.append(
                RiskFactor(
                    "owner_linked_flagged",
                    "Owner linked to a flagged merchant",
                    15,
                    ", ".join(flagged[:3]),
                )
            )
        p = _profile("merchant", merchant_id, factors, tuple(siblings), at)
        self._cache[key] = p
        return p

    # ---- account --------------------------------------------------------------------
    def account_risk(
        self,
        account_id: str,
        recent_security_events: tuple[str, ...] = (),
        as_of: str | None = None,
    ) -> EntityRiskProfile:
        at = self._at(as_of)
        key = ("account", account_id, at + "|" + ",".join(sorted(set(recent_security_events))))
        if key in self._cache:
            return self._cache[key]
        a = self.accounts.get(account_id)
        factors: list[RiskFactor] = []
        if a is None:
            factors.append(RiskFactor("account_unknown", "Account not in records", 20))
            return _profile("account", account_id, factors, as_of=at)
        self._index()
        disp = [
            d
            for d in self._disp_by_account.get(account_id, [])
            if d.submitted_at <= at and _days_between(d.submitted_at, at) <= 90
        ]
        if len(disp) >= 2:
            factors.append(
                RiskFactor(
                    "prior_disputes_many",
                    "Multiple disputes in 90 days",
                    15,
                    f"{len(disp)} disputes",
                )
            )
        elif len(disp) == 1:
            factors.append(RiskFactor("prior_disputes_some", "A recent dispute", 5))
        risky_events = [
            e
            for e in recent_security_events
            if e in ("payout_change", "mfa_change", "credential_change")
        ]
        if risky_events:
            factors.append(
                RiskFactor(
                    "recent_security_events",
                    "Recent security-sensitive changes",
                    15,
                    ", ".join(sorted(set(risky_events))),
                )
            )
        if _days_between(a.opened_at, at) < 30:
            factors.append(RiskFactor("account_young", "Account opened < 30 days ago", 10))
        if a.status_at(at) == "frozen":
            factors.append(RiskFactor("account_frozen", "Account is frozen", 30))
        dev_scores = [
            self.device_risk(d, at).score for d in self.graph.devices_for_account(account_id, at)
        ]
        worst = max(dev_scores, default=0)
        if worst >= 50:
            factors.append(
                RiskFactor(
                    "linked_device_high", "Uses a high-risk device", 20, f"device score {worst}"
                )
            )
        elif worst >= 25:
            factors.append(
                RiskFactor(
                    "linked_device_medium", "Uses a medium-risk device", 10, f"device score {worst}"
                )
            )
        txns = [t for t in self._by_account.get(account_id, []) if t.timestamp <= at]
        if txns:
            hi = sum(
                t.amount
                for t in txns
                if self.merchants.get(t.merchant_id)
                and self.merchants[t.merchant_id].mcc_risk == "high"
            )
            share = hi / max(1, sum(t.amount for t in txns))
            if share >= 0.3:
                factors.append(
                    RiskFactor(
                        "high_risk_merchant_exposure",
                        "Heavy spend at high-risk merchants",
                        10,
                        f"{share:.0%} of spend",
                    )
                )
        linked = tuple(sorted(self.graph.linked_accounts(account_id, at)))
        p = _profile("account", account_id, factors, linked, at)
        self._cache[key] = p
        return p

    # ---- customer -------------------------------------------------------------------
    def customer_risk(self, customer_id: str, as_of: str | None = None) -> EntityRiskProfile:
        at = self._at(as_of)
        key = ("customer", customer_id, at)
        if key in self._cache:
            return self._cache[key]
        accts = self.graph.accounts_for_customer(customer_id)
        profiles = [self.account_risk(a, as_of=at) for a in accts]
        factors: list[RiskFactor] = []
        if profiles:
            worst = max(profiles, key=lambda p: p.score)
            if worst.score > 0:
                factors.append(
                    RiskFactor("worst_account", "Worst account risk", worst.score, worst.entity_id)
                )
        p = _profile("customer", customer_id, factors, tuple(accts), at)
        self._cache[key] = p
        return p

    def profile(
        self, entity_type: str, entity_id: str, as_of: str | None = None
    ) -> EntityRiskProfile:
        if entity_type == "device":
            return self.device_risk(entity_id, as_of)
        if entity_type == "merchant":
            return self.merchant_risk(entity_id, as_of)
        if entity_type == "account":
            return self.account_risk(entity_id, as_of=as_of)
        if entity_type == "customer":
            return self.customer_risk(entity_id, as_of)
        raise KeyError(entity_type)

    def linked_entity_risk(
        self, account_id: str, device_id: str, as_of: str | None = None
    ) -> tuple[int, tuple[str, ...]]:
        """Worst precomputed risk among the device and the accounts it links to, as of a time."""
        at = self._at(as_of)
        dev = self.device_risk(device_id, at)
        worst, who = dev.score, (f"device:{device_id}",) if dev.score else ()
        for other in self.graph.accounts_sharing_device(device_id, at):
            if other == account_id:
                continue
            p = self.account_risk(other, as_of=at)
            if p.score > worst:
                worst, who = p.score, (f"account:{other}",)
        return worst, who
