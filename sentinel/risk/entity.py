"""Entity-level risk profiles, computed in a fixed order so nothing is circular:

    device  <- how many accounts share it, any of them frozen
    merchant <- its own dispute ratio, registration, flags, age, owner links
    account <- its own disputes / security events / age + the risk of its devices
    customer <- the worst of its accounts

A transaction's ``linked_entity_risk`` reads the *precomputed* device / account
profiles, which never depend on the transaction being scored."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from sentinel.domain.entities import Account, Customer, Device, Dispute, Merchant, Transaction
from sentinel.domain.enums import RiskLevel
from sentinel.domain.risk import EntityRiskProfile, RiskFactor
from sentinel.risk.graph import EntityGraph, Node

ENTITY_MODEL_VERSION = "entity-1.0"


def _days_between(a: str, b: str) -> int:
    return max(0, (datetime.fromisoformat(b) - datetime.fromisoformat(a)).days)


def _profile(
    entity_type: str, entity_id: str, factors: list[RiskFactor], linked: tuple[str, ...] = ()
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
    )


@dataclass
class EntityRiskEngine:
    """Computes and caches profiles over one dataset snapshot."""

    graph: EntityGraph
    customers: dict[str, Customer]
    accounts: dict[str, Account]
    merchants: dict[str, Merchant]
    devices: dict[str, Device]
    transactions: dict[str, Transaction]
    disputes: dict[str, Dispute]
    as_of: str
    _cache: dict[tuple[str, str], EntityRiskProfile] = field(default_factory=dict)
    _by_merchant: dict[str, list[Transaction]] = field(default_factory=dict)
    _by_account: dict[str, list[Transaction]] = field(default_factory=dict)
    _disp_by_account: dict[str, list[Dispute]] = field(default_factory=dict)
    _disp_by_merchant: dict[str, list[Dispute]] = field(default_factory=dict)
    _indexed: bool = False

    def _index(self) -> None:
        if self._indexed:
            return
        for t in self.transactions.values():
            self._by_merchant.setdefault(t.merchant_id, []).append(t)
            self._by_account.setdefault(t.account_id, []).append(t)
        for d in self.disputes.values():
            self._disp_by_account.setdefault(d.account_id, []).append(d)
            txn = self.transactions.get(d.transaction_id)
            if txn is not None:
                self._disp_by_merchant.setdefault(txn.merchant_id, []).append(d)
        self._indexed = True

    # ---- device ---------------------------------------------------------------------
    def device_risk(self, device_id: str) -> EntityRiskProfile:
        key = ("device", device_id)
        if key in self._cache:
            return self._cache[key]
        factors: list[RiskFactor] = []
        accts = self.graph.accounts_sharing_device(device_id)
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
        frozen = [a for a in accts if self.accounts.get(a) and self.accounts[a].status == "frozen"]
        if frozen:
            factors.append(
                RiskFactor(
                    "linked_frozen_account", "Linked account is frozen", 15, ", ".join(frozen[:3])
                )
            )
        dev = self.devices.get(device_id)
        if dev and _days_between(dev.first_seen, self.as_of) < 7:
            factors.append(
                RiskFactor("device_new", "Device first seen < 7 days ago", 5, dev.first_seen)
            )
        p = _profile("device", device_id, factors, tuple(accts))
        self._cache[key] = p
        return p

    # ---- merchant -------------------------------------------------------------------
    def merchant_risk(self, merchant_id: str) -> EntityRiskProfile:
        key = ("merchant", merchant_id)
        if key in self._cache:
            return self._cache[key]
        m = self.merchants.get(merchant_id)
        factors: list[RiskFactor] = []
        if m is None:
            factors.append(RiskFactor("merchant_unknown", "Merchant not in records", 20))
            return _profile("merchant", merchant_id, factors)
        self._index()
        txn_ids = self._by_merchant.get(merchant_id, [])
        disp = self._disp_by_merchant.get(merchant_id, [])
        ratio = len(disp) / len(txn_ids) if txn_ids else 0.0
        if ratio >= 0.05 and len(txn_ids) >= 5:
            factors.append(
                RiskFactor(
                    "dispute_ratio_high",
                    "High dispute ratio",
                    40,
                    f"{ratio:.1%} of {len(txn_ids)} transactions disputed",
                )
            )
        elif ratio >= 0.02 and len(txn_ids) >= 5:
            factors.append(
                RiskFactor(
                    "dispute_ratio_elevated",
                    "Elevated dispute ratio",
                    25,
                    f"{ratio:.1%} of {len(txn_ids)} transactions disputed",
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
        age = _days_between(m.registered_at, self.as_of)
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
        p = _profile("merchant", merchant_id, factors, tuple(siblings))
        self._cache[key] = p
        return p

    # ---- account --------------------------------------------------------------------
    def account_risk(
        self, account_id: str, recent_security_events: tuple[str, ...] = ()
    ) -> EntityRiskProfile:
        key = ("account", account_id)
        if key in self._cache:
            return self._cache[key]
        a = self.accounts.get(account_id)
        factors: list[RiskFactor] = []
        if a is None:
            factors.append(RiskFactor("account_unknown", "Account not in records", 20))
            return _profile("account", account_id, factors)
        self._index()
        disp = [
            d
            for d in self._disp_by_account.get(account_id, [])
            if _days_between(d.submitted_at, self.as_of) <= 90
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
        if _days_between(a.opened_at, self.as_of) < 30:
            factors.append(RiskFactor("account_young", "Account opened < 30 days ago", 10))
        if a.status == "frozen":
            factors.append(RiskFactor("account_frozen", "Account is frozen", 30))
        dev_scores = [self.device_risk(d).score for d in self.graph.devices_for_account(account_id)]
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
        txns = self._by_account.get(account_id, [])
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
        linked = tuple(sorted(self.graph.linked_accounts(account_id)))
        p = _profile("account", account_id, factors, linked)
        self._cache[key] = p
        return p

    # ---- customer -------------------------------------------------------------------
    def customer_risk(self, customer_id: str) -> EntityRiskProfile:
        key = ("customer", customer_id)
        if key in self._cache:
            return self._cache[key]
        accts = self.graph.accounts_for_customer(customer_id)
        profiles = [self.account_risk(a) for a in accts]
        factors: list[RiskFactor] = []
        if profiles:
            worst = max(profiles, key=lambda p: p.score)
            if worst.score > 0:
                factors.append(
                    RiskFactor("worst_account", "Worst account risk", worst.score, worst.entity_id)
                )
        p = _profile("customer", customer_id, factors, tuple(accts))
        self._cache[key] = p
        return p

    def profile(self, entity_type: str, entity_id: str) -> EntityRiskProfile:
        fn = {
            "device": self.device_risk,
            "merchant": self.merchant_risk,
            "account": self.account_risk,
            "customer": self.customer_risk,
        }[entity_type]
        return fn(entity_id)

    def linked_entity_risk(self, account_id: str, device_id: str) -> tuple[int, tuple[str, ...]]:
        """Worst precomputed risk among the device and the accounts it links to."""
        dev = self.device_risk(device_id)
        worst, who = dev.score, (f"device:{device_id}",) if dev.score else ()
        for other in self.graph.accounts_sharing_device(device_id):
            if other == account_id:
                continue
            p = self.account_risk(other)
            if p.score > worst:
                worst, who = p.score, (f"account:{other}",)
        return worst, who

    def node(self, kind: str, id: str) -> Node:
        return Node(kind, id)
