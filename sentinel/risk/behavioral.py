"""Behavioural baselines: what is *normal* for this account / merchant, computed
from deterministic synthetic history. Deviations from the baseline are the
features the transaction model scores.

This is descriptive statistics, not production ML, and is labelled as such."""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime

from sentinel.domain.entities import Dispute, Transaction


def parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts)


@dataclass(frozen=True)
class BehavioralBaseline:
    entity_id: str
    n: int
    mean_amount: float
    stddev_amount: float
    median_amount: float
    daily_count: float
    common_countries: frozenset[str]
    common_devices: frozenset[str]
    common_merchants: frozenset[str]
    common_instruments: frozenset[str]
    usual_hours: frozenset[int]
    chargeback_rate: float
    first_seen: str | None = None
    last_seen: str | None = None
    countries: dict[str, int] = field(default_factory=dict)

    @classmethod
    def empty(cls, entity_id: str) -> BehavioralBaseline:
        return cls(
            entity_id,
            0,
            0.0,
            0.0,
            0.0,
            0.0,
            frozenset(),
            frozenset(),
            frozenset(),
            frozenset(),
            frozenset(),
            0.0,
        )

    @classmethod
    def from_history(
        cls,
        entity_id: str,
        transactions: Iterable[Transaction],
        disputes: Iterable[Dispute] = (),
        *,
        share_threshold: float = 0.1,
    ) -> BehavioralBaseline:
        txns = sorted(transactions, key=lambda t: t.timestamp)
        if not txns:
            return cls.empty(entity_id)
        amounts = [t.amount for t in txns]
        n = len(amounts)
        mean = sum(amounts) / n
        var = sum((a - mean) ** 2 for a in amounts) / n
        std = math.sqrt(var)
        srt = sorted(amounts)
        median = float(srt[n // 2] if n % 2 else (srt[n // 2 - 1] + srt[n // 2]) / 2)
        first, last = parse_ts(txns[0].timestamp), parse_ts(txns[-1].timestamp)
        days = max(1.0, (last - first).total_seconds() / 86400 + 1)
        daily = n / days

        def common(values: Iterable[str]) -> frozenset[str]:
            c = Counter(values)
            return frozenset(k for k, v in c.items() if v / n >= share_threshold)

        hours = Counter(parse_ts(t.timestamp).hour for t in txns)
        usual = frozenset(h for h, c in hours.items() if c / n >= 0.05)
        disp = sum(1 for d in disputes)
        return cls(
            entity_id=entity_id,
            n=n,
            mean_amount=round(mean, 2),
            stddev_amount=round(std, 2),
            median_amount=median,
            daily_count=round(daily, 4),
            common_countries=common(t.country for t in txns),
            common_devices=common(t.device_id for t in txns),
            common_merchants=common(t.merchant_id for t in txns),
            common_instruments=common(t.instrument_id for t in txns),
            usual_hours=usual,
            chargeback_rate=round(disp / n, 4),
            first_seen=txns[0].timestamp,
            last_seen=txns[-1].timestamp,
            countries=dict(Counter(t.country for t in txns)),
        )

    # ---- deviations ---------------------------------------------------------------
    def amount_z(self, amount: int) -> float:
        if self.n < 2 or self.stddev_amount == 0:
            return 0.0
        return round((amount - self.mean_amount) / self.stddev_amount, 3)

    def amount_ratio(self, amount: int) -> float:
        if self.mean_amount <= 0:
            return 0.0
        return round(amount / self.mean_amount, 3)

    def is_usual_hour(self, hour: int) -> bool:
        return not self.usual_hours or hour in self.usual_hours

    def knows_device(self, device_id: str) -> bool:
        return device_id in self.common_devices

    def knows_country(self, country: str) -> bool:
        return not self.common_countries or country in self.common_countries

    def knows_merchant(self, merchant_id: str) -> bool:
        return merchant_id in self.common_merchants

    def knows_instrument(self, instrument_id: str) -> bool:
        return instrument_id in self.common_instruments

    def to_dict(self) -> dict[str, object]:
        return {
            "entity_id": self.entity_id,
            "n": self.n,
            "average_transaction_amount": self.mean_amount,
            "transaction_stddev": self.stddev_amount,
            "median_amount": self.median_amount,
            "daily_transaction_count": self.daily_count,
            "common_countries": sorted(self.common_countries),
            "common_devices": sorted(self.common_devices),
            "common_merchants": sorted(self.common_merchants),
            "usual_transaction_hours": sorted(self.usual_hours),
            "chargeback_rate": self.chargeback_rate,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }
