"""Where the facts come from: the three interfaces between Sentinel and a system of record.

The decision logic (``sentinel.decision``, ``sentinel.risk``, ``sentinel.evidence``) never
reads storage: it is handed a record, an issuer's signed statement and a point-in-time
context. ``SentinelApp`` reads them through these three interfaces, so a deployment can
answer them from a payment processor, a ledger, an acquirer or a KYC/KYB provider
without touching a single decision rule:

- ``RecordProvider`` -- the institution's records, read by id: the thing a decision is
  about (a transaction, a dispute, an application, a login session) and the entities
  around it (account, merchant, device, instrument).
- ``FactProvider`` -- issuers' signed statements about those records (``sentinel.fact/1``,
  verified by ``sentinel.trust``; the provider only stores and returns them).
- ``RiskContextProvider`` -- history around a record, *as of* a moment: earlier
  transactions, devices, instruments, transfers, disputes and sessions. Point-in-time
  reads only; a provider that returned the future would leak it (INV-TEMP-1).

``SyntheticSQLiteProvider`` -- the shipped ``SentinelStore`` over a generated, synthetic
dataset -- is the only implementation. Nothing here integrates a real bank system, and
nothing in the repository pretends to.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from sentinel.data.store import SentinelStore
    from sentinel.domain.entities import (
        Account,
        Device,
        Dispute,
        KYBApplication,
        LoginSession,
        Merchant,
        PaymentInstrument,
        Transaction,
    )
    from sentinel.domain.enums import FactKind


@runtime_checkable
class RecordProvider(Protocol):
    def transaction(self, tid: str) -> Transaction | None: ...
    def dispute(self, did: str) -> tuple[Dispute, dict[str, str]] | None: ...
    def kyb_application(self, app_id: str) -> tuple[KYBApplication, dict[str, str]] | None: ...
    def session(self, sid: str) -> LoginSession | None: ...
    def account(self, aid: str) -> Account | None: ...
    def merchant(self, mid: str) -> Merchant | None: ...
    def device(self, did: str) -> Device | None: ...
    def instrument(self, iid: str) -> PaymentInstrument | None: ...
    def held_id(self, kind: FactKind, rid: str) -> str | None:
        """The held record id equal to ``rid`` ignoring ASCII case, if any."""
        ...


@runtime_checkable
class FactProvider(Protocol):
    def fact_envelope(self, record_key: str) -> dict[str, Any] | None: ...
    def save_fact_envelopes(self, envelopes: list[tuple[str, dict[str, Any]]]) -> None: ...


@runtime_checkable
class RiskContextProvider(Protocol):
    def transactions_before(
        self, account_id: str, ts: str, limit: int = 500
    ) -> list[Transaction]: ...
    def account_devices(self, aid: str) -> list[str]: ...
    def instruments_for(self, account_id: str) -> list[PaymentInstrument]: ...
    def inbound_transfers(self, account_id: str) -> list[Transaction]: ...
    def disputes(self, *, account_id: str | None = None, limit: int = 100) -> list[Dispute]: ...
    def sessions(
        self, *, account_id: str | None = None, limit: int = 100
    ) -> list[LoginSession]: ...


def synthetic_sqlite_provider(
    store: SentinelStore,
) -> tuple[RecordProvider, FactProvider, RiskContextProvider]:
    """The shipped implementation: one SQLite store answers all three. (A typed identity,
    so the type checker proves the store satisfies each interface.)"""
    return store, store, store
