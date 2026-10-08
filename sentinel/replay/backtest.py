"""Policy backtest: a candidate policy replayed over the recorded history.

    sentinel replay backtest --policy-version 1 --workflow dispute
      120 decisions considered, 118 replayed, 2 not replayable
      LOOSENING (would newly execute): 3   tightening: 1   other changes: 13

One replay (``SentinelApp.replay``) answers "what would this decision have been under
another policy version, risk model or threshold?". A backtest asks the question a risk
team has before activating a change: across the recorded history, which decisions change,
in which direction, and -- above all -- which ones would NEWLY EXECUTE a consequential
capability (a refund, an onboarding, a payment, an account action) that the recorded
decision did not. That direction is ``loosening``; its reverse is ``tightening``.

Every decision goes through the same code path as a single replay (``SentinelApp._replay``:
the recorded side anchored to the audit event, the snapshot checked against the hash the
event recorded, every drift named), so a backtest row equals ``app.replay`` for that
decision. A decision whose stored record disagrees with its audit event is NOT replayed:
its recorded side cannot be trusted, so it is counted as unreplayable with the reason. So is
a decision the candidate cannot apply to (its policy has no such version, no such rule).
Nothing is skipped silently.

A backtest is a what-if. It never records an authoritative decision, never executes a
capability and never changes a recorded decision, snapshot, replay record or audit event.
It appends exactly one audit event (kind ``backtest``, action ``BACKTEST``) carrying its
overrides and its counts and ids -- no prose. ``docs/INVARIANTS.md`` INV-BACKTEST-1."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from sentinel.domain.enums import FinalAction, Workflow
from sentinel.domain.ids import new_id, now_iso
from sentinel.replay.engine import ReplayOverrides, ReplayResult

if TYPE_CHECKING:
    from sentinel.app import SentinelApp

MAX_LIMIT = 10_000

# Direction of a change. ``loosening`` and ``tightening`` are about execution only: the
# candidate would execute a consequential capability the recorded decision did not, or the
# reverse. The others compare ``FinalAction.permissiveness``.
LOOSENING = "loosening"
TIGHTENING = "tightening"
MORE_PERMISSIVE = "more_permissive"
LESS_PERMISSIVE = "less_permissive"
LATERAL = "lateral"


@dataclass(frozen=True)
class Unreplayable:
    decision_id: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {"decision_id": self.decision_id, "reason": self.reason}


@dataclass(frozen=True)
class Outcome:
    """One replayed decision: what was recorded beside what the candidate produces."""

    decision_id: str
    workflow: str
    subject_id: str
    recorded: str  # final action as recorded (from the audit event)
    candidate: str  # final action under the candidate
    executed_recorded: str | None
    executed_candidate: str | None  # the capability that WOULD execute under the candidate
    changed: bool  # final action, policy outcome, authorization or executed capability
    direction: str | None  # None when unchanged
    diffs: tuple[dict[str, Any], ...]
    drift: tuple[str, ...]  # named drift between the record and the replay (engine, ...)
    rules_recorded: tuple[str, ...]
    rules_candidate: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "workflow": self.workflow,
            "subject_id": self.subject_id,
            "recorded": self.recorded,
            "candidate": self.candidate,
            "executed_recorded": self.executed_recorded,
            "executed_candidate": self.executed_candidate,
            "changed": self.changed,
            "direction": self.direction,
            "diffs": list(self.diffs),
            "drift": list(self.drift),
            "rules_recorded": list(self.rules_recorded),
            "rules_candidate": list(self.rules_candidate),
        }


def _direction(
    o_recorded: str, o_candidate: str, x_recorded: str | None, x_candidate: str | None
) -> str:
    if x_recorded is None and x_candidate is not None:
        return LOOSENING
    if x_recorded is not None and x_candidate is None:
        return TIGHTENING
    try:
        before, after = FinalAction(o_recorded), FinalAction(o_candidate)
    except ValueError:
        return LATERAL
    if after.permissiveness > before.permissiveness:
        return MORE_PERMISSIVE
    if after.permissiveness < before.permissiveness:
        return LESS_PERMISSIVE
    return LATERAL


def outcome_of(r: ReplayResult) -> Outcome:
    """The backtest row for one replay result (the same fields ``app.replay`` returns)."""
    rec, cand = r.original, r.replayed
    x_rec, x_cand = rec.get("executed_capability"), cand.get("executed_capability")
    return Outcome(
        decision_id=r.decision_id,
        workflow=r.replayed_decision.workflow.value,
        subject_id=r.replayed_decision.subject_id,
        recorded=str(rec.get("final_action")),
        candidate=str(cand.get("final_action")),
        executed_recorded=x_rec,
        executed_candidate=x_cand,
        changed=r.changed,
        direction=(
            _direction(str(rec.get("final_action")), str(cand.get("final_action")), x_rec, x_cand)
            if r.changed
            else None
        ),
        diffs=tuple(r.decision_diff),
        drift=tuple(r.drift),
        rules_recorded=tuple(rec.get("matched_rules") or ()),
        rules_candidate=tuple(cand.get("matched_rules") or ()),
    )


@dataclass(frozen=True)
class BacktestReport:
    backtest_id: str
    created_at: str
    overrides: tuple[str, ...]
    workflow: str | None
    limit: int
    considered: int
    outcomes: tuple[Outcome, ...]  # every replayed decision, by decision id
    unreplayable: tuple[Unreplayable, ...]  # by decision id, each with its reason
    engine_version: str = ""
    drift: dict[str, int] = field(default_factory=dict)  # named drift -> decisions

    @property
    def replayed(self) -> int:
        return len(self.outcomes)

    @property
    def changes(self) -> tuple[Outcome, ...]:
        return tuple(o for o in self.outcomes if o.changed)

    @property
    def changed(self) -> int:
        return len(self.changes)

    @property
    def loosening(self) -> tuple[Outcome, ...]:
        """Decisions that executed nothing as recorded but would execute under the
        candidate: the direction that pays money or onboards a merchant."""
        return tuple(o for o in self.outcomes if o.direction == LOOSENING)

    @property
    def tightening(self) -> tuple[Outcome, ...]:
        return tuple(o for o in self.outcomes if o.direction == TIGHTENING)

    @property
    def transitions(self) -> dict[str, int]:
        """recorded final action -> candidate final action, with counts (changed only)."""
        c = Counter(f"{o.recorded} -> {o.candidate}" for o in self.changes)
        return dict(sorted(c.items()))

    @property
    def directions(self) -> dict[str, int]:
        c = Counter(o.direction for o in self.changes if o.direction)
        return {k: c[k] for k in (LOOSENING, TIGHTENING, MORE_PERMISSIVE, LESS_PERMISSIVE, LATERAL)}

    @property
    def rules_added(self) -> dict[str, int]:
        """Rules the candidate matches that the recorded decision did not, with counts."""
        c: Counter[str] = Counter()
        for o in self.outcomes:
            c.update(set(o.rules_candidate) - set(o.rules_recorded))
        return dict(sorted(c.items()))

    @property
    def rules_removed(self) -> dict[str, int]:
        c: Counter[str] = Counter()
        for o in self.outcomes:
            c.update(set(o.rules_recorded) - set(o.rules_candidate))
        return dict(sorted(c.items()))

    @property
    def unreplayable_reasons(self) -> dict[str, int]:
        return dict(sorted(Counter(u.reason for u in self.unreplayable).items()))

    def summary(self) -> dict[str, Any]:
        """Counts and ids only -- what the BACKTEST audit event carries."""
        return {
            "backtest_id": self.backtest_id,
            "overrides": list(self.overrides),
            "workflow": self.workflow,
            "limit": self.limit,
            "engine_version": self.engine_version,
            "considered": self.considered,
            "replayed": self.replayed,
            "unreplayable": len(self.unreplayable),
            "unreplayable_reasons": self.unreplayable_reasons,
            "changed": self.changed,
            "directions": self.directions,
            "transitions": self.transitions,
            "loosening_ids": [o.decision_id for o in self.loosening],
            "tightening_ids": [o.decision_id for o in self.tightening],
            "rules_added": self.rules_added,
            "rules_removed": self.rules_removed,
            "drift": dict(sorted(self.drift.items())),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.summary(),
            "created_at": self.created_at,
            "loosening": [o.to_dict() for o in self.loosening],
            "tightening": [o.to_dict() for o in self.tightening],
            "changes": [o.to_dict() for o in self.changes],
            "outcomes": [o.to_dict() for o in self.outcomes],
            "not_replayable": [u.to_dict() for u in self.unreplayable],
        }


def _reason(e: BaseException) -> str:
    a = e.args[0] if e.args else None
    return str(a) if isinstance(a, str) and a else f"{type(e).__name__}: {e}"


def validate(overrides: ReplayOverrides, workflow: str | None, limit: int) -> None:
    if workflow is not None and workflow not in {w.value for w in Workflow}:
        raise ValueError(f"unknown workflow {workflow!r}; one of {[w.value for w in Workflow]}")
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_LIMIT:
        raise ValueError(f"limit must be an integer between 1 and {MAX_LIMIT}")
    if not overrides.describe():
        raise ValueError(
            "a backtest needs a candidate: a policy version, a risk model or a rule threshold"
        )
    if overrides.ai_recommendation is not None or overrides.controls is not None:
        # a recommendation override demonstrates that the model is irrelevant to one
        # decision; a backtest is about policy, and "unguarded" is not a candidate policy
        raise ValueError("a backtest takes a policy version, a risk model or rule thresholds")


def backtest(
    app: SentinelApp,
    overrides: ReplayOverrides,
    *,
    workflow: str | None = None,
    limit: int = 500,
) -> BacktestReport:
    """Replay every stored decision (newest first, at most ``limit``; one workflow when
    ``workflow`` is given) under ``overrides`` and report what would change. Pure: it
    reads the store and writes nothing; ``SentinelApp.backtest`` records the one audit
    event."""
    from sentinel import __version__

    validate(overrides, workflow, limit)
    if overrides.policy_version is not None:
        reg = app.runtime.policies
        if not any(overrides.policy_version in reg.versions(p.policy_id) for p in reg.all()):
            raise ValueError(f"no policy has a version {overrides.policy_version}")
    anchored = app.audit_anchoring()  # once: the loop appends nothing, so it cannot change
    outcomes: list[Outcome] = []
    unreplayable: list[Unreplayable] = []
    drift: Counter[str] = Counter()
    rows = app.store.decisions(workflow=workflow, limit=limit)
    for row in rows:
        did = str(row.get("decision_id") or "")
        if not did:
            unreplayable.append(Unreplayable("?", "the stored decision has no id"))
            continue
        try:
            r = app._replay(did, overrides, anchored=anchored)
        except (KeyError, ValueError) as e:
            unreplayable.append(Unreplayable(did, _reason(e)))
            continue
        if not r.record_verified:
            unreplayable.append(
                Unreplayable(
                    did,
                    "the record does not match its audit event: " + "; ".join(r.record_issues),
                )
            )
            continue
        o = outcome_of(r)
        outcomes.append(o)
        drift.update(o.drift)
    return BacktestReport(
        backtest_id=new_id("BACKTEST"),
        created_at=now_iso(),
        overrides=tuple(overrides.describe()),
        workflow=workflow,
        limit=limit,
        considered=len(rows),
        outcomes=tuple(sorted(outcomes, key=lambda o: o.decision_id)),
        unreplayable=tuple(sorted(unreplayable, key=lambda u: u.decision_id)),
        engine_version=__version__,
        drift=dict(drift),
    )
