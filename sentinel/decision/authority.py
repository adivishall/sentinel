"""Evaluation authority: which evaluations may become decision records.

AUTHORITATIVE
    Persisted: audited, able to open a case and to count as executed. It runs with
    every control, the configured *active* version of its policy
    (``PolicyRegistry.active``) and the active risk model for its surface
    (``scoring.ACTIVE``). No request parameter changes any of the three.

WHAT-IF
    The attack simulator (both sides: its facts are fixtures signed on request), a
    scenario run under another version, replay, backtests and the evaluation suites. The same engine computes the
    result and returns it; it is never recorded as a decision.

Version classes, for every policy and risk model:

    active           the one authoritative evaluation uses (the highest shipped version)
    historical       every other registered version; kept so recorded decisions replay
    replay/what-if   any registered version, named explicitly; never persisted
    caller-selected  none on the authoritative path

The check reads the inputs a decision was actually composed from, not the options
a caller asked for, so a new surface or a direct Python caller cannot persist a
downgraded decision. ``_finish`` in ``workflows.py`` calls it before anything is
written."""

from __future__ import annotations

from sentinel.decision.composer import FULL, DecisionInputs
from sentinel.policy.loader import PolicyRegistry
from sentinel.risk import scoring


class ControlDowngrade(PermissionError):
    """An evaluation that would be recorded as authoritative ran with fewer controls, a
    non-active policy version or a non-active risk model."""


def downgrades(inputs: DecisionInputs, policies: PolicyRegistry) -> tuple[str, ...]:
    """Every way ``inputs`` differ from an authoritative evaluation (empty = authoritative)."""
    out: list[str] = []
    missing = FULL - frozenset(inputs.controls)
    if missing:
        out.append(f"controls missing: {', '.join(sorted(missing))}")
    try:
        active = policies.active(inputs.policy.policy_id)
    except KeyError:
        out.append(f"policy {inputs.policy.policy_id!r} is not registered")
    else:
        if inputs.policy.version != active.version:
            out.append(
                f"policy {inputs.policy.key} is not the active version "
                f"({active.key}); historical versions are replay-only"
            )
        elif inputs.policy.content_hash != active.content_hash:
            out.append(f"policy {inputs.policy.key} content differs from the registered policy")
    risk = inputs.risk
    if risk is not None and risk.entity_type in scoring.ACTIVE:
        want = scoring.ACTIVE[risk.entity_type].version
        if risk.model_version != want:
            out.append(
                f"risk model {risk.model_version} is not the active {risk.entity_type} "
                f"model ({want}); historical models are replay-only"
            )
    return tuple(out)


def require_authoritative(inputs: DecisionInputs, policies: PolicyRegistry) -> None:
    found = downgrades(inputs, policies)
    if found:
        raise ControlDowngrade(
            "refusing to record a downgraded evaluation as authoritative: " + "; ".join(found)
        )
