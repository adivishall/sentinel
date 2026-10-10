"""Authenticated reviewers for tests (what ``ReviewerRegistry.authenticate`` returns).

Case actions take a ``Reviewer`` the registry resolved, never a name and a role from the
request (tests/test_reviewer_identity.py covers the registry and the credential path)."""

from __future__ import annotations

from sentinel.cases.identity import Reviewer, ReviewerRegistry

LIMIT = 10**9


def reviewer(reviewer_id: str, role: str = "HUMAN_REVIEWER", limit: int = LIMIT) -> Reviewer:
    return Reviewer(reviewer_id, reviewer_id.title(), role, limit, f"cred-{reviewer_id}")


ANALYST = reviewer("analyst")
ALICE = reviewer("alice")
BOB = reviewer("bob")
CAROL = reviewer("carol")
SENIOR = reviewer("senior", "SENIOR_REVIEWER")
SAM = reviewer("sam", "SENIOR_REVIEWER")


def registry(*specs: tuple[str, str, int]) -> tuple[ReviewerRegistry, dict[str, str]]:
    """A registry with the given (id, role, limit) reviewers and their one-time tokens."""
    reg, tokens = ReviewerRegistry(), {}
    for rid, role, limit in specs:
        reg, tokens[rid] = reg.add(rid, rid.title(), role, limit)
    return reg, tokens
