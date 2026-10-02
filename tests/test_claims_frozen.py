"""The frozen claim-classifier fixture stays frozen, and its first run stays recorded.

The release audit found the set frozen only by convention: nothing pinned the fixture,
and the docs labelled whatever the current run produced as the "first run"."""

from __future__ import annotations

import hashlib
from pathlib import Path

from sentinel.evaluation import claims

FIXTURE = Path(claims.__file__).parent / "attacks" / "claims_frozen.json"


def test_the_fixture_is_byte_for_byte_the_one_committed_before_its_first_run():
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == claims.FROZEN_SHA256


def test_the_first_run_is_recorded_and_reported_beside_the_current_run():
    r = claims.frozen()
    first = r["first_run"]
    assert first["n"] == r["n"] == 40
    assert first["false_negative_n"] + first["false_positive_n"] == first["n"]
    assert r["fixture_sha256"] == claims.FROZEN_SHA256
    # the classifier has not changed since the first run; if it does, the current numbers
    # may move, but the recorded first run must not be rewritten to match them
    assert (r["correct"], r["false_negatives"], r["false_positives"]) == (
        first["correct"],
        first["false_negatives"],
        first["false_positives"],
    )
