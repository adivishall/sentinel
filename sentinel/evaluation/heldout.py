"""Held-out evaluation: the same metrics on independently authored wording."""

from __future__ import annotations

from typing import Any

from sentinel.evaluation import harness
from sentinel.evaluation.attacks import heldout
from sentinel.evaluation.common import pct, write_json
from sentinel.evaluation.methodology import methodology


def run() -> dict[str, Any]:
    rows = harness.run(heldout.build())
    s = harness.summarize(rows)
    s["set"] = "held_out"
    s["rows"] = rows
    return s


def main(out_dir: str = "results") -> dict[str, Any]:
    s = run()
    rows = s.pop("rows")
    write_json(out_dir, "heldout_rows.json", rows)
    s["methodology"] = methodology("heldout", s)
    write_json(out_dir, "heldout.json", s)
    print(
        f"[held-out] {s['n_attacks']} independent attacks, {s['n_deserved_controls']} deserved controls"
    )
    print(
        f"  ASR unguarded {pct(s['asr_unguarded'])}   ASR guarded {pct(s['asr_guarded'])}   detection recall {pct(s['detection_recall'])}   FP {pct(s['fp_rate'])}"
    )
    return s


if __name__ == "__main__":
    main()
