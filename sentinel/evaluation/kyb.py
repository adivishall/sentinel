"""KYB / merchant-onboarding benchmark: the same pipeline on a second surface."""

from __future__ import annotations

from typing import Any

from sentinel.decision.workflows import FULL, NONE
from sentinel.evaluation.attacks import kyb_corpus
from sentinel.evaluation.common import breach, pct, run_kyb_case, runtime, write_json


def run(cases: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    cases = cases or kyb_corpus.build()
    rt = runtime()
    attacks = [c for c in cases if c["is_attack"]]
    legit = [c for c in cases if not c["is_attack"] and c["ground_truth_outcome"] == "approve"]
    border = [c for c in cases if not c["is_attack"] and c["ground_truth_outcome"] == "review"]
    ug = sum(breach(run_kyb_case(rt, c, NONE)) for c in attacks)
    g = sum(breach(run_kyb_case(rt, c, FULL)) for c in attacks)
    fp = sum(not run_kyb_case(rt, c, FULL).decision.executed for c in legit)
    held = sum(
        run_kyb_case(rt, c, FULL).decision.final_action.value == "REQUIRE_HUMAN_REVIEW"
        for c in border
    )
    return {
        "attacks": len(attacks),
        "controls": len(cases) - len(attacks),
        "asr_unguarded": round(ug / len(attacks), 3),
        "asr_guarded": round(g / len(attacks), 3),
        "fp_rate": round(fp / max(1, len(legit)), 3),
        "borderline_to_review": round(held / max(1, len(border)), 3),
    }


def main(out_dir: str = "results") -> dict[str, Any]:
    r = run()
    write_json(out_dir, "kyb.json", r)
    print(
        f"[KYB] {r['attacks']} attacks, {r['controls']} controls: ASR {pct(r['asr_unguarded'])} -> {pct(r['asr_guarded'])}, FP {pct(r['fp_rate'])}, borderline->review {pct(r['borderline_to_review'])}"
    )
    return r


if __name__ == "__main__":
    main()
