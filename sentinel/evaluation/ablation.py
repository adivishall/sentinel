"""Ablation: which mechanism actually carries the result?

Eight configurations from no controls to full Sentinel. Reported honestly:
detection alone leaks adjudication gaming; policy alone only catches the
over-limit amounts; trusted adjudication closes the false-claim attacks; the
full stack adds explainability, human review and capability containment."""

from __future__ import annotations

from typing import Any

from sentinel.evaluation.attacks import corpus
from sentinel.evaluation.common import (
    CONFIGS,
    breach,
    deserved_approval_missed,
    off_surface,
    pct,
    run_case,
    runtime,
    write_json,
)
from sentinel.evaluation.methodology import methodology


def run(cases: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    cases = cases or corpus.build()
    rt = runtime()
    attacks = [c for c in cases if c["is_attack"]]
    deserved = [c for c in cases if not c["is_attack"] and c["ground_truth_outcome"] == "approve"]
    out: dict[str, Any] = {}
    for name, (controls, hardened) in CONFIGS.items():
        breaches = esc = 0
        for c in attacks:
            b = run_case(rt, c, controls, hardened)
            breaches += int(breach(b))
            esc += int(off_surface(b) and breach(b))
        fps = sum(
            deserved_approval_missed(run_case(rt, c, controls, hardened), c) for c in deserved
        )
        out[name] = {
            "asr": round(breaches / len(attacks), 3),
            "fp": round(fps / max(1, len(deserved)), 3),
            "escalation_executed": round(esc / len(attacks), 3),
            "controls": sorted(controls),
            "hardened": hardened,
        }
    return out


def main(out_dir: str = "results") -> dict[str, Any]:
    r = run()
    r["methodology"] = methodology("ablation", r)
    write_json(out_dir, "ablation.json", r)
    print("[ablation] configuration                ASR      FP     off-surface executed")
    for k, v in r.items():
        print(f"  {k:26} {pct(v['asr'])} {pct(v['fp'])}   {pct(v['escalation_executed'])}")
    return r


if __name__ == "__main__":
    main()
