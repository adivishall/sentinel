"""Do we beat the obvious defence? no defence vs hardened prompt vs Sentinel."""

from __future__ import annotations

from typing import Any

from sentinel.decision.workflows import FULL, NONE
from sentinel.evaluation.attacks import corpus
from sentinel.evaluation.common import breach, pct, run_case, runtime, write_json
from sentinel.evaluation.methodology import methodology


def run(cases: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    cases = cases or corpus.build()
    rt = runtime()
    attacks = [c for c in cases if c["is_attack"]]
    n = len(attacks)
    out: dict[str, Any] = {}
    out["no_defence"] = round(sum(breach(run_case(rt, c, NONE)) for c in attacks) / n, 3)
    hardened = {c["id"]: breach(run_case(rt, c, NONE, hardened=True)) for c in attacks}
    out["hardened_prompt"] = round(sum(hardened.values()) / n, 3)
    out["sentinel"] = round(sum(breach(run_case(rt, c, FULL)) for c in attacks) / n, 3)
    by: dict[str, list[int]] = {}
    for c in attacks:
        k = c["attack_class"]
        by.setdefault(k, [0, 0])
        by[k][1] += 1
        by[k][0] += int(hardened[c["id"]])
    out["hardened_by_class"] = {k: round(v[0] / v[1], 3) for k, v in by.items()}
    return out


def main(out_dir: str = "results") -> dict[str, Any]:
    r = run()
    r["methodology"] = methodology("baselines", r)
    write_json(out_dir, "baselines.json", r)
    print(
        f"[baselines] no defence {pct(r['no_defence'])}   hardened prompt {pct(r['hardened_prompt'])}   Sentinel {pct(r['sentinel'])}"
    )
    print(
        "  where the hardened prompt still fails:",
        {k: v for k, v in r["hardened_by_class"].items() if v > 0},
    )
    return r


if __name__ == "__main__":
    main()
