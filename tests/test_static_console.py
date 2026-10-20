"""The static console build (``scripts/static_console.py``, what Vercel runs): a fresh
snapshot from the engine, validated, assembled next to the console's files -- and a check
that refuses a stale, empty, tampered or non-offline snapshot."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CONSOLE = ["index.html", "ui/app.js", "ui/index.html", "ui/snapshot.json", "ui/styles.css"]


@pytest.fixture(scope="module")
def static_console():
    spec = importlib.util.spec_from_file_location(
        "static_console", ROOT / "scripts" / "static_console.py"
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def built(static_console, tmp_path_factory):
    out = tmp_path_factory.mktemp("console") / "public"
    return out, static_console.build(out)


def _snapshot(out: Path) -> dict:
    return json.loads((out / "ui" / "snapshot.json").read_text(encoding="utf-8"))


def test_committed_pages_snapshot_is_current(static_console):
    """The snapshot GitHub Pages serves from main must be the installed engine's own."""
    from sentinel import __version__

    s = static_console.check(ROOT / "ui" / "snapshot.json")
    assert s["version"] == __version__ and s["decisions"] and s["cases"] and s["attacks"]


def test_build_assembles_only_the_console(built):
    out, summary = built
    files = sorted(str(p.relative_to(out)) for p in out.rglob("*") if p.is_file())
    assert files == CONSOLE
    for rel in CONSOLE:
        if rel != "ui/snapshot.json":
            assert (out / rel).read_bytes() == (ROOT / rel).read_bytes()
    snap = _snapshot(out)
    assert snap["system"]["store"] == ":memory:" and snap["system"]["mode"] == "offline"
    assert summary["audit_events"] == snap["audit_verify"]["length"] > 0
    compare = snap["attack_compare"]
    attacks = {
        k: r["summary"]["with_sentinel_executed"]
        for k, r in compare.items()
        if r["attack_class"] != "none"
    }
    controls = {
        k: r["summary"]["with_sentinel_executed"]
        for k, r in compare.items()
        if r["attack_class"] == "none"
    }
    assert attacks and set(attacks.values()) == {None}  # no attack executes with Sentinel
    assert controls and None not in controls.values()  # the deserved control still executes


def _set(*path, value):
    def mutate(snap):
        node = snap
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = value

    return mutate


@pytest.mark.parametrize(
    "mutate, problem",
    [
        (_set("system", "version", value="0.0.0"), "system.version"),
        (_set("system", "mode", value="live"), "offline simulator"),
        (_set("system", "store", value="/data/sentinel.db"), "in-memory"),
        (_set("cases", "cases", value=[]), "cases.cases is empty"),
        (_set("audit_verify", "ok", value=False), "audit chain not verified"),
        (_set("audit", "head", value="0" * 64), "audit head"),
        (
            _set(
                "attack_compare",
                "document_injection",
                "summary",
                "with_sentinel_executed",
                value="APPROVE_REFUND",
            ),
            "executed with Sentinel",
        ),
        (
            _set(
                "attack_compare",
                "legitimate_control",
                "summary",
                "with_sentinel_executed",
                value=None,
            ),
            "deserved capability did not execute",
        ),
        (_set("system", "api_key", value="not-a-real-key"), "secret-like"),
    ],
)
def test_check_refuses_a_bad_snapshot(static_console, built, tmp_path, mutate, problem):
    out, _ = built
    snap = _snapshot(out)
    mutate(snap)
    bad = tmp_path / "snapshot.json"
    bad.write_text(json.dumps(snap), encoding="utf-8")
    with pytest.raises(static_console.SnapshotError, match=problem):
        static_console.check(bad)


def test_check_refuses_non_snapshots(static_console, tmp_path):
    p = tmp_path / "x.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(static_console.SnapshotError, match="not readable JSON"):
        static_console.check(p)
    p.write_text(json.dumps({"hello": "world"}), encoding="utf-8")
    with pytest.raises(static_console.SnapshotError, match="not a sentinel ui snapshot"):
        static_console.check(p)


def test_cli_exit_codes(static_console, built, tmp_path, capsys):
    out, _ = built
    assert static_console.main(["check", str(out / "ui" / "snapshot.json")]) == 0
    assert "snapshot ok" in capsys.readouterr().out
    empty = tmp_path / "empty.json"
    empty.write_text("{}", encoding="utf-8")
    assert static_console.main(["check", str(empty)]) == 1
    assert "FAILED" in capsys.readouterr().err
