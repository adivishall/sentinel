#!/usr/bin/env python3
"""The static console as a deployable directory: a fresh snapshot from the real
engine, validated, next to the console's own files.

    python scripts/static_console.py build --out public      # what Vercel runs (vercel.json)
    python scripts/static_console.py check ui/snapshot.json  # validate a snapshot

``build`` regenerates the snapshot with the installed engine (``sentinel ui snapshot`` on
an in-memory store filled with the synthetic demo world, offline simulator forced),
refuses to publish one that fails ``check``, and assembles ``index.html`` + ``ui/`` (the
console's HTML, JavaScript, stylesheet and the snapshot) in the output directory --
nothing else from the repository. A static host serves that directory; the console finds
no API there, falls back to the snapshot and says so in its sidebar. ``check`` is
deliberately strict: a stale, empty, tampered or non-offline snapshot is a build
failure, never a published page.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
CONSOLE_FILES = ("index.html", "ui/index.html", "ui/app.js", "ui/styles.css")
SECRET_KEY = re.compile(r"token|secret|password|api_key|private_key|credential", re.I)
NON_EMPTY = (
    ("transactions", "transactions"),
    ("disputes", "disputes"),
    ("merchants", "merchants"),
    ("accounts", "accounts"),
    ("cases", "cases"),
    ("decisions", "decisions"),
    ("policies", "policies"),
    ("evaluations", "results"),
)


class SnapshotError(ValueError):
    """The snapshot must not be published."""


def _secret_like(node: Any, path: str = "") -> list[str]:
    """Keys that look like a credential and carry a non-empty string value."""
    found: list[str] = []
    if isinstance(node, dict):
        for k, v in node.items():
            here = f"{path}/{k}"
            derived = str(k).endswith(("_hash", "_digest", "_id", "_fingerprint"))
            if SECRET_KEY.search(str(k)) and not derived and isinstance(v, str) and v:
                found.append(here)
            found.extend(_secret_like(v, here))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            found.extend(_secret_like(v, f"{path}[{i}]"))
    return found


def check(path: Path, version: str | None = None) -> dict[str, Any]:
    """Validate a snapshot file; return a short summary or raise ``SnapshotError``."""
    try:
        snap = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise SnapshotError(f"{path}: not readable JSON ({e})") from e
    marker = snap.get("generated_by", "") if isinstance(snap, dict) else ""
    if not str(marker).startswith("sentinel ui snapshot"):
        raise SnapshotError(f"{path}: not a sentinel ui snapshot")
    if version is None:
        from sentinel import __version__ as installed

        version = installed
    system = snap.get("system") or {}
    problems: list[str] = []
    if system.get("version") != version:
        problems.append(f"system.version {system.get('version')!r} != engine {version!r}")
    if system.get("mode") != "offline" or system.get("provider") != "offline":
        problems.append("not the offline simulator")
    if system.get("store") != ":memory:":
        problems.append(f"store {system.get('store')!r}: not a throwaway in-memory world")
    for key, inner in NON_EMPTY:
        if not (snap.get(key) or {}).get(inner):
            problems.append(f"{key}.{inner} is empty")
    verify = snap.get("audit_verify") or {}
    if verify.get("ok") is not True or not verify.get("length"):
        problems.append("audit chain not verified")
    elif verify.get("head_hash") != (snap.get("audit") or {}).get("head"):
        problems.append("audit head does not match audit_verify")
    compare = snap.get("attack_compare") or {}
    if not compare:
        problems.append("attack_compare is empty")
    for kind, result in compare.items():
        executed = ((result or {}).get("summary") or {}).get("with_sentinel_executed")
        if (result or {}).get("attack_class") == "none":  # the deserved control must execute
            if executed != (result or {}).get("target_capability") or executed is None:
                problems.append(f"control {kind}: the deserved capability did not execute")
        elif executed is not None:
            problems.append(f"attack {kind}: a capability executed with Sentinel")
    secrets = _secret_like(snap)
    if secrets:
        problems.append("secret-like values at " + ", ".join(secrets[:5]))
    if problems:
        raise SnapshotError(f"{path}: " + "; ".join(problems))
    return {
        "version": version,
        "decisions": len(snap["decisions"]["decisions"]),
        "cases": len(snap["cases"]["cases"]),
        "attacks": len(compare),
        "audit_events": verify["length"],
        "bytes": path.stat().st_size,
    }


def build(out: Path) -> dict[str, Any]:
    """Regenerate, validate and assemble; ``out`` is replaced only after every step passed."""
    with tempfile.TemporaryDirectory(prefix="sentinel-console-") as tmp:
        stage = Path(tmp) / "site"
        (stage / "ui").mkdir(parents=True)
        snap = stage / "ui" / "snapshot.json"
        cmd = [sys.executable, "-m", "sentinel", "--db", ":memory:", "ui", "snapshot", "--out"]
        env = {**os.environ, "SENTINEL_FORCE_OFFLINE": "1"}
        subprocess.run([*cmd, str(snap)], check=True, cwd=ROOT, env=env)
        summary = check(snap)
        for rel in CONSOLE_FILES:
            shutil.copy2(ROOT / rel, stage / rel)
        if out.exists():
            shutil.rmtree(out)
        shutil.copytree(stage, out)
    return summary


def _describe(s: dict[str, Any]) -> str:
    return (
        f"version {s['version']}, {s['decisions']} decisions, {s['cases']} cases, "
        f"{s['attacks']} attack comparisons, {s['audit_events']} audit events, "
        f"{s['bytes'] / 1e6:.1f} MB"
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="the static console: build or check")
    sub = ap.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build", help="fresh snapshot + console files into a directory")
    b.add_argument("--out", default="public")
    c = sub.add_parser("check", help="validate a snapshot file")
    c.add_argument("snapshot")
    args = ap.parse_args(argv)
    try:
        if args.command == "check":
            print(f"snapshot ok: {_describe(check(Path(args.snapshot)))}")
        else:
            print(f"static console -> {args.out}/: {_describe(build(Path(args.out)))}")
    except (SnapshotError, subprocess.CalledProcessError, OSError) as e:
        print(f"static console: FAILED: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
