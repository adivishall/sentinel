"""Every data file the package reads at runtime ships in the wheel.

Found by the release audit (critical): the policy trust root
(sentinel/trust/policy_root.json) was not in package-data, so a non-editable install
(and the Docker image) could not load a single policy and refused to start."""

from __future__ import annotations

import tomllib
from fnmatch import fnmatch
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "sentinel"


def test_every_non_python_file_in_the_package_is_declared_as_package_data():
    globs = tomllib.loads((ROOT / "pyproject.toml").read_text())["tool"]["setuptools"][
        "package-data"
    ]["sentinel"]
    data = [
        p.relative_to(PKG).as_posix()
        for p in PKG.rglob("*")
        if p.is_file() and p.suffix not in (".py", ".pyc") and "__pycache__" not in p.parts
    ]
    missing = [f for f in data if not any(fnmatch(f, g) for g in globs)]
    assert not missing, f"not shipped in the wheel: {missing}"


def test_the_policy_trust_root_is_shipped():
    assert (PKG / "trust" / "policy_root.json").is_file()
