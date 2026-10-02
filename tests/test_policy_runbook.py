"""The operator's policy-release runbook (docs/DEPLOYMENT.md, "Policy releases"), executed.

Found by the release audit: following the documented commands ended in REFUSED -- they
omitted the operator's trust store and policy directory, and never re-released the
shipped versions under the operator's key. This runs the documented steps verbatim."""

from __future__ import annotations

import json
import shutil

from sentinel.cli.main import main
from sentinel.policy.loader import MANIFEST, POLICY_DIR, PolicyRegistry, policy_dir, policy_trust
from sentinel.policy.release import RELEASES_FILE


def test_an_operator_can_release_the_policies_under_their_own_root(tmp_path, monkeypatch, capsys):
    key, trust, pdir = tmp_path / "release.pem", tmp_path / "policy-trust.json", tmp_path / "p"
    # 1. the operator's release key and trust root
    assert (
        main(
            [
                "trust",
                "keygen",
                "--issuer",
                "policy-pipeline",
                "--purpose",
                "policy-release",
                "--key-out",
                str(key),
                "--trust-out",
                str(trust),
            ]
        )
        == 0
    )
    # 2. a copy of the policies, without the maintainers' release book
    shutil.copytree(POLICY_DIR, pdir)
    (pdir / RELEASES_FILE).unlink()
    monkeypatch.setenv("SENTINEL_POLICY_DIR", str(pdir))
    monkeypatch.setenv("SENTINEL_POLICY_TRUST", str(trust))
    # 3. release every pinned version under the operator's key, 4. activate the newest
    newest: dict[str, int] = {}
    for k in json.loads((pdir / MANIFEST).read_text())["policies"]:
        pid, _, v = k.partition("@v")
        assert (
            main(
                [
                    "policy",
                    "sign",
                    "--key",
                    str(key),
                    "--signer",
                    "policy-pipeline",
                    "--policy",
                    pid,
                    "--version",
                    v,
                ]
            )
            == 0
        )
        newest[pid] = max(newest.get(pid, 0), int(v))
    for pid, v in newest.items():
        assert (
            main(
                [
                    "policy",
                    "activate",
                    "--key",
                    str(key),
                    "--signer",
                    "policy-pipeline",
                    "--policy",
                    pid,
                    "--version",
                    str(v),
                ]
            )
            == 0
        )
    # 5. verify, as the server does at start
    capsys.readouterr()
    assert main(["policy", "verify"]) == 0
    reg = PolicyRegistry(signed=True, trust=policy_trust())
    reg.load_dir(policy_dir())
    assert {pid: reg.active(pid).version for pid in newest} == newest
    assert reg.trust_root == "operator"
