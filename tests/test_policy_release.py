"""Signed policy releases (issue #14).

INV-POLICY-1  A modified policy cannot execute as a valid signed release: the policy that
              decides is one a trusted policy-release key signed, byte for byte, and
              explicitly activated -- the policy directory (files, MANIFEST.json,
              RELEASES.json) is not the trust root.

Each failure class the issue names has a test: a modified policy with a recomputed
manifest, an unauthorized new version, a fake activation, a wrong signer, a revoked
signer, a version mismatch, an effective-date bypass -- plus activation rollback and
equivocation, the decision / audit / replay record, and the CLI.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sentinel.app import SentinelApp
from sentinel.decision.authority import downgrades
from sentinel.domain.enums import FactKind
from sentinel.policy.loader import (
    DEFAULT_REGISTRY,
    MANIFEST,
    POLICY_DIR,
    SHIPPED_POLICY_ROOT,
    PolicyIntegrityError,
    PolicyRegistry,
    load_policy,
    pin_manifest,
    policy_digest,
    policy_trust,
)
from sentinel.policy.release import (
    RELEASES_FILE,
    ReleaseBook,
    ReleaseStatus,
    sign_activation,
    sign_release,
    verify_release,
)
from sentinel.replay.engine import ReplayOverrides
from sentinel.trust import crypto
from sentinel.trust.keys import FACTS, POLICY_RELEASE, TrustedKey, TrustStore
from tests.records import ledger

NOW = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)


def _key(issuer="release-pipeline", purpose=POLICY_RELEASE, scopes=("*",), **kw):
    private = crypto.generate()
    pub = crypto.public_raw(private)
    key = TrustedKey(
        key_id=crypto.key_id(pub),
        issuer=issuer,
        public_key=pub,
        purpose=purpose,
        scopes=frozenset(scopes),
        not_before=NOW - timedelta(days=30),
        **kw,
    )
    return private, key


def _policies(d: Path):
    return [load_policy(f) for f in sorted(d.glob("*.v*.json"))]


def _sign_dir(d: Path, private, signer="release-pipeline", *, activate=True) -> ReleaseBook:
    """Release every version in ``d`` and activate each in version order (the shipped
    pattern), effective from the document's own date."""
    book = ReleaseBook()
    for p in _policies(d):
        book.releases.append(sign_release(private, signer=signer, policy=p, released_at=NOW))
        if activate:
            eff = datetime.strptime(p.effective_from, "%Y-%m-%d").replace(tzinfo=UTC)
            book.activations.append(
                sign_activation(
                    private,
                    signer=signer,
                    policy=p,
                    sequence=p.version,
                    effective_from=eff,
                    issued_at=NOW,
                )
            )
    (d / RELEASES_FILE).write_text(book.dumps(), encoding="utf-8")
    return book


@pytest.fixture()
def signed_dir(tmp_path):
    """A copy of the shipped policies, released and activated by a test pipeline key."""
    d = tmp_path / "policies"
    shutil.copytree(POLICY_DIR, d)
    private, key = _key()
    _sign_dir(d, private)
    return d, private, TrustStore.empty().with_key(key)


def _registry(d, trust, *, clock=lambda: NOW):
    reg = PolicyRegistry(signed=True, trust=trust, clock=clock)
    reg.load_dir(d)
    return reg


# ---- the shipped releases ----------------------------------------------------------------------
def test_the_shipped_policies_are_released_and_activated_by_the_shipped_root():
    reg = PolicyRegistry(signed=True, trust=TrustStore.load(SHIPPED_POLICY_ROOT))
    reg.load_dir(POLICY_DIR)
    for pid in {p.policy_id for p in reg.all()}:
        a = reg.active(pid)
        assert a.release.status is ReleaseStatus.VERIFIED, pid
        assert a.version == max(reg.versions(pid))  # each was activated in order
        assert a.release.activation_sequence == a.version
    assert DEFAULT_REGISTRY.signed  # required by default
    # the root is outside the policy directory, and holds public keys only
    assert SHIPPED_POLICY_ROOT.parent != POLICY_DIR
    root = json.loads(SHIPPED_POLICY_ROOT.read_text())
    assert all(k["purpose"] == POLICY_RELEASE for k in root["keys"])
    assert "PRIVATE" not in SHIPPED_POLICY_ROOT.read_text()


def test_every_decision_records_the_release_it_ran_under():
    app = SentinelApp.demo(seed=7, customers=40, merchants=10, transactions=600)
    d = app.store.all_disputes()[0]
    b = app.evaluate_dispute("", dispute_id=d.dispute_id)
    pol = b.decision.policy
    active = DEFAULT_REGISTRY.active("dispute-refund")
    assert pol.release_status == "VERIFIED" and pol.policy_digest == policy_digest(active)
    assert pol.release_key_id == active.release.key_id and pol.release_signer == "sentinel-policy"
    assert pol.activation_sequence == active.version
    ev = app.audit_event(b.decision.decision_id)
    assert ev["detail"]["policy_release"]["digest"] == pol.policy_digest
    assert ev["detail"]["policy_release"]["activation_sequence"] == pol.activation_sequence
    snap = app.store.decision_snapshot(b.decision.decision_id)
    assert snap["policy"]["digest"] == pol.policy_digest
    assert app.store.policy_activation_floor()["dispute-refund"] == active.version
    r = app.replay(b.decision.decision_id, ReplayOverrides())
    assert r.policy_release["artifact_matches_recorded"] is True
    assert r.policy_release["artifact"]["status"] == "VERIFIED"


# ---- INV-POLICY-1: each failure class ----------------------------------------------------------
def test_inv_policy_1_a_modified_policy_with_a_recomputed_manifest_is_refused(signed_dir):
    d, _, trust = signed_dir
    f = d / "dispute-refund.v4.json"
    doc = json.loads(f.read_text())
    for r in doc["rules"]:
        if r["outcome"] == "BLOCK":
            r["outcome"] = "ALLOW"  # quietly disarm the BLOCK rules
    f.write_text(json.dumps(doc, indent=2))
    manifest = json.loads((d / MANIFEST).read_text())
    manifest["policies"]["dispute-refund@v4"] = policy_digest(load_policy(f))  # recomputed
    (d / MANIFEST).write_text(json.dumps(manifest))
    PolicyRegistry().load_dir(d)  # the manifest alone is satisfied ...
    with pytest.raises(PolicyIntegrityError, match="dispute-refund@v4 INVALID.*content changed"):
        _registry(d, trust)  # ... the signed release is not


def test_an_unauthorized_new_version_is_refused(signed_dir):
    d, _, trust = signed_dir
    doc = json.loads((d / "dispute-refund.v4.json").read_text())
    doc["version"] = 5
    (d / "dispute-refund.v5.json").write_text(json.dumps(doc, indent=2))
    pin_manifest(d)  # anyone who can write the directory can pin it
    with pytest.raises(PolicyIntegrityError, match="dispute-refund@v5 UNSIGNED"):
        _registry(d, trust)


def test_a_higher_version_is_not_active_until_it_is_activated(signed_dir):
    d, private, trust = signed_dir
    doc = json.loads((d / "dispute-refund.v4.json").read_text())
    doc["version"] = 5
    (d / "dispute-refund.v5.json").write_text(json.dumps(doc, indent=2))
    pin_manifest(d)
    book = ReleaseBook.load(d / RELEASES_FILE)
    v5 = load_policy(d / "dispute-refund.v5.json")
    book.releases.append(
        sign_release(private, signer="release-pipeline", policy=v5, released_at=NOW)
    )
    (d / RELEASES_FILE).write_text(book.dumps())
    reg = _registry(d, trust)
    assert reg.versions("dispute-refund")[-1] == 5
    assert reg.active("dispute-refund").version == 4  # released, not activated
    book.activations.append(
        sign_activation(
            private,
            signer="release-pipeline",
            policy=v5,
            sequence=5,
            effective_from=NOW,
            issued_at=NOW,
        )
    )
    (d / RELEASES_FILE).write_text(book.dumps())
    assert _registry(d, trust).active("dispute-refund").version == 5


def test_a_fake_activation_counts_for_nothing(signed_dir):
    d, private, trust = signed_dir
    v1 = load_policy(d / "dispute-refund.v1.json")
    book = ReleaseBook.load(d / RELEASES_FILE)
    forger, _ = _key()  # not in the trust store
    book.activations.append(
        sign_activation(
            forger,
            signer="release-pipeline",
            policy=v1,
            sequence=99,
            effective_from=NOW,
            issued_at=NOW,
        )
    )
    genuine = next(a for a in book.activations if a["policy_id"] == "dispute-refund")
    book.activations.append(dict(genuine, sequence=100))  # a genuine statement, edited
    (d / RELEASES_FILE).write_text(book.dumps())
    reg = _registry(d, trust)
    assert reg.active("dispute-refund").version == 4
    assert any("unknown signer" in x for x in reg.release_problems)
    assert any("does not verify" in x for x in reg.release_problems)


def test_an_activation_of_content_that_was_never_released_is_refused(signed_dir):
    d, private, trust = signed_dir
    v4 = load_policy(d / "dispute-refund.v4.json")
    lax = replace(v4, rules=tuple(r for r in v4.rules if r.outcome.value != "BLOCK"))
    book = ReleaseBook.load(d / RELEASES_FILE)
    book.activations.append(
        sign_activation(  # the right key, but it activates a digest nobody released
            private,
            signer="release-pipeline",
            policy=lax,
            sequence=9,
            effective_from=NOW,
            issued_at=NOW,
        )
    )
    (d / RELEASES_FILE).write_text(book.dumps())
    reg = _registry(d, trust)
    assert reg.active("dispute-refund").release.activation_sequence == 4
    assert any("other content" in x for x in reg.release_problems)


@pytest.mark.parametrize(
    "who, why",
    [
        ({"issuer": "someone-else"}, "belongs to someone-else"),
        ({"purpose": FACTS, "scopes": ("*",)}, "not trusted to release"),
        ({"scopes": ("merchant-onboarding",)}, "not trusted to release dispute-refund"),
    ],
)
def test_a_wrong_signer_is_refused(signed_dir, who, why):
    d, _, _ = signed_dir
    private, key = _key(**who)
    _sign_dir(d, private, signer="release-pipeline")
    with pytest.raises(PolicyIntegrityError, match=why):
        _registry(d, TrustStore.empty().with_key(key))


def test_a_revoked_signer_is_refused(signed_dir):
    d, _, trust = signed_dir
    (key,) = trust.keys.values()
    revoked = TrustStore.empty().with_key(
        replace(key, revoked_at=NOW - timedelta(hours=1), revocation_reason="compromised")
    )
    with pytest.raises(PolicyIntegrityError, match="REVOKED.*compromised"):
        _registry(d, revoked)


def test_a_release_for_another_version_does_not_release_this_one(signed_dir):
    d, private, trust = signed_dir
    v3, v4 = (load_policy(d / f"dispute-refund.v{v}.json") for v in (3, 4))
    stmt = sign_release(private, signer="release-pipeline", policy=v3, released_at=NOW)
    r = verify_release(stmt, policy=v4, trust=trust, now=NOW)
    assert r.status is ReleaseStatus.INVALID and "not dispute-refund@v4" in r.reason
    relabelled = dict(stmt, version=4)  # the label edited, the signature kept
    r = verify_release(relabelled, policy=v4, trust=trust, now=NOW)
    assert r.status is ReleaseStatus.INVALID and "does not verify" in r.reason


def test_an_activation_cannot_precede_the_policys_own_effective_date(signed_dir):
    d, private, trust = signed_dir
    v4 = load_policy(d / "dispute-refund.v4.json")
    book = ReleaseBook.load(d / RELEASES_FILE)
    book.activations.append(
        sign_activation(
            private,
            signer="release-pipeline",
            policy=v4,
            sequence=7,
            effective_from=datetime(2026, 1, 1, tzinfo=UTC),
            issued_at=NOW,
        )
    )
    (d / RELEASES_FILE).write_text(book.dumps())
    reg = _registry(d, trust)
    assert any("before dispute-refund@v4's own effective_from" in x for x in reg.release_problems)


def test_a_scheduled_activation_takes_effect_on_the_system_clock_only(signed_dir):
    d, private, trust = signed_dir
    v3 = load_policy(d / "dispute-refund.v3.json")
    book = ReleaseBook.load(d / RELEASES_FILE)
    book.activations.append(  # roll back to v3, scheduled for tomorrow
        sign_activation(
            private,
            signer="release-pipeline",
            policy=v3,
            sequence=10,
            effective_from=NOW + timedelta(days=1),
            issued_at=NOW,
        )
    )
    (d / RELEASES_FILE).write_text(book.dumps())
    clock = {"now": NOW}
    reg = _registry(d, trust, clock=lambda: clock["now"])
    assert reg.active("dispute-refund").version == 4
    clock["now"] = NOW + timedelta(days=1, minutes=1)
    assert reg.active("dispute-refund").version == 3


def test_an_activation_rollback_is_refused(signed_dir):
    """Deleting the newest activation from RELEASES.json would re-activate an older
    version; the audit chain remembers the activation decisions were made under."""
    d, _, trust = signed_dir
    book = ReleaseBook.load(d / RELEASES_FILE)
    book.activations = [
        a
        for a in book.activations
        if not (a["policy_id"] == "dispute-refund" and a["sequence"] == 4)
    ]
    (d / RELEASES_FILE).write_text(book.dumps())
    reg = _registry(d, trust)
    assert reg.active("dispute-refund").version == 3  # nothing else remembers ...
    reg.set_activation_floor("dispute-refund", 4)  # ... but the audit chain does
    with pytest.raises(PolicyIntegrityError, match="rollback"):
        reg.active("dispute-refund")


def test_two_activations_with_one_sequence_are_equivocation(signed_dir):
    d, private, trust = signed_dir
    v3 = load_policy(d / "dispute-refund.v3.json")
    book = ReleaseBook.load(d / RELEASES_FILE)
    book.activations.append(
        sign_activation(
            private,
            signer="release-pipeline",
            policy=v3,
            sequence=4,
            effective_from=NOW,
            issued_at=NOW,
        )
    )
    (d / RELEASES_FILE).write_text(book.dumps())
    with pytest.raises(PolicyIntegrityError, match="equivocation"):
        _registry(d, trust)


def test_the_policy_directory_is_not_the_trust_root(signed_dir, monkeypatch):
    """A writer of the directory signs with their own key and drops a trust store beside
    the policies: the root is SENTINEL_POLICY_TRUST or the shipped one, never the
    directory."""
    d, _, _ = signed_dir
    attacker, key = _key(issuer="sentinel-policy")
    _sign_dir(d, attacker, signer="sentinel-policy")
    (d / "trust").mkdir()
    (d / "trust" / "policy_root.json").write_text(TrustStore.empty().with_key(key).dumps())
    monkeypatch.delenv("SENTINEL_POLICY_TRUST", raising=False)
    assert policy_trust().origin == str(SHIPPED_POLICY_ROOT)
    with pytest.raises(PolicyIntegrityError, match="unknown signer"):
        PolicyRegistry(signed=True).load_dir(d)


def test_an_unverified_policy_is_never_recorded_as_authoritative(signed_dir):
    from sentinel.decision.workflows import DisputeRequest, Runtime, run_dispute
    from sentinel.security.provenance import UntrustedContent

    d, _, trust = signed_dir
    reg = _registry(d, trust)
    b = run_dispute(
        Runtime(persist=False, policies=reg),
        DisputeRequest(UntrustedContent("It never arrived."), ledger()),
    )
    assert b.inputs is not None and not downgrades(b.inputs, reg)
    stripped = replace(b.inputs, policy=replace(b.inputs.policy, release=None))
    assert any("no verified signed release" in x for x in downgrades(stripped, reg))


def test_replay_reports_an_artifact_that_is_not_the_recorded_release():
    app = SentinelApp.demo(seed=7, customers=40, merchants=10, transactions=600)
    env = app.issuer.sign(FactKind.DISPUTE_LEDGER, "DSP-RELEASE", ledger())
    b = app.evaluate_dispute("It never arrived.", envelope=env)
    did = b.decision.decision_id
    snap = app.store.decision_snapshot(did)
    snap["policy"]["digest"] = "0" * 64  # recorded under some other release
    app.store._exec(
        "UPDATE decisions SET snapshot = ? WHERE decision_id = ?", (json.dumps(snap), did)
    )
    r = app.replay(did, ReplayOverrides())
    assert r.policy_release["artifact_matches_recorded"] is False
    assert "not the one the decision recorded" in r.explanation
    assert not r.record_verified  # and the snapshot no longer matches its audit event


# ---- the CLI -----------------------------------------------------------------------------------
def test_the_cli_signs_activates_and_verifies(tmp_path, capsys):
    from sentinel.cli.main import main

    d = tmp_path / "policies"
    shutil.copytree(POLICY_DIR, d)
    (d / RELEASES_FILE).unlink()
    key, trust = tmp_path / "release.pem", tmp_path / "policy-trust.json"
    assert (
        main(
            [
                "trust",
                "keygen",
                "--issuer",
                "pipeline",
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
    for p in _policies(d):
        args = [
            "--key",
            str(key),
            "--signer",
            "pipeline",
            "--policy",
            p.policy_id,
            "--version",
            str(p.version),
            "--dir",
            str(d),
        ]
        assert main(["policy", "sign", *args]) == 0
        eff = p.effective_from + "T00:00:00Z"
        assert main(["policy", "activate", *args, "--effective-from", eff]) == 0
    capsys.readouterr()
    assert main(["policy", "verify", "--dir", str(d), "--trust", str(trust)]) == 0
    assert "dispute-refund" in capsys.readouterr().out
    f = d / "dispute-refund.v4.json"
    f.write_text(f.read_text().replace('"BLOCK"', '"ALLOW"', 1))
    assert main(["policy", "verify", "--dir", str(d), "--trust", str(trust)]) == 2
    assert "REFUSED" in capsys.readouterr().out
