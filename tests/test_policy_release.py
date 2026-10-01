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
    assert any("not a verified, activated release" in x for x in downgrades(stripped, reg))
    # a release is bound to its content: an edited copy keeps no VERIFIED stamp
    edited = replace(b.inputs.policy, rules=b.inputs.policy.rules[1:])
    assert edited.release.status is ReleaseStatus.INVALID
    assert downgrades(replace(b.inputs, policy=edited), reg)  # refused, either way


def test_replay_reports_an_artifact_that_is_not_the_recorded_release():
    """The recorded release comes from the audit event; a replay that runs edited rules
    runs an artifact nobody released, and says so."""
    app = SentinelApp.demo(seed=7, customers=40, merchants=10, transactions=600)
    env = app.issuer.sign(FactKind.DISPUTE_LEDGER, "DSP-RELEASE", ledger())
    did = app.evaluate_dispute("It never arrived.", envelope=env).decision.decision_id
    same = app.replay(did, ReplayOverrides())
    assert same.policy_release["artifact_matches_recorded"] is True
    rule = DEFAULT_REGISTRY.active("dispute-refund").rules[-1].rule_id
    r = app.replay(did, ReplayOverrides(rule_values={rule: 1}))
    assert r.policy_release["recorded"]["release_status"] == "VERIFIED"
    assert r.policy_release["artifact"]["status"] == "INVALID"
    assert r.policy_release["artifact_matches_recorded"] is False
    assert "not the one the decision recorded" in r.explanation


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
            "--trust",
            str(trust),
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


# ---- regressions: the adversarial review of #14 ------------------------------------------------
def test_r2_a_policy_value_must_be_json_and_keys_unique(tmp_path):
    from sentinel.policy.engine import PolicyValidationError
    from sentinel.policy.loader import policy_from_dict

    doc = json.loads((POLICY_DIR / "dispute-refund.v4.json").read_text())
    dated = json.loads(json.dumps(doc))
    dated["rules"][0]["when"][0]["value"] = [datetime(2026, 9, 30).date()]
    with pytest.raises(PolicyValidationError, match="not a JSON value"):
        policy_from_dict(dated)  # a YAML date stringifies to text another file could hold
    f = tmp_path / "p.v4.json"
    text = (POLICY_DIR / "dispute-refund.v4.json").read_text()
    f.write_text(text.replace('"outcome": "BLOCK",', '"outcome": "BLOCK", "outcome": "ALLOW",', 1))
    with pytest.raises(PolicyValidationError, match="duplicate key"):
        load_policy(f)
    for bad in (4.9, True, "4"):
        with pytest.raises(PolicyValidationError, match="positive integer"):
            policy_from_dict({**doc, "version": bad})


def test_r2_signed_policies_are_json_only(signed_dir):
    d, _, trust = signed_dir
    (d / "extra.v1.yaml").write_text("policy_id: x\n")
    with pytest.raises(PolicyIntegrityError, match="JSON only"):
        _registry(d, trust)


def test_r3_an_unreadable_trust_root_leaves_no_usable_empty_registry(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_POLICY_TRUST", str(tmp_path / "missing.json"))
    reg = PolicyRegistry(autoload=POLICY_DIR, signed=True)
    for _ in range(2):  # stays unusable: never an empty registry that "works"
        with pytest.raises(PolicyIntegrityError, match="trust root does not load"):
            reg.all()


def _record_activations(store, activations):
    """What a newer Sentinel start would have chained: activations in effect."""
    from sentinel.audit.chain import AuditChain
    from sentinel.data.store import SqliteAuditBackend

    AuditChain(SqliteAuditBackend(store)).append(
        actor="sentinel",
        workflow="system",
        action="POLICY_ACTIVATIONS",
        kind="system",
        detail={"activations": activations},
    )


def test_r4_a_rollback_is_caught_for_a_policy_no_decision_used(tmp_path):
    """Activations in effect are recorded at start (POLICY_ACTIVATIONS), so removing one
    for a policy without decisions is still a rollback on the next start."""
    from sentinel.data.store import SentinelStore

    store = SentinelStore(str(tmp_path / "s.db"))
    SentinelApp(store)
    assert store.policy_activation_floor()["investigation"] == 1
    assert store.policy_activation_floor()["transaction-authorization"] == 3
    SentinelApp(store)  # unchanged activations: no new event, starts again
    _record_activations(store, {"investigation": 2})  # a later start ran under activation 2
    with pytest.raises(PolicyIntegrityError, match="investigation: activation 1 is older"):
        SentinelApp(store)


def test_r5_one_stores_history_does_not_lock_out_other_apps(tmp_path):
    from sentinel.data.store import SentinelStore

    store = SentinelStore(str(tmp_path / "s.db"))
    _record_activations(store, {"dispute-refund": 9})
    with pytest.raises(PolicyIntegrityError, match="rollback"):
        SentinelApp(store)
    SentinelApp()  # a fresh app in the same process is unaffected
    assert DEFAULT_REGISTRY.active("dispute-refund").version == 4


def test_r5_no_trustworthy_policy_is_a_503(monkeypatch):
    from sentinel.api.server import build_routes

    app = SentinelApp.demo(seed=3, customers=10, merchants=4, transactions=80)

    def broken(*a, **k):
        raise PolicyIntegrityError("no signed activation in effect")

    monkeypatch.setattr(app, "evaluate_dispute", broken)
    import threading
    import urllib.error
    import urllib.request

    from sentinel.api.server import make_server

    httpd = make_server(app, "127.0.0.1", 0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{httpd.server_address[1]}/v1/disputes/evaluate",
            data=json.dumps({"dispute_id": "DSP-000001"}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(req, timeout=10)
        assert e.value.code == 503 and "no signed activation" not in e.value.read().decode()
    finally:
        httpd.shutdown()
    assert build_routes  # (the route table is unchanged)


def test_r6_an_unsigned_book_entry_cannot_push_the_activation_sequence(tmp_path):
    from sentinel.cli.main import main

    d = tmp_path / "policies"
    shutil.copytree(POLICY_DIR, d)
    (d / RELEASES_FILE).unlink()
    key, trust = tmp_path / "release.pem", tmp_path / "policy-trust.json"
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
    common = ["--key", str(key), "--signer", "pipeline", "--dir", str(d), "--trust", str(trust)]
    assert main(["policy", "sign", *common, "--policy", "investigation", "--version", "1"]) == 0
    book = ReleaseBook.load(d / RELEASES_FILE)
    book.activations.append({"policy_id": "investigation", "sequence": 2**53 - 2})  # junk
    (d / RELEASES_FILE).write_text(book.dumps())
    assert (
        main(
            [
                "policy",
                "activate",
                *common,
                "--policy",
                "investigation",
                "--version",
                "1",
                "--effective-from",
                "2026-09-01T00:00:00Z",
            ]
        )
        == 0
    )
    seqs = [a.get("sequence") for a in ReleaseBook.load(d / RELEASES_FILE).activations]
    assert seqs[-1] == 1  # from the verified activations, not the junk


def test_r8_an_unreadable_effective_from_is_refused_in_signed_mode(signed_dir):
    d, private, trust = signed_dir
    f = d / "investigation.v1.json"
    doc = json.loads(f.read_text())
    doc["effective_from"] = "2026-09-01T00:00:00+00:00"
    f.write_text(json.dumps(doc, indent=2))
    manifest = json.loads((d / MANIFEST).read_text())
    manifest["policies"]["investigation@v1"] = policy_digest(load_policy(f))
    (d / MANIFEST).write_text(json.dumps(manifest))
    book = ReleaseBook.load(d / RELEASES_FILE)
    book.releases = [r for r in book.releases if r["policy_id"] != "investigation"]
    book.releases.append(
        sign_release(private, signer="release-pipeline", policy=load_policy(f), released_at=NOW)
    )
    (d / RELEASES_FILE).write_text(book.dumps())
    with pytest.raises(PolicyIntegrityError, match="unreadable"):
        _registry(d, trust)


def test_a_digest_with_a_trailing_newline_is_not_a_digest():
    """``$`` also matches before a final newline; the digest grammar is a full match."""
    private, key = _key()
    policy = DEFAULT_REGISTRY.get("dispute-refund", 4)
    doc = sign_release(private, signer=key.issuer, policy=policy, released_at=NOW)
    trust = TrustStore.empty().with_key(key)
    assert verify_release(doc, policy=policy, trust=trust, now=NOW).status is ReleaseStatus.VERIFIED
    doc["digest"] += "\n"
    r = verify_release(doc, policy=policy, trust=trust, now=NOW)
    assert r.status is ReleaseStatus.INVALID and "full SHA-256" in r.reason
