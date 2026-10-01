"""Fact provenance (sentinel.trust): why Sentinel may trust the facts behind a decision.

INV-PROV-1  Attacker-controlled input -- text, request-body facts, or a forged, altered,
            mis-addressed, replayed, expired or revoked envelope -- cannot produce a
            VERIFIED_EXTERNAL decision, and facts that are not trusted never execute a
            consequential capability.
INV-AUDIT-1 (facts) The audit event identifies the provenance and the exact payload of the
            facts a decision used, and replay verifies the recorded statement again.

Plus the regressions for the trust-audit findings this closes (issue #11).
"""

from __future__ import annotations

import copy
import dataclasses
import inspect
import json
from datetime import timedelta

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from sentinel.app import SentinelApp
from sentinel.decision.workflows import DisputeRequest, Runtime, run_dispute
from sentinel.domain.enums import (
    EvidenceStatus,
    EvidenceVerdict,
    FactKind,
    FinalAction,
    ProvenanceStatus,
    TrustClass,
)
from sentinel.replay.engine import ReplayOverrides
from sentinel.security.provenance import UntrustedContent
from sentinel.trust import crypto
from sentinel.trust.canonical import CanonicalError, canonical_json, digest, strict_loads
from sentinel.trust.facts import (
    DOMAIN,
    HEADER_FIELDS,
    MemorySequences,
    envelope_digest,
    verify_fact,
)
from sentinel.trust.issuer import Issuer, utc_now
from sentinel.trust.keys import TrustStore, TrustStoreError
from tests.records import ledger

KIND = FactKind.DISPUTE_LEDGER
LEDGER = ledger(amount=18000, delivery_status="not_delivered", refund_state="none")
CLAIM = "My order never arrived after three weeks."
ISSUER = Issuer.ephemeral("core-ledger", scopes=("dispute_ledger", "kyb_record"))
TRUST = TrustStore.empty().with_key(ISSUER.key)
NOW = utc_now()


def _verify(env, *, trust=TRUST, now=NOW, kind=KIND, subject="dispute:DSP-1", sequences=None):
    return verify_fact(
        env, trust=trust, now=now, kind=kind, subject=subject, sequences=sequences
    ).provenance


def _signed(payload=LEDGER, record_id="DSP-1", issuer=ISSUER, **kw):
    return issuer.sign(KIND, record_id, dict(payload), **kw)


# ---- canonical JSON ----------------------------------------------------------------------------
def test_canonical_json_is_one_byte_string_per_value():
    a = canonical_json({"b": 1, "a": [True, None, "é"]})
    b = canonical_json({"a": [True, None, "é"], "b": 1})
    assert a == b == '{"a":[true,null,"é"],"b":1}'.encode()


@pytest.mark.parametrize(
    "raw",
    [
        '{"a":1,"a":2}',  # two parsers could keep different values
        '{"a":1.0}',  # 1.0 and 1 are the same number with different bytes
        '{"a":NaN}',
        '{"a":Infinity}',
        '{"a":9007199254740993}',  # outside the range every JSON reader holds exactly
        "[" * 40 + "]" * 40,
        '"\\ud800"',  # a lone surrogate is not text
        b"\xff\xfe",
    ],
)
def test_strict_parsing_refuses_what_has_no_canonical_form(raw):
    with pytest.raises(CanonicalError):
        strict_loads(raw)


def test_canonical_json_refuses_non_json_values():
    for bad in ({"a": 1.5}, {1: "x"}, {"a": object()}, {"a": float("nan")}):
        with pytest.raises(CanonicalError):
            canonical_json(bad)


# ---- envelope verification: every refusal is named ------------------------------------------
def test_a_signed_statement_verifies():
    p = _verify(_signed())
    assert p.status is ProvenanceStatus.VERIFIED_EXTERNAL
    assert p.key_id == ISSUER.key.key_id and p.source == "core-ledger" and p.sequence == 1
    assert p.payload_digest == digest(LEDGER)


@pytest.mark.parametrize(
    "field,value",
    [
        ("subject", "dispute:DSP-2"),
        ("kind", "kyb_record"),
        ("sequence", 99),
        ("issuer", "someone-else"),
        ("expires_at", "2099-01-01T00:00:00Z"),
        ("issued_at", "2020-01-01T00:00:00Z"),
        ("effective_at", "2020-01-01T00:00:00Z"),
    ],
)
def test_changing_any_signed_header_field_breaks_the_statement(field, value):
    env = _signed()
    env[field] = value
    p = _verify(env, subject=None, kind=KIND)
    assert p.status is ProvenanceStatus.INVALID, (field, p.reason)


def test_an_altered_payload_is_invalid_even_with_a_recomputed_digest():
    env = _signed()
    env["payload"] = {**LEDGER, "delivery_status": "delivered"}
    assert "altered" in _verify(env).reason
    env["payload_sha256"] = digest(
        env["payload"]
    )  # the digest is signed; this breaks the signature
    assert _verify(env).status is ProvenanceStatus.INVALID


def test_a_statement_about_another_record_cannot_be_reused():
    p = _verify(_signed(record_id="DSP-1"), subject="dispute:DSP-2")
    assert p.status is ProvenanceStatus.INVALID and "signed for dispute:DSP-1" in p.reason
    assert _verify(_signed(), kind=FactKind.KYB_RECORD, subject=None).status is (
        ProvenanceStatus.INVALID
    )


def test_an_attacker_key_is_not_a_trusted_key():
    mallory = Issuer.ephemeral("core-ledger")  # same issuer name, the attacker's own key
    forged = _signed(issuer=mallory)
    assert "unknown signer" in _verify(forged).reason
    forged["key_id"] = ISSUER.key.key_id  # claim the real key's identity
    assert _verify(forged).reason == "the signature does not verify"


def test_a_key_is_bound_to_its_issuer_and_scope():
    other = Issuer.ephemeral("acquirer", scopes=("kyb_record",))
    trust = TRUST.with_key(other.key)
    env = _signed(issuer=other)  # a dispute ledger signed by the acquirer's key
    assert "not trusted to sign dispute_ledger" in _verify(env, trust=trust).reason
    env = _signed(issuer=other)
    env["issuer"] = "core-ledger"
    assert _verify(env, trust=trust).status is ProvenanceStatus.INVALID


def test_revoked_retired_and_expired_keys():
    env = _signed()
    revoked = TrustStore.empty().with_key(
        dataclasses.replace(ISSUER.key, revoked_at=NOW, revocation_reason="compromised")
    )
    p = _verify(env, trust=revoked)
    assert p.status is ProvenanceStatus.REVOKED and "compromised" in p.reason
    # retired (rotated) before the statement was issued: invalid; after: still valid
    before = TrustStore.empty().with_key(
        dataclasses.replace(ISSUER.key, not_after=NOW - timedelta(hours=1))
    )
    assert _verify(env, trust=before).status is ProvenanceStatus.INVALID
    after = TrustStore.empty().with_key(
        dataclasses.replace(ISSUER.key, not_after=NOW + timedelta(hours=1))
    )
    assert _verify(env, trust=after).status is ProvenanceStatus.VERIFIED_EXTERNAL
    assert _verify(env, now=NOW + timedelta(days=31)).status is ProvenanceStatus.EXPIRED


def test_time_is_checked():
    future = _signed(issued_at=NOW + timedelta(hours=1))
    assert _verify(future).reason == "issued in the future"
    long = _signed(validity=timedelta(days=400))  # longer than the key allows (30 days)
    assert "longer than the key allows" in _verify(long).reason


def test_a_replayed_older_statement_is_superseded_and_equivocation_is_invalid():
    seqs = MemorySequences()
    newer = _signed({**LEDGER, "refund_state": "refunded"}, sequence=2)
    seqs.advance("core-ledger", "dispute:DSP-1", 2, envelope_digest(newer))
    assert _verify(_signed(sequence=1), sequences=seqs).status is ProvenanceStatus.SUPERSEDED
    other = _signed({**LEDGER, "amount": 1}, sequence=2)  # same sequence, different statement
    assert "equivocation" in _verify(other, sequences=seqs).reason
    assert _verify(newer, sequences=seqs).status is ProvenanceStatus.VERIFIED_EXTERNAL


def test_signatures_are_domain_separated():
    """A signature over the same header bytes without Sentinel's fact domain prefix (say,
    one a key produced for another protocol) is not a fact signature."""
    env = _signed()
    header = canonical_json({k: env[k] for k in HEADER_FIELDS})
    env["signature"] = crypto.b64e(crypto.sign(ISSUER.private, header))
    assert _verify(env).reason == "the signature does not verify"
    assert crypto.verify(
        ISSUER.key.public_key, crypto.b64d(_signed()["signature"]), DOMAIN + header
    )


@pytest.mark.parametrize(
    "bad",
    [None, [], "x", {}, {"format": "sentinel.fact/1"}, {**{k: 1 for k in HEADER_FIELDS}}],
)
def test_malformed_envelopes_are_invalid(bad):
    assert _verify(bad).status is ProvenanceStatus.INVALID


def test_malformed_signature_encodings_are_invalid():
    env = _signed()
    env["signature"] = env["signature"] + "="  # padded: not the canonical encoding
    assert _verify(env).status is ProvenanceStatus.INVALID
    env["signature"] = "!!!"
    assert _verify(env).status is ProvenanceStatus.INVALID


# ---- INV-PROV-1: fuzzed mutations of a real statement never verify ---------------------------
_JSON = st.recursive(
    st.none() | st.booleans() | st.integers(-(2**60), 2**60) | st.text(max_size=12),
    lambda inner: st.lists(inner, max_size=3)
    | st.dictionaries(st.text(max_size=6), inner, max_size=3),
    max_leaves=8,
)


@settings(max_examples=300, deadline=None)
@given(
    field=st.sampled_from(sorted(set(HEADER_FIELDS) | {"payload", "signature"})),
    value=_JSON,
    path=st.sampled_from(["replace", "payload-key"]),
)
def test_inv_prov_1_no_mutation_of_a_signed_statement_verifies(field, value, path):
    env = _signed()
    original = copy.deepcopy(env)
    if path == "payload-key":
        env["payload"] = {**env["payload"], "delivery_status": value}
    else:
        env[field] = value
    p = _verify(env, subject=None)
    # identity is judged on the JSON, not Python equality: True == 1 in Python, but a
    # boolean where the signer wrote the integer 1 is a different statement (and refused)
    if json.dumps(env, sort_keys=True) == json.dumps(original, sort_keys=True):
        assert p.status is ProvenanceStatus.VERIFIED_EXTERNAL
    else:
        assert p.status is not ProvenanceStatus.VERIFIED_EXTERNAL, (field, value, p.reason)


@settings(max_examples=200, deadline=None)
@given(doc=_JSON)
def test_inv_prov_1_arbitrary_json_never_verifies(doc):
    assert _verify(doc, subject=None).status is not ProvenanceStatus.VERIFIED_EXTERNAL


# ---- the trust store --------------------------------------------------------------------------
def test_a_trust_store_entry_cannot_claim_another_keys_identity():
    doc = TRUST.to_json()
    doc["keys"][0]["key_id"] = "ed25519:" + "0" * 32
    with pytest.raises(TrustStoreError, match="not the fingerprint"):
        TrustStore.from_json(doc)


@pytest.mark.parametrize(
    "change",
    [
        {"purpose": "everything"},
        {"scopes": ["dispute_ledger", "made_up_kind"]},
        {"not_before": "2026-09-29 00:00:00"},
        {"extra": 1},
        {"max_validity_days": 10_000},
    ],
)
def test_a_malformed_trust_store_fails_closed(change):
    doc = TRUST.to_json()
    doc["keys"][0].update(change)
    with pytest.raises(TrustStoreError):
        TrustStore.from_json(doc)


def test_duplicate_keys_are_refused():
    doc = TRUST.to_json()
    doc["keys"].append(doc["keys"][0])
    with pytest.raises(TrustStoreError, match="duplicate"):
        TrustStore.from_json(doc)


# ---- the pipeline: what each way of arriving can establish ------------------------------------
def _run(req):
    return run_dispute(Runtime(persist=False, trust=TRUST), req)


def test_unsigned_facts_never_execute_but_can_still_deny():
    b = _run(DisputeRequest(UntrustedContent(CLAIM), LEDGER, "DSP-1"))
    d = b.decision
    assert d.provenance.status is ProvenanceStatus.UNTRUSTED and not d.executed
    assert d.final_action is FinalAction.REQUIRE_HUMAN_REVIEW
    assert b.reconciliation.verdict is EvidenceVerdict.INSUFFICIENT
    # the record's fields are claims about the records, never verified facts
    assert all(
        e.trust is TrustClass.UNVERIFIED_RECORD and e.status is EvidenceStatus.CLAIMED
        for e in b.reconciliation.evidence
        if e.source == "payment_ledger"
    )
    # ... but unverified facts can make an outcome stricter
    refunded = _run(
        DisputeRequest(UntrustedContent(CLAIM), {**LEDGER, "refund_state": "refunded"}, "DSP-1")
    )
    assert refunded.decision.final_action in (FinalAction.DENY, FinalAction.BLOCK)


def test_the_same_facts_signed_execute():
    b = _run(DisputeRequest(UntrustedContent(CLAIM), {}, "DSP-1", envelope=_signed()))
    assert b.decision.provenance.status is ProvenanceStatus.VERIFIED_EXTERNAL
    assert b.decision.executed and b.reconciliation.verdict is EvidenceVerdict.SUPPORTED
    assert all(
        e.trust is TrustClass.VERIFIED_EXTERNAL and e.status is EvidenceStatus.VERIFIED
        for e in b.reconciliation.evidence
        if e.source == "payment_ledger"
    )


@pytest.mark.parametrize(
    "attack",
    ["forged", "altered", "other_record", "expired", "revoked", "unknown_trust"],
)
def test_inv_prov_1_no_attack_on_the_fact_channel_executes(attack):
    env, trust, now = _signed(), TRUST, NOW
    if attack == "forged":
        env = _signed(issuer=Issuer.ephemeral("core-ledger"))
    elif attack == "altered":
        env["payload"]["refund_state"] = "none"
        env["payload"]["amount"] = 49_000
    elif attack == "other_record":
        env = _signed(record_id="DSP-OTHER")
    elif attack == "revoked":
        trust = TrustStore.empty().with_key(dataclasses.replace(ISSUER.key, revoked_at=NOW))
    elif attack == "unknown_trust":
        trust = TrustStore.empty()
    rt = Runtime(
        persist=False,
        trust=trust,
        clock=lambda: now + timedelta(days=31 if attack == "expired" else 0),
    )
    b = run_dispute(rt, DisputeRequest(UntrustedContent(CLAIM), {}, "DSP-1", envelope=env))
    assert b.decision.provenance.status is not ProvenanceStatus.VERIFIED_EXTERNAL
    assert not b.decision.executed, (attack, b.decision.provenance.reason)


# ---- the application: record store, stored envelopes, the API ---------------------------------
@pytest.fixture()
def app():
    return SentinelApp.demo(seed=7, customers=40, merchants=10, transactions=600)


def _supported_dispute(app):
    """A stored dispute whose signed ledger supports its claim (so it would pay)."""
    for d in app.store.all_disputes():
        b = app.evaluate_dispute(dispute_id=d.dispute_id)
        if b.decision.executed:
            return d, b
    raise AssertionError("no supported dispute in the dataset")


def test_a_record_read_by_id_is_verified_against_its_issuers_statement(app):
    d, b = _supported_dispute(app)
    p = b.decision.provenance
    assert p.status is ProvenanceStatus.VERIFIED_EXTERNAL and p.source == "synthetic-ledger"
    assert b.decision.facts_source == "system_of_record"


def test_a_tampered_record_store_row_is_detected(app):
    d, _ = _supported_dispute(app)
    # a DB-write attacker changes the stored record behind a signed statement
    app.store._conn.execute(
        "UPDATE disputes SET refund_state = 'none', amount = 49000 WHERE dispute_id = ?",
        (d.dispute_id,),
    )
    app.store._conn.commit()
    b = app.evaluate_dispute(dispute_id=d.dispute_id)
    assert b.decision.provenance.status is ProvenanceStatus.INVALID
    assert "differs from the signed statement" in b.decision.provenance.reason
    assert "amount" in b.decision.provenance.reason and not b.decision.executed


def test_without_an_issuer_the_record_store_is_trusted_local(app):
    plain = SentinelApp()  # a store with no signed statements
    plain.load_dataset(app.store.to_dataset())
    d = plain.store.all_disputes()[0]
    p = plain.evaluate_dispute(dispute_id=d.dispute_id).decision.provenance
    assert p.status is ProvenanceStatus.TRUSTED_LOCAL and p.source == "record_store"


def test_a_replayed_older_statement_cannot_pay_a_second_refund(app):
    old = app.issuer.sign(KIND, "DSP-ROLLBACK", LEDGER, sequence=1)
    new = app.issuer.sign(KIND, "DSP-ROLLBACK", {**LEDGER, "refund_state": "refunded"}, sequence=2)
    assert app.evaluate_dispute(CLAIM, envelope=new).decision.final_action is not FinalAction.ALLOW
    b = app.evaluate_dispute(CLAIM, envelope=old)  # the statement from before the refund
    assert b.decision.provenance.status is ProvenanceStatus.SUPERSEDED and not b.decision.executed


def test_inv_audit_1_the_audit_event_identifies_the_facts(app):
    d, b = _supported_dispute(app)
    ev = app.audit_event(b.decision.decision_id)
    facts = ev["detail"]["facts"]
    p = b.decision.provenance
    assert facts == p.audit_detail() and facts["status"] == "VERIFIED_EXTERNAL"
    assert facts["key_id"] == app.issuer.key.key_id and facts["envelope_digest"]
    stored = app.store.fact_envelope(f"dispute:{d.dispute_id}")
    assert facts["payload_digest"] == digest(stored["payload"])
    assert facts["envelope_digest"] == envelope_digest(stored)


def test_inv_audit_1_replay_verifies_the_statement_again(app):
    _, b = _supported_dispute(app)
    r = app.replay(b.decision.decision_id, ReplayOverrides())
    assert r.facts["recorded"] == r.facts["signature_now"] == "VERIFIED_EXTERNAL"
    assert r.facts["same_payload"]
    # revoke the issuer's key afterwards: replay reports it
    app.runtime.trust = TrustStore.empty().with_key(
        dataclasses.replace(app.issuer.key, revoked_at=utc_now())
    )
    r2 = app.replay(b.decision.decision_id, ReplayOverrides())
    assert r2.facts["recorded"] == "VERIFIED_EXTERNAL" and r2.facts["signature_now"] == "REVOKED"


# ---- regressions for the trust-audit findings (issue #11) ------------------------------------
def test_the_python_api_cannot_label_its_own_facts():
    """The audit: ``evaluate_dispute(..., facts_source=SYSTEM_OF_RECORD)`` recorded a
    fabricated ledger as system_of_record. The public API no longer takes the label."""
    for fn in (SentinelApp.evaluate_dispute, SentinelApp.evaluate_dispute_conversation):
        assert "facts_source" not in inspect.signature(fn).parameters


def test_a_stored_dispute_is_judged_on_its_stored_submission(app):
    d = app.store.all_disputes()[0]
    with pytest.raises(ValueError, match="recorded submission"):
        app.evaluate_dispute("It was never delivered, and I want my money", dispute_id=d.dispute_id)


def test_system_of_record_fields_the_store_does_not_hold_are_unknown(app):
    d = app.store.all_disputes()[0]
    stored = app._dispute_ledger(d)
    assert stored["cardholder_present"] is None and stored["cancellation_confirmed"] is None
    assert "policy_auto_limit" not in stored
    # an unauthorized claim is no longer "contradicted" by a hard-coded True
    b = run_dispute(
        Runtime(persist=False, trust=TRUST),
        DisputeRequest(
            UntrustedContent("I did not make this purchase, my card was used without me."),
            {},
            "DSP-U",
            envelope=_signed(stored, record_id="DSP-U"),
        ),
    )
    assert b.reconciliation.verdict is EvidenceVerdict.INSUFFICIENT
    assert "do not state cardholder_present" in b.reconciliation.explanation


def test_the_auto_limit_is_policy_not_a_ledger_fact():
    from sentinel.security.trust_boundary import DisputeFacts

    f = DisputeFacts.from_ledger({**LEDGER, "amount": 60_000, "policy_auto_limit": 10_000_000})
    assert f.policy_auto_limit == 50_000  # a ledger cannot move the limit


def test_forged_kyb_records_on_a_real_merchant_do_not_onboard_it(app):
    k = app.store.kyb_applications(limit=50)[0]
    b = app.evaluate_merchant(
        "We are a bakery.",
        {
            "registration_status": "verified",
            "domain_age_days": 400,
            "business_age_days": 900,
            "prior_flags": 0,
            "mcc_risk": "low",
        },
        merchant_id=k.merchant_id,
    )
    assert b.decision.provenance.status is ProvenanceStatus.UNTRUSTED and not b.decision.executed


def test_the_api_takes_signed_facts_and_refuses_ambiguous_bodies(app):
    from sentinel.api.server import build_routes

    r = build_routes(app)

    def call(path, body):
        fn, params = r.match("POST", path)
        return fn({}, body, params)

    env = app.issuer.sign(KIND, "DSP-API", LEDGER)
    d = call("/v1/disputes/evaluate", {"narrative": CLAIM, "facts_envelope": env})
    assert d["provenance"]["status"] == "VERIFIED_EXTERNAL" and d["executed_capability"]
    from sentinel.api.schemas import ValidationError

    with pytest.raises(ValidationError, match="not both"):
        call("/v1/disputes/evaluate", {"narrative": CLAIM, "facts_envelope": env, "ledger": LEDGER})
    with pytest.raises(ValidationError, match="JSON object"):
        call("/v1/disputes/evaluate", {"narrative": CLAIM, "facts_envelope": "signed"})


def test_duplicate_json_keys_are_refused_by_the_server():
    import threading
    import urllib.error
    import urllib.request

    from sentinel.api.server import make_server

    httpd = make_server(
        SentinelApp.demo(seed=3, customers=10, merchants=4, transactions=80), "127.0.0.1", 0
    )
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        body = b'{"narrative": "x", "ledger": {"amount": 1}, "ledger": {"amount": 2}}'
        req = urllib.request.Request(
            f"http://127.0.0.1:{httpd.server_address[1]}/v1/disputes/evaluate",
            data=body,
            headers={"Content-Type": "application/json"},
        )
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(req)
        assert e.value.code == 400 and "duplicate key" in json.loads(e.value.read())["error"]
    finally:
        httpd.shutdown()


def test_deleting_a_stored_statement_does_not_downgrade_a_tampered_record(app):
    """A DB-write attacker who edits a record AND deletes its signed statement must not get
    TRUSTED_LOCAL facts: the deployment requires signed records (configuration, not data)."""
    d, _ = _supported_dispute(app)
    app.store._conn.execute(
        "UPDATE disputes SET amount = 49000 WHERE dispute_id = ?", (d.dispute_id,)
    )
    app.store._conn.execute(
        "DELETE FROM fact_envelopes WHERE record_key = ?", (f"dispute:{d.dispute_id}",)
    )
    app.store._conn.commit()
    b = app.evaluate_dispute(dispute_id=d.dispute_id)
    assert b.decision.provenance.status is ProvenanceStatus.INVALID
    assert "requires one" in b.decision.provenance.reason and not b.decision.executed


@pytest.mark.parametrize(
    "subject", ["dispute:", "dispute:" + "x" * 65, "dispute:a/b", "DISPUTE:X", "dispute:x y"]
)
def test_malformed_subjects_are_invalid(subject):
    env = ISSUER.sign(KIND, "ok", LEDGER)
    env["subject"] = subject
    assert _verify(env, subject=None).status is ProvenanceStatus.INVALID


# ---- regressions: the adversarial review of the first draft (#11) -------------------------
def test_f1_a_stored_dispute_cannot_be_re_pointed_with_its_own_statement(app):
    d = app.store.all_disputes()[0]
    own = app.store.fact_envelope(f"dispute:{d.dispute_id}")
    for kw in ({"envelope": own}, {"envelope": own, "dispute_id": d.dispute_id}):
        with pytest.raises(ValueError, match="evaluate it by id"):
            app.evaluate_dispute("It never arrived.", **kw)
    with pytest.raises(ValueError, match="evaluate it by id"):
        app.evaluate_dispute("It never arrived.", LEDGER, dispute_id=d.dispute_id)


def test_g1_the_conversation_route_does_not_re_point_a_stored_dispute_either(app):
    """The review of #12 found the conversation route took a stored dispute's own signed
    statement with new text: by id DSP-000042 (seed 2) went to review; through the
    conversation it executed APPROVE_REFUND with the account's risk dropped."""
    for d in app.store.all_disputes()[:25]:
        own = app.store.fact_envelope(f"dispute:{d.dispute_id}")
        assert own is not None
        with pytest.raises(ValueError, match="evaluate it by id"):
            app.evaluate_dispute_conversation(("Hello,", "it never arrived."), envelope=own)
    assert not any(e.kind == "decision" for e in app.runtime.audit.events())


def test_f2_deleting_the_rollback_marks_does_not_reopen_an_older_statement(app):
    old = app.issuer.sign(KIND, "DSP-ROLL", LEDGER, sequence=1)
    new = app.issuer.sign(KIND, "DSP-ROLL", {**LEDGER, "refund_state": "refunded"}, sequence=2)
    app.evaluate_dispute(CLAIM, envelope=new)  # acted on: the refund was already paid
    app.store._conn.execute("DELETE FROM fact_sequences")  # a DB writer erases the marks
    app.store._conn.commit()
    b = app.evaluate_dispute(CLAIM, envelope=old)
    assert b.decision.provenance.status is ProvenanceStatus.SUPERSEDED  # the chain remembers
    assert not b.decision.executed


def test_f2_one_applications_statement_cannot_stand_in_for_another():
    app = SentinelApp.demo(seed=42, customers=60, merchants=12, transactions=900)
    by_merchant: dict[str, list[str]] = {}
    for k in app.store.kyb_applications(limit=1000):
        by_merchant.setdefault(k.merchant_id, []).append(k.application_id)
    a1, a2 = next(v for v in by_merchant.values() if len(v) > 1)[:2]
    other = app.store.fact_envelope(f"application:{a1}")
    app.store.save_fact_envelopes([(f"application:{a2}", other)])  # a DB writer swaps them
    b = app.evaluate_merchant("", application_id=a2)
    assert b.decision.provenance.status is ProvenanceStatus.INVALID
    assert "application_id" in b.decision.provenance.reason and not b.decision.executed


def test_f3_an_oversized_integer_fails_safe_and_leaves_no_orphan_audit_event(app):
    env = app.issuer.sign(KIND, "DSP-BIG", LEDGER)
    env["payload"] = {**env["payload"], "amount": 2**64}
    n_audit, n_dec = len(app.runtime.audit), app.store.count("decisions")
    b = app.evaluate_dispute(CLAIM, envelope=env)
    assert b.decision.provenance.status is ProvenanceStatus.INVALID and not b.decision.executed
    # a failed statement is a tamper signal: the policy's BLOCK is decisive (DENY, no case),
    # not a fail-safe review that nobody may ever approve
    assert b.decision.final_action is FinalAction.DENY and b.case is None
    assert "block-failed-fact-provenance" in b.decision.policy.matched_rules
    assert len(app.runtime.audit) == n_audit + 1 and app.store.count("decisions") == n_dec + 1
    body = app.evaluate_dispute(CLAIM, {**LEDGER, "amount": 2**64})  # the unsigned route too
    assert not body.decision.executed and app.verify_audit().ok


def test_f4_the_audit_names_the_record_the_decision_actually_used(app):
    t = app.store.transactions(limit=1)[0]
    app.store._conn.execute(
        "UPDATE transactions SET amount = 999999 WHERE transaction_id = ?", (t.transaction_id,)
    )
    app.store._conn.commit()
    from sentinel.decision.workflows import transaction_record
    from sentinel.trust import record_digest

    b = app.evaluate_transaction(t.transaction_id)
    used = app.store.transaction(t.transaction_id)
    assert b.decision.provenance.status is ProvenanceStatus.INVALID
    assert b.decision.provenance.payload_digest == record_digest(transaction_record(used))


def test_f5_an_incomplete_statement_is_not_completed_by_defaults(app):
    partial = {k: v for k, v in LEDGER.items() if k != "refund_state"}
    b = app.evaluate_dispute(CLAIM, envelope=app.issuer.sign(KIND, "DSP-PART", partial))
    assert b.decision.provenance.status is ProvenanceStatus.INVALID
    assert "omits ['refund_state']" in b.decision.provenance.reason and not b.decision.executed


def test_f6_replay_reports_a_signature_check_and_withholds_it_on_an_edited_record(app):
    d, b = _supported_dispute(app)
    r = app.replay(b.decision.decision_id, ReplayOverrides())
    assert r.facts["signature_now"] == "VERIFIED_EXTERNAL" and "reverified" not in r.facts
    snap = app.store.decision_snapshot(b.decision.decision_id)
    snap["provenance"]["status"] = "INVALID"  # the stored snapshot edited
    app.store._conn.execute(
        "UPDATE decisions SET snapshot = ? WHERE decision_id = ?",
        (json.dumps(snap), b.decision.decision_id),
    )
    app.store._conn.commit()
    r2 = app.replay(b.decision.decision_id, ReplayOverrides())
    assert not r2.record_verified and r2.facts["signature_now"] is None
    assert r2.facts["recorded"] == "VERIFIED_EXTERNAL"  # from the audit event, not the snapshot


def test_f8_an_oversized_json_integer_is_a_400_not_a_dropped_connection():
    import threading
    import urllib.error
    import urllib.request

    from sentinel.api.server import make_server

    httpd = make_server(
        SentinelApp.demo(seed=3, customers=10, merchants=4, transactions=80), "127.0.0.1", 0
    )
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        body = b'{"narrative": "x", "ledger": {"amount": ' + b"9" * 5000 + b"}}"
        req = urllib.request.Request(
            f"http://127.0.0.1:{httpd.server_address[1]}/v1/disputes/evaluate",
            data=body,
            headers={"Content-Type": "application/json"},
        )
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(req)
        assert e.value.code == 400
    finally:
        httpd.shutdown()


def test_a_trailing_newline_never_satisfies_a_grammar():
    """``$`` in a Python pattern also matches before a final newline, so ``^id$`` with
    ``match`` accepted ``"DSP-1\\n"`` (found by the review of #15). Every grammar is a full
    match: a subject, a timestamp, an issuer, a route."""
    from sentinel.api.server import Router
    from sentinel.trust.keys import parse_ts

    env = _signed(record_id="DSP-1\n")
    prov = _verify(env, subject=None)
    assert prov.status is ProvenanceStatus.INVALID and "malformed subject" in prov.reason
    with pytest.raises(ValueError):
        parse_ts("2026-01-01T00:00:00Z\n", "issued_at")
    doc = TRUST.to_json()
    doc["keys"][0]["issuer"] += "\n"
    with pytest.raises(TrustStoreError):
        TrustStore.from_json(doc)
    router = Router()
    router.add("GET", "/v1/system", lambda: None)
    assert router.match("GET", "/v1/system") is not None
    assert router.match("GET", "/v1/system\n") is None


def test_a_kyb_statement_must_name_its_application():
    """Found by the release audit: the statement fields did not require ``application_id``,
    so an issuer-signed KYB payload naming no application verified, and onboarded a
    merchant against any application text. It is now INVALID, as is a non-string id."""
    app = SentinelApp.demo(seed=42, customers=60, merchants=12, transactions=900)
    clean = {
        "registration_status": "verified",
        "domain_age_days": 900,
        "business_age_days": 1600,
        "prior_flags": 0,
        "mcc_risk": "low",
    }
    for i, payload in enumerate((clean, {**clean, "application_id": 7})):
        env = app.issuer.sign(FactKind.KYB_RECORD, f"MER-AUD-{i}", payload)
        b = app.evaluate_merchant("We sell books online.", envelope=env)
        assert b.decision.provenance.status is ProvenanceStatus.INVALID, payload
        assert not b.decision.executed
    env = app.issuer.sign(
        FactKind.KYB_RECORD, "MER-AUD-9", {**clean, "application_id": "APP-AUD-9"}
    )
    ok = app.evaluate_merchant("We sell books online.", envelope=env)
    assert ok.decision.provenance.status is ProvenanceStatus.VERIFIED_EXTERNAL


def test_the_submission_alias_is_not_dropped_on_the_stored_dispute_route():
    """Found by the release audit: by id, a different ``narrative`` was refused but a
    different ``submission`` (its alias) was silently ignored."""
    from sentinel.api.server import build_routes

    app = SentinelApp.demo(seed=7, customers=40, merchants=10, transactions=600)
    fn, params = build_routes(app).match("POST", "/v1/disputes/evaluate")
    d = app.store.all_disputes()[0]
    with pytest.raises(ValueError, match="recorded"):
        fn({}, {"dispute_id": d.dispute_id, "submission": "totally different text"}, params)
    assert fn({}, {"dispute_id": d.dispute_id}, params)["subject_id"] == d.dispute_id
