"""Scenario profiles: deterministic by seed, comparable across profiles."""

from sentinel.data.generator import PROFILES, generate


def _counts(ds):
    from collections import Counter

    return Counter(s.scenario for s in ds.scenarios), Counter(t.label for t in ds.transactions)


def test_profiles_change_only_the_scenario_mix():
    base = generate(42, 80, 16, 1200, profile="balanced")
    heavy = generate(42, 80, 16, 1200, profile="fraud-heavy")
    attack = generate(42, 80, 16, 1200, profile="attack-heavy")
    quiet = generate(42, 80, 16, 1200, profile="quiet")
    sb, _ = _counts(base)
    sh, _ = _counts(heavy)
    sa, _ = _counts(attack)
    sq, _ = _counts(quiet)
    assert sh["account_takeover"] > sb["account_takeover"] and sh["graph_linked_fraud"] == 2
    assert len([d for d in attack.disputes if d.label == "fraud:ai_manipulation"]) > len(
        [d for d in base.disputes if d.label == "fraud:ai_manipulation"]
    )
    assert sum(1 for k in attack.kyb_applications if k.label == "attack:document_borne") > sum(
        1 for k in base.kyb_applications if k.label == "attack:document_borne"
    )
    assert sq["graph_linked_fraud"] == 0 and sq["account_takeover"] == 1
    # the underlying world (customers, merchants) is the same across profiles
    assert [c.customer_id for c in base.customers[:80]] == [
        c.customer_id for c in heavy.customers[:80]
    ]
    assert [m.merchant_id for m in base.merchants] == [m.merchant_id for m in heavy.merchants]
    assert base.profile == "balanced" and heavy.profile == "fraud-heavy"


def test_profiles_are_deterministic_and_named():
    a = generate(7, 60, 12, 800, profile="fraud-heavy")
    b = generate(7, 60, 12, 800, profile=PROFILES["fraud-heavy"])
    assert a.summary() == b.summary() and a.summary()["profile"] == "fraud-heavy"
    assert set(PROFILES) == {"balanced", "fraud-heavy", "attack-heavy", "quiet"}


def test_multiple_rings_share_distinct_payout_instruments():
    ds = generate(42, 80, 16, 1200, profile="fraud-heavy")
    refs = {i.external_ref for i in ds.instruments if i.external_ref}
    assert len(refs) == 2
    g = ds.graph()
    for ref in refs:
        assert len(g.accounts_sharing_instrument(ref)) == 3
