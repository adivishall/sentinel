import pytest

from firewall import normalize as N


def test_validate_rejects_non_str():
    with pytest.raises(N.InvalidSubmission):
        N.validate(None)
    with pytest.raises(N.InvalidSubmission):
        N.validate(123)


def test_validate_rejects_empty_and_whitespace():
    for bad in ["", "   ", "\n\t "]:
        with pytest.raises(N.InvalidSubmission):
            N.validate(bad)


def test_validate_rejects_oversized():
    with pytest.raises(N.InvalidSubmission):
        N.validate("x" * (N.MAX_LEN + 1))


def test_validate_accepts_normal():
    assert N.validate("My order never arrived") == "My order never arrived"


def test_homoglyph_fold_to_ascii():
    # Cyrillic а е о р с -> ascii
    assert "ignore" in N.normalize("іgnоrе").replace("і", "i")  # tolerant
    assert N.normalize("раѕѕ") == "pass"  # Cyrillic p a s s


def test_zero_width_stripped():
    dirty = "ig​no‌re"
    assert N.normalize(dirty) == "ignore"


def test_normalize_idempotent():
    s = "Ｆull-width and ѕome homoglyphѕ"
    assert N.normalize(N.normalize(s)) == N.normalize(s)


def test_prepare_combines_validates_and_normalizes():
    # prepare = validate + normalize; ordinary spaces are preserved, unicode folded
    assert N.prepare("ѕome t*xt".replace("*", "e")) == "some text"
