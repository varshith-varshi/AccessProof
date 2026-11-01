"""Production-invalid synthetic lab permission checks fail closed."""
import pytest

from scripts.sharepoint_trial_verdict import EXPECTED_ACCESS, validate_synthetic_access


def test_exact_expected_alice_bob_allow_and_negative_controls():
    assert validate_synthetic_access(dict(EXPECTED_ACCESS)) == []


@pytest.mark.parametrize("key", list(EXPECTED_ACCESS))
def test_every_mismatch_blocks_acceptance(key):
    data = dict(EXPECTED_ACCESS)
    data[key] = not data[key]
    failures = validate_synthetic_access(data)
    assert len(failures) == 1
    assert failures[0].startswith("SYNTHETIC_ACCESS_MISMATCH_")


@pytest.mark.parametrize("key", list(EXPECTED_ACCESS))
def test_missing_evidence_blocks_acceptance(key):
    data = dict(EXPECTED_ACCESS)
    data.pop(key)
    assert validate_synthetic_access(data) == [
        "SYNTHETIC_ACCESS_MATRIX_INCOMPLETE_OR_OUT_OF_SCOPE"
    ]


def test_extra_user_or_document_blocks_acceptance():
    data = dict(EXPECTED_ACCESS)
    data[("charlie", 2)] = True
    assert validate_synthetic_access(data) == [
        "SYNTHETIC_ACCESS_MATRIX_INCOMPLETE_OR_OUT_OF_SCOPE"
    ]


def test_ambiguous_permission_value_fails_closed():
    data = dict(EXPECTED_ACCESS)
    data[("bob", 2)] = 0
    assert validate_synthetic_access(data) == ["SYNTHETIC_ACCESS_NOT_BOOLEAN_bob_2"]
