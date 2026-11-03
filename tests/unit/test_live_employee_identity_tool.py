"""Offline checks for scripts/live/employee_identity.py (no Microsoft calls)."""
import importlib.util
from pathlib import Path

import httpx
import pytest

spec = importlib.util.spec_from_file_location("employee_identity", Path(__file__).resolve().parents[2] / "scripts/live/employee_identity.py")
ei = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ei)


@pytest.mark.parametrize("status,location,expected", [
    (200, None, "ALLOW"), (302, "https://neuralmatrix093.sharepoint.com/x", "ALLOW"),
    (302, "https://evil.example/x", "AMBIGUOUS"), (403, None, "DENY"), (404, None, "DENY"),
    (401, None, "AMBIGUOUS"), (500, None, "AMBIGUOUS"),
])
def test_delegated_decision_maps_sharepoint_answers(status, location, expected):
    def handler(request):
        assert request.headers["Authorization"] == "Bearer user-token"
        return httpx.Response(status, headers={"location": location} if location else {})
    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        assert ei.delegated_decision(http, "drive", "item", "user-token")[0] == expected


def test_expected_matrix_is_the_certified_fixture():
    assert ei.EXPECTED["alice"] == {"finance_alice.txt": "ALLOW", "engineering_bob.txt": "DENY", "shared_control.txt": "ALLOW"}
    assert ei.EXPECTED["bob"] == {"finance_alice.txt": "DENY", "engineering_bob.txt": "ALLOW", "shared_control.txt": "ALLOW"}


def test_summary_never_contains_raw_subject():
    s = ei._summary({"sub": "pairwise-secret-sub", "oid": "o", "tid": "t", "iss": "i", "aud": "a"})
    assert "pairwise-secret-sub" not in str(s) and len(s["sub_sha256"]) == 64
