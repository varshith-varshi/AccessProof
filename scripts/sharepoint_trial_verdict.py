"""Synthetic SharePoint lab's explicit positive and negative permission oracle.

Only applies to the dedicated, operator-approved three-file validation site.
It cannot issue a production Protect certificate or replace employee OIDC.
"""
from __future__ import annotations

EXPECTED_ACCESS: dict[tuple[str, int], bool] = {
    ("alice", 2): True,     # finance_alice.txt
    ("alice", 3): False,    # engineering_bob.txt
    ("alice", 4): True,     # shared_control.txt
    ("bob", 2): False,
    ("bob", 3): True,
    ("bob", 4): True,
}


def validate_synthetic_access(
    observations: dict[tuple[str, int], bool],
) -> list[str]:
    """Return machine-readable safety findings (no personal data)."""
    if not isinstance(observations, dict):
        return ["SYNTHETIC_ACCESS_OBSERVATIONS_INVALID"]
    actual_keys = set(observations)
    if actual_keys != set(EXPECTED_ACCESS):
        return ["SYNTHETIC_ACCESS_MATRIX_INCOMPLETE_OR_OUT_OF_SCOPE"]
    problems: list[str] = []
    for (employee, item_id), expected in EXPECTED_ACCESS.items():
        observed = observations[(employee, item_id)]
        if type(observed) is not bool:
            problems.append(f"SYNTHETIC_ACCESS_NOT_BOOLEAN_{employee}_{item_id}")
        elif observed != expected:
            problems.append(f"SYNTHETIC_ACCESS_MISMATCH_{employee}_{item_id}")
    return problems
