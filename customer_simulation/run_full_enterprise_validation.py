"""Repeatable, LOCAL-ONLY AccessProof enterprise customer regression runner.

Run from the repository root:
    .venv/bin/python -m customer_simulation.run_full_enterprise_validation

Executed pytest selections are real integration tests, not the 150-entry
scenario *catalogue*. Never point this runner at live infrastructure.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "customer_simulation" / "evidence" / "executed-20261022"
PYTEST = [
    str(ROOT / ".venv" / "bin" / "python"), "-m", "pytest",
    "-p", "pytest_asyncio.plugin", "-o", "addopts=", "-q",
]

CHECKS = [
    ("three_customer_http_journeys", [
        "tests/integration/test_customer_lifecycle_over_http.py",
        "tests/integration/test_synthetic_customer_http_boundary.py",
    ]),
    ("provider_contract_and_chaos", [
        "tests/security/test_connector_recovery_ownership.py",
        "tests/security/test_twin_drive_provider_chaos.py",
        "tests/security/test_twin_directory_provider_chaos.py",
        "tests/security/test_microsoft_graph_source_boundary.py",
        "tests/security/test_microsoft_acl_lifecycle.py",
        "tests/security/test_microsoft_reconcile_moved_out.py",
        "tests/security/test_microsoft_remote_item_boundary.py",
    ]),
    ("identity_revoke_isolation", [
        "tests/unit/test_guard_oidc.py",
        "tests/security/test_directory_lifecycle_fail_closed.py",
        "tests/security/test_adversarial_equal_revision_replay.py",
        "tests/security/test_policy_ordering.py",
        "tests/security/test_cross_source_context_binding.py",
        "tests/security/test_tenant_isolation.py",
    ]),
    ("gateway_source_integrity_and_release", [
        "tests/security/test_gateway_adversarial_contract.py",
        "tests/security/test_gateway_guard_failures.py",
        "tests/security/test_gateway_scoped_readiness.py",
        "tests/security/test_gateway_upstream_transport.py",
        "tests/security/test_adversarial_guard_duplicate_grants.py",
        "tests/security/test_source_content_attestation.py",
        "tests/unit/test_gateway_authorization_core.py",
        "tests/unit/test_gateway_only_release_contract.py",
        "tests/unit/test_gateway_network_boundary.py",
        "tests/unit/test_layer2_late_sources.py",
    ]),
    ("source_attestation_sse_and_route_observer", [
        "tests/security/test_source_content_attestation.py",
        "tests/unit/test_local_customer_route_probe.py",
        "tests/integration/test_synthetic_customer_http_boundary.py",
    ]),
    ("activation_certification", [
        "tests/integration/test_automatic_protection_preflight.py",
        "tests/security/test_source_effective_certification.py",
        "tests/integration/test_microsoft_shadow_release_gate.py",
    ]),
    ("ten_thousand_policy_records_and_load", [
        "tests/load/test_twin_large_policy_cache.py",
    ]),
    ("complete_python_regression", ["tests/"]),
]


def _count(pattern: str, body: str) -> int:
    found = re.findall(pattern, body)
    return int(found[-1]) if found else 0


def main() -> int:
    if Path.cwd().resolve() != ROOT:
        raise SystemExit("ERROR: run only from the AccessProof repository root")
    if os.getenv("ACCESSPROOF_ENV", "").lower() == "production":
        raise SystemExit("ERROR: refusing to execute in production mode")
    for name in ("DATABASE_URL", "ACCESSPROOF_CURRENT_DATABASE_URL"):
        value = os.getenv(name, "").lower()
        if value and ("accessproof.in" in value or "13.48.3.158" in value):
            raise SystemExit(f"ERROR: {name} points to a known production host")
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.pop("DATABASE_URL", None)
    env.pop("ACCESSPROOF_CURRENT_DATABASE_URL", None)
    env.pop("PYTHONPATH", None)
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    env["ACCESSPROOF_ENV"] = "development"
    env["TMPDIR"] = "/dev/shm" if Path("/dev/shm").exists() else "/tmp"
    data: dict[str, object] = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "environment": "local_disposable_sqlite_plus_mock_provider_http",
        "production_contacted": False,
        "customer_data_used": False,
        "scenario_catalogue_individually_executed": False,
        "three_customer_journey_source": "google-drive-synthetic-only",
        "supported_customer_rag_integration": ["accessproof-gateway"],
        "public_rag_sdk_available": False,
        "stages": [],
        "external_provider_checks": "BLOCKED",
        "customer_protect_certification": "BLOCKED",
        "known_provenance_integrity_gap": "UNRESOLVED_STRICT_XFAIL",
    }
    # Prevent false "validation failed" results caused by removed SDK tests
    # or an accidental typo in a stage definition. Fail before any evidence
    # is written if this local runner refers to nonexistent test modules.
    missing_test_paths = [
        test_path
        for _, test_paths in CHECKS
        for test_path in test_paths
        if not (ROOT / test_path).exists()
    ]
    if missing_test_paths:
        raise RuntimeError(
            "VALIDATION_TEST_SELECTION_STALE: " + ", ".join(missing_test_paths)
        )
    result_rows: list[dict[str, object]] = []
    failed = False
    for title, paths in CHECKS:
        command = PYTEST + paths
        try:
            proc = subprocess.run(command, cwd=ROOT, env=env,
                                  capture_output=True, text=True, timeout=300, check=False)
            output = proc.stdout + "\n" + proc.stderr
            exit_code = proc.returncode
            status = "PASS" if exit_code == 0 else "FAIL"
        except subprocess.TimeoutExpired as exc:
            output = f"Timed out: {exc}\n"
            exit_code = 124
            status = "FAIL"
        (EVIDENCE / f"{title}.log").write_text(output, encoding="utf-8")
        row: dict[str, object] = {
            "name": title,
            "status": status,
            "exit_code": exit_code,
            "passed": _count(r"(\d+) passed", output),
            "failed": _count(r"(\d+) failed", output),
            "expected_failures": _count(r"(\d+) xfailed", output),
            "skipped": _count(r"(\d+) skipped", output),
            "log": f"customer_simulation/evidence/executed-20261022/{title}.log",
        }
        result_rows.append(row)
        print(f"{title}: {status}, {row['passed']} passed, {row['failed']} failed, "
              f"{row['expected_failures']} known XFAIL", flush=True)
        failed = failed or exit_code != 0
    data["stages"] = result_rows
    data["global_verdict"] = "FAILED_LOCAL_GATES" if failed else "LOCAL_SYNTHETIC_ONLY_NOT_CUSTOMER_PROTECT"
    output_path = EVIDENCE / "test_results.json"
    output_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    # Keep the lightweight summary honest after a real execution. The scenario
    # matrix remains a catalogue rather than an assertion that every row ran.
    # Only the independently exercised HTTP journeys are counted here.
    summary_path = ROOT / "customer_simulation" / "evidence" / "latest-summary.json"
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        summary = {}
    journey = next((row for row in result_rows if row["name"] == "three_customer_http_journeys"), {})
    summary.update({
        "last_validation_at_utc": data["created_at_utc"],
        "locally_executed_end_to_end": int(journey.get("passed", 0)),
        "local_validation_status": "FAILED" if failed else "PASS",
        "scenario_catalogue_individually_executed": False,
        "external_sandbox_required": 26,
    })
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print("Evidence:", output_path)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
