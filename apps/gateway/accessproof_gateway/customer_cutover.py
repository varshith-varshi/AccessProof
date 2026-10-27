"""Explicitly authorized reference Docker customer-RAG cutover.

Runs ONLY from the customer-controlled host. A failed post-cutover challenge
stops the changed RAG service instead of silently returning traffic to an
unprotected model. Never edits Compose source, deploys to production by itself
or claims to certify arbitrary/custom RAG routes.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path
from typing import Any

import httpx

from apps.guard.accessproof_guard.onboarding import validate_control_plane_url

from .challenge_cli import read_private_json, write_private_result
from .customer_agent import (
    CustomerAgentError, _docker_compose_json, verify_deployment_contract,
)
from .cutover_agent import EmployeeRouteProbe, probe_customer_employee_route
from .installer import InstallationSpec


def _compose_service_args(installation: dict[str, Any]) -> list[str]:
    origin = installation.get("customer_compose")
    override = installation.get("override")
    if not isinstance(origin, str) or not isinstance(override, str):
        raise CustomerAgentError("Invalid customer installation file references")
    if not Path(origin).is_file() or not Path(override).is_file():
        raise CustomerAgentError("Customer Compose files no longer exist")
    return ["docker", "compose", "-f", origin, "-f", override]


def _docker(args: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=True, timeout=timeout,
                          capture_output=True, text=True)


def _local_gateway_ready(spec: InstallationSpec, client: httpx.Client | None = None) -> bool:
    url = f"http://127.0.0.1:{spec.listen_port}/health/ready"
    own = client is None
    http = client or httpx.Client(timeout=5, follow_redirects=False, trust_env=False)
    try:
        response = http.get(url)
        return response.status_code == 200
    except httpx.HTTPError:
        return False
    finally:
        if own:
            http.close()


def _machine_headers(machine: dict[str, Any]) -> tuple[str, str, dict[str, str]]:
    guard_id = machine.get("guard_id")
    token = machine.get("credential")
    server = machine.get("control_plane_url")
    if (not isinstance(guard_id, str) or not guard_id
            or not isinstance(token, str) or not token
            or not isinstance(server, str) or not server):
        raise CustomerAgentError("Enrolled Guard machine credentials are required")
    return validate_control_plane_url(server), guard_id, {
        "Authorization": f"Bearer {token}",
    }


def _previous_reference_test(
    *, challenge: dict[str, Any], installation: dict[str, Any],
    machine: dict[str, Any], client: httpx.Client,
) -> None:
    server, guard_id, headers = _machine_headers(machine)
    challenge_id = challenge.get("challenge_id")
    if not isinstance(challenge_id, str) or not challenge_id:
        raise CustomerAgentError("The enrolled Guard challenge identifier is missing")
    response = client.get(
        f"{server}/api/v1/guards/{guard_id}/rag-challenges/{challenge_id}",
        headers=headers, follow_redirects=False,
    )
    response.raise_for_status()
    data = response.json()
    if (data.get("state") != "tested"
            or data.get("guard_id") != guard_id
            or data.get("application_id") != installation.get("application_id")
            or data.get("deployment_sha256") != installation.get("deployment_sha256")
            or data.get("route_sha256") != installation.get("route_sha256")):
        raise CustomerAgentError("Control plane has not verified this exact reference installation")


def verify_and_submit_customer_cutover(
    *, installation: dict[str, Any], spec: InstallationSpec,
    challenge: dict[str, Any], machine: dict[str, Any],
    probe: EmployeeRouteProbe, resolved_compose: dict[str, Any],
    control_client: httpx.Client | None = None,
    rag_client: httpx.Client | None = None,
    attempts: int = 4,
) -> dict[str, Any]:
    """Submit only real employee-facing allow and deny response observations."""
    verify_deployment_contract(
        installation=installation, spec=spec, resolved_compose=resolved_compose,
    )
    own = control_client is None
    http = control_client or httpx.Client(timeout=15, follow_redirects=False, trust_env=False)
    try:
        _previous_reference_test(
            challenge=challenge, installation=installation,
            machine=machine, client=http,
        )
        evidence = probe_customer_employee_route(
            installation=installation, spec=spec,
            resolved_compose=resolved_compose,
            nonce=challenge["challenge_nonce"], probe=probe, client=rag_client,
        )
        server, guard_id, headers = _machine_headers(machine)
        endpoint = (
            f"{server}/api/v1/guards/{guard_id}/rag-challenges/"
            f"{challenge['challenge_id']}/cutover"
        )
        receipt = {
            "challenge_id": challenge["challenge_id"],
            "guard_id": guard_id, "nonce": challenge["challenge_nonce"],
            "deployment_sha256": installation["deployment_sha256"],
            "route_sha256": installation["route_sha256"],
            **evidence,
        }
        # The Guard asynchronously uploads decision audits. Retry transient
        # "audit not yet delivered" only; never retry mismatched/bypass proof.
        for attempt in range(attempts):
            result = http.post(endpoint, headers=headers, json=receipt)
            if result.status_code == 202:
                body = result.json()
                if (body.get("state") != "customer_cutover_verified"
                        or not isinstance(body.get("guard_audits_matched"), int)
                        or body["guard_audits_matched"] < 2):
                    raise CustomerAgentError("Control plane returned an invalid customer cutover result")
                return {
                    "state": "CUSTOMER_CUTOVER_VERIFIED",
                    "employee_route_allow_deny": evidence,
                    "control_plane": body,
                    "production_certification": False,
                }
            if result.status_code == 409 and attempt + 1 < attempts:
                try:
                    error = result.json().get("detail")
                except ValueError:
                    error = None
                if error in {
                    "CUSTOMER_CUTOVER_GUARD_AUDIT_MISMATCH",
                    "CUSTOMER_CUTOVER_DENIED_USER_NOT_GUARD_AUDITED",
                }:
                    time.sleep(1)
                    continue
            raise CustomerAgentError("Control plane refused customer cutover security evidence")
        raise CustomerAgentError("Guard audit upload did not complete")
    finally:
        if own:
            http.close()


def approved_docker_cutover(
    *, installation: dict[str, Any], spec: InstallationSpec,
    challenge: dict[str, Any], machine: dict[str, Any],
    probe: EmployeeRouteProbe, approve: bool,
) -> dict[str, Any]:
    """Change one customer-owned RAG service, only with an explicit CLI flag."""
    if not approve:
        raise CustomerAgentError("Explicit --approve-route-cutover is required")
    compose = _compose_service_args(installation)
    resolved = _docker_compose_json(installation["customer_compose"], installation["override"])
    verify_deployment_contract(
        installation=installation, spec=spec, resolved_compose=resolved,
    )
    if not _local_gateway_ready(spec):
        raise CustomerAgentError("Gateway and enrolled Guard are not ready; RAG route was not changed")
    server, guard_id, headers = _machine_headers(machine)
    with httpx.Client(timeout=15, follow_redirects=False, trust_env=False) as control:
        _previous_reference_test(
            challenge=challenge, installation=installation,
            machine=machine, client=control,
        )
        # The customer must explicitly authorize this service restart. Do
        # not rebuild, start dependencies, stop other services, or alter files.
        rag_changed = False
        try:
            rag_changed = True
            _docker([*compose, "up", "-d", "--no-deps", "--no-build", spec.rag_service])
            # A live positive+negative RAG probe validates post-cutover routing.
            # If either fails, stop only this RAG service (fail-closed).
            result = verify_and_submit_customer_cutover(
                installation=installation, spec=spec, challenge=challenge,
                machine=machine, probe=probe, resolved_compose=resolved,
                control_client=control,
            )
            if not _local_gateway_ready(spec):
                raise CustomerAgentError("Guard readiness disappeared after customer cutover")
            return result
        except (CustomerAgentError, httpx.HTTPError, subprocess.CalledProcessError,
                subprocess.TimeoutExpired, OSError, ValueError):
            if rag_changed:
                try:
                    _docker([*compose, "stop", "-t", "10", spec.rag_service], timeout=30)
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
                    raise CustomerAgentError(
                        "CUTOVER_VERIFICATION_FAILED_AND_RAG_STOP_NOT_CONFIRMED"
                    ) from None
            raise CustomerAgentError("CUTOVER_FAILED_RAG_STOPPED_FAIL_CLOSED") from None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Owner-approved, customer-side, reference RAG Protect route cutover.",
    )
    parser.add_argument("--installation", required=True, type=Path)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--challenge", required=True, type=Path)
    parser.add_argument("--guard-credentials", required=True, type=Path)
    parser.add_argument("--employee-route-probe", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--approve-route-cutover", action="store_true",
                        help="Explicitly approve restarting ONLY the selected customer RAG")
    args = parser.parse_args()
    try:
        installation = read_private_json(args.installation)
        spec = InstallationSpec.parse(read_private_json(args.spec))
        challenge = read_private_json(args.challenge)
        machine = read_private_json(args.guard_credentials)
        probe = EmployeeRouteProbe.parse(read_private_json(args.employee_route_probe))
        receipt = approved_docker_cutover(
            installation=installation, spec=spec, challenge=challenge,
            machine=machine, probe=probe, approve=args.approve_route_cutover,
        )
        write_private_result(args.output, receipt)
        print(json.dumps({
            "state": "CUSTOMER_CUTOVER_VERIFIED",
            "production_certification": False, "output": str(args.output),
            "next": "Confirm remaining Guard/source checks and enrolled Guard Protect acknowledgment.",
        }))
        return 0
    except (CustomerAgentError, ValueError, OSError, KeyError, httpx.HTTPError,
            subprocess.CalledProcessError, subprocess.TimeoutExpired):
        print("CUTOVER_FAILED: Inspect restricted logs and verify the customer RAG is safely stopped.")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
