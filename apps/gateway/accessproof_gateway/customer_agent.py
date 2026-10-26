"""Customer-side reference RAG verifier; local Docker-only supported deployment.

The agent uses the enrolled Guard credential on the customer's machine. It
does not send source content, private signing keys or employee tokens to the
AccessProof control plane. Proof is limited to a formally restricted Compose
reference environment, not arbitrary RAG code.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import time
from pathlib import Path
from typing import Any

import httpx

from apps.guard.accessproof_guard.onboarding import validate_control_plane_url
from .challenge_cli import parse_challenge, read_private_json, write_private_result
from .network_boundary import NetworkBoundaryError, verify_reference_compose_isolation
from .installer import InstallationError, InstallationSpec, validate_reference_service


class CustomerAgentError(ValueError):
    pass


def verify_deployment_contract(
    *, installation: dict[str, Any], spec: InstallationSpec,
    resolved_compose: dict[str, Any],
) -> dict[str, Any]:
    customer = Path(installation.get("customer_compose", ""))
    override = Path(installation.get("override", ""))
    if not customer.is_file() or not override.is_file():
        raise CustomerAgentError("Installer manifests are missing or unreadable")
    expected = hashlib.sha256(
        b"accessproof.gateway.compose/v1\0" + customer.read_bytes()
        + b"\0" + override.read_bytes()
    ).hexdigest()
    if (installation.get("reference_contract") != "accessproof.gateway/v1"
            or installation.get("deployment_sha256") != expected
            or installation.get("application_id") != spec.application_id
            or installation.get("tenant_id") != spec.tenant_id):
        raise CustomerAgentError("Installed deployment has changed since operator approval")
    route_environment = validate_reference_service(
        spec, {"services": {k: v for k, v in resolved_compose.get("services", {}).items()
             if k != "accessproof-gateway"}},
    )
    expected_route = hashlib.sha256(
        f"http://127.0.0.1:{spec.listen_port}/v1/chat/completions".encode()
    ).hexdigest()
    if installation.get("route_sha256") != expected_route:
        raise CustomerAgentError("Gateway route hash changed")
    return verify_reference_compose_isolation(
        resolved_compose, rag_service=spec.rag_service,
        model_url=spec.model_url, expected_route_env=route_environment,
        guard_url=spec.guard_url,
        model_provider=spec.model_provider,
    )


def submit_customer_reference_probe(
    *, installation: dict[str, Any], challenge_config: dict[str, Any],
    machine_credentials: dict[str, Any], spec: InstallationSpec,
    resolved_compose: dict[str, Any], client: httpx.Client | None = None,
    audit_wait_attempts: int = 30, audit_wait_interval_seconds: float = 2.0,
) -> dict[str, Any]:
    network = verify_deployment_contract(
        installation=installation, spec=spec, resolved_compose=resolved_compose,
    )
    challenge_input = {name: value for name, value in challenge_config.items()
                       if name not in {"challenge_id"}}
    challenge = parse_challenge(challenge_input)
    if (challenge.application_id != spec.application_id
            or hashlib.sha256(challenge.url.encode()).hexdigest() != installation["route_sha256"]
            or not isinstance(challenge_config.get("challenge_id"), str)):
        raise CustomerAgentError("Challenge does not match installed application/route")
    guard_id = machine_credentials.get("guard_id")
    control_plane = machine_credentials.get("control_plane_url")
    machine_token = machine_credentials.get("credential")
    if not guard_id or not machine_token or not control_plane:
        raise CustomerAgentError("An enrolled Guard machine credential is required")
    control_plane = validate_control_plane_url(control_plane)
    observed = challenge.run()
    if observed["status"] != "PASS_LOCAL_REFERENCE_ONLY" or len(observed["probes"]) != 4:
        raise CustomerAgentError("Real Gateway HTTP tests failed")
    if not network["static_egress_isolated"]:
        raise CustomerAgentError("RAG deployment does not provide isolated model egress")
    payload = {
        "challenge_id": challenge_config["challenge_id"],
        "guard_id": guard_id, "nonce": challenge.challenge_nonce,
        "deployment_sha256": installation["deployment_sha256"],
        "route_sha256": installation["route_sha256"],
        "contract": "accessproof.gateway/v1",
        "observations": observed["probes"],
        # Each assertion is based on a local code/configuration check AND
        # actual HTTP response-body observations, not a browser checkbox.
        # Post-cutover authentication and source readiness remain separate.
        "customer_route_verified": True,
        "ingress_boundary_verified": True,
        "retrieval_boundary_verified": True,
        "output_boundary_verified": True,
        "alternate_route_blocked": True,
    }
    # Do not transmit the private synthetic identities, canary document
    # bodies, source signatures or Guard local machine credential in JSON.
    endpoint = (f"{control_plane}/api/v1/guards/{guard_id}"
                f"/rag-challenges/{challenge_config['challenge_id']}/submit")
    if (not 1 <= audit_wait_attempts <= 60
            or not 0 <= audit_wait_interval_seconds <= 5):
        raise CustomerAgentError("Invalid bounded Guard audit wait configuration")
    own = client is None
    http = client or httpx.Client(timeout=15, follow_redirects=False, trust_env=False)
    try:
        response = None
        for attempt in range(audit_wait_attempts):
            response = http.post(endpoint, json=payload,
                                 headers={"Authorization": f"Bearer {machine_token}"})
            if response.status_code != 409:
                break
            try:
                reason = response.json().get("detail")
                reason = reason.get("code") if isinstance(reason, dict) else reason
            except (ValueError, TypeError):
                reason = None
            if reason != "GUARD_AUDIT_EVIDENCE_MISSING":
                break
            if attempt + 1 < audit_wait_attempts:
                time.sleep(audit_wait_interval_seconds)
        assert response is not None
        response.raise_for_status()
        receipt = response.json()
        if receipt.get("state") != "tested_awaiting_customer_cutover":
            raise CustomerAgentError("Control plane did not accept the reference test results")
        return {
            "reference_tests": observed,
            "network_validation": network,
            "control_plane": receipt,
            "production_certification": False,
        }
    finally:
        if own:
            http.close()


def _docker_compose_json(compose: str, override: str) -> dict[str, Any]:
    result = subprocess.run(
        ["docker", "compose", "-f", compose, "-f", override,
         "config", "--format", "json"],
        timeout=30, check=True, capture_output=True, text=True,
    )
    manifest = json.loads(result.stdout)
    if not isinstance(manifest, dict):
        raise CustomerAgentError("Docker Compose config did not return a JSON object")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Run and submit a customer-side Gateway reference certification test.")
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--challenge", type=Path, required=True)
    parser.add_argument("--guard-credentials", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        installation = read_private_json(args.installation)
        specification = InstallationSpec.parse(read_private_json(args.spec))
        challenge = read_private_json(args.challenge)
        machine = read_private_json(args.guard_credentials)
        resolved = _docker_compose_json(installation["customer_compose"], installation["override"])
        receipt = submit_customer_reference_probe(
            installation=installation, challenge_config=challenge,
            machine_credentials=machine, spec=specification, resolved_compose=resolved,
        )
        write_private_result(args.output, receipt)
        print(json.dumps({
            "status": "REFERENCE_TESTS_SUBMITTED",
            "production_certification": False,
            "output": str(args.output),
            "next": "Run the separately authorized customer-RAG cutover and verify the employee-facing route.",
        }))
        return 0
    except (CustomerAgentError, NetworkBoundaryError, InstallationError, ValueError, KeyError,
            OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired,
            httpx.HTTPError):
        print("REFERENCE_CUSTOMER_AGENT_FAILED: Check local operator logs and Guard audit delivery.")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
