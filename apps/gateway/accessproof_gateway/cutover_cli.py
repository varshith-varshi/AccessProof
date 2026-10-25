"""Explicitly approved customer-side RAG Compose cutover for reference stack.

The customer runs this on its own authorized Docker host, after the enrolled
Guard has verified the reference route. No SaaS server ever gets Docker access.
A failed cutover rolls back ONLY the RAG service's deployment override.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from apps.guard.accessproof_guard.onboarding import validate_control_plane_url
from .challenge_cli import parse_challenge, read_private_json, write_private_result
from .customer_agent import _docker_compose_json, verify_deployment_contract
from .installer import InstallationSpec, InstallationError
from .network_boundary import NetworkBoundaryError


class CutoverError(ValueError):
    pass


def _run(command: list[str]) -> None:
    subprocess.run(command, timeout=120, check=True, capture_output=True, text=True)


def _inspect_route(url: str, *, gateway_port: int) -> None:
    parts = urlsplit(url)
    if (parts.scheme != "http" or parts.hostname != "127.0.0.1"
            or not parts.port or parts.port == gateway_port
            or parts.username or parts.password or parts.query or parts.fragment
            or parts.path != "/v1/chat/completions"):
        raise CutoverError("Reference cutover requires the local employee-facing RAG endpoint, not the Gateway")


def _collect_response(
    client: httpx.Client, url: str, bearer: str, *,
    application_id: str, request_id: str, resources: list[dict[str, Any]],
    forbidden_canary: str, positive_canary: str = "", allowed: bool,
) -> dict[str, Any]:
    request = {
        "application_id": application_id, "employee_question": "Approved post-cutover reference security check.",
        "request_id": request_id, "retrieved_resources": resources,
    }
    with client.stream(
        "POST", url, follow_redirects=False, timeout=15,
        json=request, headers={"Authorization": f"Bearer {bearer}"},
    ) as response:
        size = 0
        parts: list[bytes] = []
        for part in response.iter_bytes():
            size += len(part)
            if size > 1_000_000:
                raise CutoverError("Employee route returned oversized response bytes")
            parts.append(part)
        raw = b"".join(parts)
        try:
            decoded = json.loads(raw)
        except (ValueError, UnicodeDecodeError) as exc:
            raise CutoverError("Employee route did not return a supported response envelope") from exc
        if not isinstance(decoded, dict):
            raise CutoverError("Invalid employee response object")
        text = json.dumps(decoded, ensure_ascii=False)
        if forbidden_canary in text or forbidden_canary.encode() in raw:
            raise CutoverError("Forbidden canary escaped the protected employee endpoint")
        if allowed:
            meta = decoded.get("accessproof")
            if (response.status_code != 200 or not isinstance(meta, dict)
                    or meta.get("decision") != "allow"
                    or not isinstance(meta.get("decision_id"), str)
                    or not meta["decision_id"]
                    or (positive_canary and positive_canary not in text)):
                raise CutoverError("Customer-facing RAG did not produce an attested Protect positive result")
        else:
            if response.status_code not in (403, 503):
                raise CutoverError("Customer-facing RAG released an unauthorized request")
        detail = decoded.get("detail")
        return {
            "http_status": response.status_code, "response_sha256": hashlib.sha256(raw).hexdigest(),
            "decision_id": decoded.get("accessproof", {}).get("decision_id") if allowed else None,
            "reason_code": detail.get("code") if isinstance(detail, dict) else None,
        }


def approved_reference_cutover(
    *, install: dict[str, Any], spec: InstallationSpec,
    machine: dict[str, Any], challenge_file: dict[str, Any],
    application_url: str, client: httpx.Client | None = None,
    runner: Any = _run, audit_wait_attempts: int = 15,
    audit_wait_seconds: float = 1.0,
) -> dict[str, Any]:
    """Apply only after approved, machine-verified reference challenge.

    This excludes external model endpoints or unknown RAG frameworks. The
    customer-side test must exercise the actual post-restart application
    endpoint; a direct Gateway call is not sufficient.
    """
    _inspect_route(application_url, gateway_port=spec.listen_port)
    compose = _docker_compose_json(install["customer_compose"], install["override"])
    verify_deployment_contract(installation=install, spec=spec, resolved_compose=compose)
    challenge = parse_challenge({k: v for k, v in challenge_file.items() if k != "challenge_id"})
    guard_id = machine.get("guard_id")
    credential = machine.get("credential")
    if not isinstance(guard_id, str) or not isinstance(credential, str) or not guard_id or not credential:
        raise CutoverError("An enrolled private Guard machine credential is required")
    server = validate_control_plane_url(str(machine.get("control_plane_url") or ""))
    challenge_id = challenge_file.get("challenge_id")
    if not isinstance(challenge_id, str):
        raise CutoverError("A bound, server-issued challenge is required")
    endpoint = f"{server}/api/v1/guards/{guard_id}/rag-challenges/{challenge_id}"
    own = client is None
    http = client or httpx.Client(timeout=20, follow_redirects=False, trust_env=False)
    headers = {"Authorization": f"Bearer {credential}"}
    try:
        state = http.get(endpoint, headers=headers)
        state.raise_for_status()
        metadata = state.json()
        if (metadata.get("state") != "tested"
                or metadata.get("guard_id") != guard_id
                or metadata.get("application_id") != spec.application_id
                or metadata.get("deployment_sha256") != install["deployment_sha256"]
                or metadata.get("route_sha256") != install["route_sha256"]):
            raise CutoverError("The control plane has not independently verified this exact staged route")
        compose_flags = ["docker", "compose", "-f", install["customer_compose"]]
        merged_flags = [*compose_flags, "-f", install["override"]]
        # This mutates the authorized customer RAG service, never the source
        # files or unrelated applications.
        try:
            runner([*merged_flags, "up", "-d", "--no-deps", "--force-recreate", spec.rag_service])
            base = hashlib.sha256(challenge.challenge_nonce.encode()).hexdigest()[:24]
            positive = next(item for item in challenge.probes if item.name == "allow")
            negative = next(item for item in challenge.probes if item.name == "deny")
            forged = next(item for item in challenge.probes if item.name == "tamper")
            result = _collect_response(
                http, application_url, positive.employee_token,
                application_id=spec.application_id,
                request_id=f"ap-cutover-{base}",
                resources=positive.retrieved_resources,
                forbidden_canary=challenge.forbidden_canary,
                positive_canary=challenge.allowed_canary, allowed=True,
            )
            negative_responses: dict[str, dict[str, Any]] = {}
            for case, probe in (("deny", negative), ("tamper", forged)):
                negative_responses[case] = _collect_response(
                    http, application_url, probe.employee_token,
                    application_id=spec.application_id,
                    request_id=f"ap-cutover-{base}-{case}",
                    resources=probe.retrieved_resources,
                    forbidden_canary=challenge.forbidden_canary, allowed=False,
                )
                if (negative_responses[case]["http_status"] !=
                        {"deny": 403, "tamper": 503}[case] or
                        negative_responses[case].get("reason_code") != {
                            "deny": "NO_AUTHORIZED_RESOURCES",
                            "tamper": "SOURCE_CONTENT_ATTESTATION_FAILED",
                        }[case]):
                    raise CutoverError("Customer RAG negative challenge did not fail at the expected Guard layer")
            receipt = {
                "challenge_id": challenge_id, "guard_id": guard_id,
                "nonce": challenge.challenge_nonce,
                "deployment_sha256": install["deployment_sha256"],
                "route_sha256": install["route_sha256"],
                "application_request_id": f"ap-cutover-{base}",
                "application_http_status": result["http_status"],
                "application_response_sha256": result["response_sha256"],
                "decision_id": result["decision_id"],
                "negative_request_id": f"ap-cutover-{base}-deny",
                "negative_http_status": negative_responses["deny"]["http_status"],
                "negative_response_sha256": negative_responses["deny"]["response_sha256"],
                "negative_reason_code": negative_responses["deny"]["reason_code"],
                "negative_forbidden_canary_observed": False,
                "tamper_request_id": f"ap-cutover-{base}-tamper",
                "tamper_http_status": negative_responses["tamper"]["http_status"],
                "tamper_response_sha256": negative_responses["tamper"]["response_sha256"],
                "tamper_reason_code": negative_responses["tamper"]["reason_code"],
                "forbidden_canary_observed": False,
                "gateway_route_enforced": True,
            }
            # Local Guard writes audit records durably and uploads them in a
            # separate control-plane sync tick. Wait a bounded interval for
            # its independently authenticated audit events to arrive.
            # Never turn a persistent 409 into a success response.
            if not 1 <= audit_wait_attempts <= 60 or not 0 <= audit_wait_seconds <= 5:
                raise CutoverError("Invalid bounded Guard-audit wait configuration")
            ack = None
            for attempt in range(audit_wait_attempts):
                ack = http.post(endpoint + "/cutover", headers=headers, json=receipt)
                if ack.status_code != 409:
                    break
                try:
                    error_code = ack.json().get("detail")
                except (ValueError, TypeError):
                    raise CutoverError("Invalid control-plane evidence rejection") from None
                if error_code != "CUSTOMER_CUTOVER_GUARD_AUDIT_MISMATCH":
                    break
                if attempt + 1 < audit_wait_attempts:
                    time.sleep(audit_wait_seconds)
            assert ack is not None
            ack.raise_for_status()
            if ack.json().get("state") != "customer_cutover_verified":
                raise CutoverError("Control plane has not accepted the customer cutover")
            return {
                "state": "CUTOVER_VERIFIED_AWAITING_GUARD_HEARTBEAT",
                "production_certification": False,
                "application": spec.application_id,
                "deployment_sha256": install["deployment_sha256"],
                "customer_http_checks": ["allow", "deny", "tamper"],
                "control_plane": ack.json(),
            }
        except (CutoverError, httpx.HTTPError, subprocess.CalledProcessError,
                subprocess.TimeoutExpired, KeyError, ValueError,
                NetworkBoundaryError, InstallationError) as exc:
            # Restoring the original Compose route could silently resume an
            # *unprotected* direct model path. Fail closed instead: stop only
            # the selected customer RAG service; operator must explicitly
            # approve a safe recovery or new protected cutover.
            try:
                runner([*merged_flags, "stop", "-t", "10", spec.rag_service])
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
                raise CutoverError("Cutover verification failed and RAG shutdown requires immediate operator intervention") from None
            raise CutoverError("Cutover verification failed; customer RAG stopped fail closed") from exc
    finally:
        if own:
            http.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Explicitly approved cutover for a certified reference Docker RAG.")
    parser.add_argument("--installation", type=Path, required=True)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--challenge", type=Path, required=True)
    parser.add_argument("--guard-credentials", type=Path, required=True)
    parser.add_argument("--application-url", required=True, help="Loopback customer RAG endpoint, not Gateway")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--approve-customer-rag-restart", action="store_true")
    args = parser.parse_args()
    if not args.approve_customer_rag_restart:
        print("CUTOVER_NOT_APPROVED: Explicit customer authorization is required.")
        return 2
    try:
        installation = read_private_json(args.installation)
        spec = InstallationSpec.parse(read_private_json(args.spec))
        challenge = read_private_json(args.challenge)
        machine = read_private_json(args.guard_credentials)
        result = approved_reference_cutover(
            install=installation, spec=spec, machine=machine,
            challenge_file=challenge, application_url=args.application_url,
        )
        write_private_result(args.output, result)
        print(json.dumps({
            "state": result["state"], "production_certification": False,
            "output": str(args.output),
        }))
        return 0
    except (CutoverError, NetworkBoundaryError, InstallationError, ValueError,
            OSError, httpx.HTTPError,
            subprocess.CalledProcessError, subprocess.TimeoutExpired, KeyError):
        print("CUTOVER_UNVERIFIED: Customer-side verification failed; check installation and rollback status.")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
