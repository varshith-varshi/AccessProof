"""Guided, one-command customer-side integration for the strict Docker RAG contract.

This orchestrates existing installer / enrolled Guard challenge / approved
cutover components. It deliberately cannot auto-certify unknown RAG paths or
activate Protect without control-plane evidence. Never edits customer source,
runs a SaaS-initiated shell, or transmits secrets in printed diagnostic output.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from urllib.parse import quote, urlsplit
import httpx
from apps.guard.accessproof_guard.onboarding import validate_control_plane_url

from pathlib import Path
from typing import Any

from .challenge_cli import read_private_json, write_private_result
from .customer_agent import (
    CustomerAgentError, _docker_compose_json,
    submit_customer_reference_probe, verify_deployment_contract,
)
from .customer_cutover import approved_docker_cutover
from .cutover_agent import EmployeeRouteProbe
from .installer import (
    InstallationError, InstallationSpec, stage_installation, validate_reference_service, _labels,
    verify_existing_staged_installation,
)

class IntegrationWizardError(ValueError):
    """Unsupported or unapproved integration — do not release employee traffic."""


def _resolved_compose(compose: Path) -> dict[str, Any]:
    if compose.is_symlink() or not compose.is_file():
        raise IntegrationWizardError("CUSTOMER_COMPOSE_FILE_UNSAFE")
    result = subprocess.run(
        ["docker", "compose", "-f", str(compose.resolve()), "config",
         "--format", "json"], timeout=30, check=True,
        capture_output=True, text=True,
    )
    data = json.loads(result.stdout)
    if not isinstance(data, dict):
        raise IntegrationWizardError("CUSTOMER_COMPOSE_INVALID")
    return data


def _environ(service: dict[str, Any]) -> dict[str, str]:
    raw = service.get("environment") or {}
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items() if v is not None}
    if isinstance(raw, list):
        return dict(item.split("=", 1) for item in raw
                    if isinstance(item, str) and "=" in item)
    raise IntegrationWizardError("RAG_ENVIRONMENT_INVALID")


def analyze_reference(
    spec: InstallationSpec, resolved: dict[str, Any],
) -> dict[str, Any]:
    """Return a secret-free compatibility report, not a Protect certificate."""
    issues: list[str] = []
    services = resolved.get("services")
    if not isinstance(services, dict):
        raise IntegrationWizardError("COMPOSE_SERVICES_INVALID")
    service = services.get(spec.rag_service)
    if not isinstance(service, dict):
        raise IntegrationWizardError("RAG_SERVICE_NOT_FOUND")
    try:
        route_env = validate_reference_service(spec, resolved)
    except InstallationError as exc:
        # This is an opaque code, never source/config values.
        raise IntegrationWizardError("SUPPORTED_RAG_CONTRACT_REQUIRED") from exc
    environment = _environ(service)
    # Cache absence cannot be inferred from missing AccessProof-specific env
    # variables. Otherwise an arbitrary customer Redis/LangChain cache could be
    # silently labelled "none" and a protected-route claim could be overstated.
    declared_cache = environment.get("ACCESSPROOF_DEMO_CACHE_BACKEND", "").strip().lower()
    labels = _labels(service.get("labels"))
    hints = {
        "redis": bool(environment.get("ACCESSPROOF_DEMO_CACHE_URL") or
                      environment.get("REDIS_URL") or environment.get("CACHE_REDIS_URL")),
        "memcached": bool(environment.get("ACCESSPROOF_DEMO_CACHE_MEMCACHED_HOST") or
                          environment.get("MEMCACHED_HOST")),
        "postgresql": bool(environment.get("ACCESSPROOF_DEMO_CACHE_SQLALCHEMY_URL")),
    }
    named = {key for key, present in hints.items() if present}
    if declared_cache and declared_cache not in {"redis", "memcached", "postgresql", "memory", "none"}:
        issues.append("CACHE_BACKEND_NOT_SUPPORTED")
    if declared_cache:
        cache_backend = declared_cache
        cache_confidence = "DECLARED_UNVERIFIED"
        if named and (named != {declared_cache}):
            issues.append("CACHE_BACKEND_DECLARATION_CONFLICT")
    elif len(named) == 1:
        cache_backend = next(iter(named))
        cache_confidence = "INFERRED_UNVERIFIED"
    elif len(named) > 1:
        cache_backend = "ambiguous"
        cache_confidence = "AMBIGUOUS"
        issues.append("CACHE_MULTIPLE_BACKENDS_DETECTED")
    elif labels.get("com.accessproof.cache.mode") == "none":
        cache_backend = "none"
        cache_confidence = "NO_CACHE_DECLARED_UNVERIFIED"
    else:
        cache_backend = "unknown"
        cache_confidence = "UNKNOWN"
        issues.append("CACHE_CONFIGURATION_UNKNOWN")
    if labels.get("com.accessproof.cache.mode") == "none" and cache_backend != "none":
        issues.append("CACHE_NO_CACHE_DECLARATION_CONFLICT")
    # A custom cache may exist outside these env variables. Its presence can
    # be hinted by config, but only approved live route probes establish safety.
    if any(key in environment for key in (
        "CACHE_URL", "LANGCHAIN_CACHE_URL", "GPTCACHE_URL", "SEMANTIC_CACHE_URL",
    )) and cache_backend in {"none", "unknown"}:
        issues.append("CACHE_POSSIBLY_UNINSTRUMENTED")
    if cache_backend == "memory":
        issues.append("PROCESS_LOCAL_CACHE_UNCERTIFIED")
    if cache_backend not in {"none", "unknown"}:
        # This label is a *declaration*, never proof of output interception.
        if labels.get("com.accessproof.cache.return_path") != "signed-manifest-guard-reauthorization/v1":
            issues.append("CACHE_RESPONSE_PATH_NOT_DECLARED")
    if service.get("network_mode") or service.get("privileged"):
        issues.append("RAG_UNSAFE_NETWORK_MODE")
    if service.get("extra_hosts"):
        issues.append("RAG_HOST_EGRESS_UNVERIFIED")
    if any(
        isinstance(vol, str) and "docker.sock" in vol or
        isinstance(vol, dict) and "docker.sock" in str(vol.get("source", ""))
        for vol in service.get("volumes", [])
    ):
        issues.append("RAG_HOST_DOCKER_SOCKET_EXPOSED")
    # This check is only a preliminary preview; the enrolled agent performs
    # independent topology checks and real employee-route traffic challenges.
    model_host = urlsplit(spec.model_url).hostname
    guard_host = urlsplit(spec.guard_url).hostname
    native_remote = spec.model_provider in {"anthropic", "gemini"}
    if model_host not in services and not native_remote:
        issues.append("EXTERNAL_MODEL_NEEDS_CUSTOM_NETWORK_REVIEW")
    if model_host in services and native_remote:
        issues.append("CLOUD_PROVIDER_MASQUERADING_AS_COMPOSE_SERVICE")
    if guard_host not in services:
        issues.append("GUARD_NOT_IN_REFERENCE_COMPOSE")
    def nets(item: Any) -> set[str]:
        value = item.get("networks", []) if isinstance(item, dict) else []
        if isinstance(value, dict):
            return set(value)
        if isinstance(value, list) and all(isinstance(name, str) for name in value):
            return set(value)
        return set()
    rag_networks = nets(service)
    model_networks = nets(services.get(model_host))
    guard_networks = nets(services.get(guard_host))
    configs = resolved.get("networks", {})
    if (not isinstance(configs, dict) or not rag_networks
            or (not native_remote and not model_networks)
            or any(not isinstance(configs.get(name), dict)
                   or configs[name].get("internal") is not True for name in rag_networks)):
        issues.append("RAG_NETWORK_NOT_ISOLATED")
    if rag_networks & model_networks:
        issues.append("DIRECT_RAG_MODEL_EGRESS_BYPASS")
    if not guard_networks:
        issues.append("GUARD_NETWORK_NOT_REVIEWABLE")
    if isinstance(services.get(model_host), dict) and services[model_host].get("ports"):
        issues.append("MODEL_HAS_HOST_PUBLISHED_PORT")
    return {
        "supported_reference_contract": True,
        "application_id": spec.application_id,
        "rag_service": spec.rag_service,
        "route_environment_name": route_env,
        "detected_cache_backend": cache_backend,
        "cache_identification_confidence": cache_confidence,
        "cache_inventory_complete": False,
        "cache_return_path_verified": False,
        "model_provider": spec.model_provider,
        "blocking_issues": sorted(set(issues)),
        "automatic_customer_traffic_cutover": False,
        "production_certification": False,
    }


def _validate_stage(
    spec: InstallationSpec, compose: Path, output: Path,
    *, resolved: dict[str, Any], allow_create: bool,
) -> dict[str, str]:
    if output.exists():
        return verify_existing_staged_installation(spec, compose, output)
    if not allow_create:
        raise IntegrationWizardError("INSTALLATION_NOT_STAGED")
    return stage_installation(spec, compose, output, resolved)


def _run_installer_apply(spec_path: Path, compose: Path, output: Path) -> None:
    # Reuse independently tested installer safeguards, including existing
    # Gateway refusal, credential file checks and loopback liveness.
    result = subprocess.run(
        [sys.executable, "-m", "apps.gateway.accessproof_gateway.installer",
         "--spec", str(spec_path), "--compose", str(compose),
         "--output", str(output), "--apply-staged"],
        check=False, capture_output=True, timeout=240, text=True,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip().splitlines()
        raise IntegrationWizardError(detail[-1][:500] if detail else "GATEWAY_INSTALL_FAILED")


def _read_secret(path: Path | None, name: str) -> dict[str, Any]:
    if path is None:
        raise IntegrationWizardError(f"{name}_REQUIRED")
    return read_private_json(path)


def request_guard_protect_activation(
    *, application_id: str, approval: dict[str, Any],
    client: httpx.Client | None = None,
) -> dict[str, Any]:
    """Request existing control-plane security preflight, never override it.

    Explicit user admin credentials are separate from the enrolled machine
    challenge. Only a guard-acknowledged status of 'protected' may be shown
    as active. Never transmit private provider or ingestion signing keys.
    """
    if set(approval) != {"control_plane_url", "admin_session_token"}:
        raise IntegrationWizardError("ADMIN_PROTECTION_CREDENTIALS_INVALID")
    if not isinstance(approval["control_plane_url"], str):
        raise IntegrationWizardError("CONTROL_PLANE_URL_UNSAFE")
    try:
        server = validate_control_plane_url(approval["control_plane_url"])
    except (TypeError, ValueError, RuntimeError) as exc:
        raise IntegrationWizardError("CONTROL_PLANE_URL_UNSAFE") from exc
    token = approval["admin_session_token"]
    if not isinstance(token, str) or not 30 <= len(token) <= 16_384:
        raise IntegrationWizardError("ADMIN_PROTECTION_TOKEN_INVALID")
    url = (f"{server}/api/v1/current/ai-applications/"
           f"{quote(application_id, safe='')}/protection/enable")
    own = client is None
    http = client or httpx.Client(
        timeout=15, follow_redirects=False, trust_env=False,
    )
    try:
        response = http.post(
            url, headers={"Authorization": f"Bearer {token}"},
        )
        if response.status_code != 202:
            raise IntegrationWizardError("CONTROL_PLANE_PROTECT_PREFLIGHT_REJECTED")
        payload = response.json()
        if not isinstance(payload, dict):
            raise IntegrationWizardError("INVALID_CONTROL_PLANE_PROTECT_STATUS")
        state = payload.get("state")
        if state not in {
            "protected", "validating", "awaiting_guard_ack",
            "action_required", "protection_needs_attention",
        }:
            raise IntegrationWizardError("INVALID_CONTROL_PLANE_PROTECT_STATUS")
        return {
            "state": state,
            "protect_active": state == "protected"
            and payload.get("guard_acknowledged") is True
            and isinstance(payload.get("checks"), list)
            and bool(payload["checks"])
            and all(isinstance(item, dict) and item.get("ok") is True
                    for item in payload["checks"]),
        }
    except (httpx.HTTPError, ValueError) as exc:
        if isinstance(exc, IntegrationWizardError):
            raise
        raise IntegrationWizardError("CONTROL_PLANE_PROTECT_REQUEST_FAILED") from exc
    finally:
        if own:
            http.close()


def run_wizard(
    *, mode: str, spec_path: Path, compose: Path, output: Path,
    approve_gateway_install: bool = False,
    approve_route_cutover: bool = False,
    challenge_path: Path | None = None,
    machine_path: Path | None = None,
    probe_path: Path | None = None,
    approve_protect_request: bool = False,
    admin_credentials_path: Path | None = None,
) -> dict[str, Any]:
    """Single orchestrator with explicit approvals, resumption and hard gates."""
    if mode not in {"plan", "stage", "install", "verify", "cutover", "complete"}:
        raise IntegrationWizardError("INVALID_WIZARD_MODE")
    if approve_protect_request and (
        mode not in {"complete", "cutover"} or not approve_route_cutover
    ):
        raise IntegrationWizardError("PROTECT_REQUEST_REQUIRES_VERIFIED_CUTOVER")
    if approve_protect_request:
        # Validate secret before ANY Docker action. It is not enough to hold
        # an enrolled Guard machine token; only a human ORG_ADMIN can request
        # the control plane's independent Protect preflight.
        admin_credentials = _read_secret(
            admin_credentials_path, "ORG_ADMIN_PROTECT_CREDENTIALS",
        )
        if (set(admin_credentials) != {"control_plane_url", "admin_session_token"}
                or not isinstance(admin_credentials["admin_session_token"], str)
                or not 30 <= len(admin_credentials["admin_session_token"]) <= 16_384):
            raise IntegrationWizardError("ADMIN_PROTECTION_CREDENTIALS_INVALID")
    else:
        admin_credentials = None
    spec = InstallationSpec.parse(read_private_json(spec_path))
    if not compose.is_file() or compose.is_symlink():
        raise IntegrationWizardError("CUSTOMER_COMPOSE_FILE_UNSAFE")
    compose = compose.resolve()
    resolved = _resolved_compose(compose)
    analysis = analyze_reference(spec, resolved)
    if mode == "plan":
        return {"state": "PLAN_ONLY", **analysis}
    if analysis["blocking_issues"]:
        raise IntegrationWizardError("INTEGRATION_PREFLIGHT_NOT_SUPPORTED")
    if output.is_symlink() or (output.exists() and not output.is_dir()):
        raise IntegrationWizardError("STAGED_INSTALLATION_UNSAFE")
    paths = _validate_stage(
        spec, compose, output, resolved=resolved, allow_create=mode in {"stage", "install"},
    )
    if mode == "stage":
        return {"state": "STAGED_UNVERIFIED", "installation": str(output / "installation.json"),
                "customer_rag_traffic_changed": False, "production_certification": False}
    if mode in {"install", "complete"}:
        if not approve_gateway_install:
            raise IntegrationWizardError("EXPLICIT_GATEWAY_INSTALL_APPROVAL_REQUIRED")
        # Require all approvals and private challenge inputs before touching
        # a running Docker project. Incomplete one-command setup never
        # silently performs a partial install+cutover.
        if mode == "complete" and not approve_route_cutover:
            raise IntegrationWizardError("EXPLICIT_CUSTOMER_RAG_CUTOVER_APPROVAL_REQUIRED")
        if mode == "complete":
            _read_secret(challenge_path, "SERVER_ISSUED_CHALLENGE")
            _read_secret(machine_path, "ENROLLED_GUARD_MACHINE")
            EmployeeRouteProbe.parse(
                _read_secret(probe_path, "CUSTOMER_EMPLOYEE_ROUTE_PROBE")
            )
        _run_installer_apply(spec_path, compose, output)
        if mode == "install":
            return {"state": "INSTALLED_UNVERIFIED",
                    "installation": str(output / "installation.json"),
                    "customer_rag_traffic_changed": False, "production_certification": False}

    # Only enrolled machine credentials + a replay-resistant challenge from
    # the control plane may progress past Gateway installation.
    installation = read_private_json(output / "installation.json")
    challenge = _read_secret(challenge_path, "SERVER_ISSUED_CHALLENGE")
    machine = _read_secret(machine_path, "ENROLLED_GUARD_MACHINE")
    resolved_with_override = _docker_compose_json(paths["compose"], paths["override"])
    verify_deployment_contract(
        installation=installation, spec=spec,
        resolved_compose=resolved_with_override,
    )
    if mode in {"verify", "complete"}:
        receipt = submit_customer_reference_probe(
            installation=installation, challenge_config=challenge,
            machine_credentials=machine, spec=spec,
            resolved_compose=resolved_with_override,
        )
        if mode == "verify":
            return {"state": "REFERENCE_TESTS_SUBMITTED",
                    "production_certification": False,
                    "customer_rag_traffic_changed": False,
                    "result": receipt}
    if not approve_route_cutover:
        raise IntegrationWizardError("EXPLICIT_CUSTOMER_RAG_CUTOVER_APPROVAL_REQUIRED")
    probe = EmployeeRouteProbe.parse(
        _read_secret(probe_path, "CUSTOMER_EMPLOYEE_ROUTE_PROBE")
    )
    # This method validates the exact challenge/control-plane receipt, live
    # Guard readiness, static isolation, and customer employee allow/deny.
    # It stops ONLY the changed RAG service if evidence fails after cutover.
    receipt = approved_docker_cutover(
        installation=installation, spec=spec, challenge=challenge,
        machine=machine, probe=probe, approve=True,
    )
    result = {"state": receipt["state"],
              "customer_rag_traffic_changed": True,
              "production_certification": False,
              "result": receipt}
    if approve_protect_request:
        assert admin_credentials is not None
        result["control_plane_protection"] = request_guard_protect_activation(
            application_id=spec.application_id, approval=admin_credentials,
        )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="AccessProof guided Docker RAG integration; no automatic Protect certification.",
    )
    parser.add_argument("mode", choices=("plan", "stage", "install", "verify", "cutover", "complete"))
    parser.add_argument("--spec", type=Path, required=True, help="Mode-0600 approved installation spec")
    parser.add_argument("--compose", type=Path, required=True, help="Existing customer Compose file")
    parser.add_argument("--output", type=Path, required=True, help="Private staging directory")
    parser.add_argument("--approve-gateway-install", action="store_true")
    parser.add_argument("--approve-route-cutover", action="store_true")
    parser.add_argument("--approve-protect-request", action="store_true",
                        help="Request existing control-plane preflight after verified cutover")
    parser.add_argument("--admin-credentials", type=Path,
                        help="Mode-0600 ORG_ADMIN session for requested Protect preflight")
    parser.add_argument("--challenge", type=Path, help="Mode-0600 control-plane-issued challenge")
    parser.add_argument("--guard-credentials", type=Path, help="Mode-0600 machine credentials")
    parser.add_argument("--employee-route-probe", type=Path, help="Mode-0600 synthetic identities")
    parser.add_argument("--receipt", type=Path, help="Write private result, never overwrite")
    args = parser.parse_args()
    try:
        if args.mode in {"plan", "stage"} and (
            args.approve_gateway_install or args.approve_route_cutover
        ):
            raise IntegrationWizardError("APPROVAL_FOR_WRONG_PHASE")
        result = run_wizard(
            mode=args.mode, spec_path=args.spec, compose=args.compose,
            output=args.output,
            approve_gateway_install=args.approve_gateway_install,
            approve_route_cutover=args.approve_route_cutover,
            challenge_path=args.challenge, machine_path=args.guard_credentials,
            probe_path=args.employee_route_probe,
            approve_protect_request=args.approve_protect_request,
            admin_credentials_path=args.admin_credentials,
        )
        if args.receipt:
            write_private_result(args.receipt, result)
        # Only return status codes; result may contain challenge diagnostics
        # or private network details and therefore belongs in 0600 receipt.
        print(json.dumps({
            "state": result["state"],
            "production_certification": False,
            "customer_rag_traffic_changed": result.get("customer_rag_traffic_changed", False),
            "receipt": str(args.receipt) if args.receipt else None,
            "installation": result.get("installation"),
            "protect_active": result.get("control_plane_protection", {}).get("protect_active", False),
            "blocking_issues": result.get("blocking_issues") if args.mode == "plan" else None,
        }))
        return 0
    except (IntegrationWizardError, InstallationError, CustomerAgentError,
            subprocess.CalledProcessError, subprocess.TimeoutExpired,
            json.JSONDecodeError, ValueError, KeyError, OSError):
        print("ACCESSPROOF_INTEGRATION_FAILED: Review private local diagnostics; no Protect certification issued.")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
