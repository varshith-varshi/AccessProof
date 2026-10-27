"""Audit whether a customer RAG can bypass the AccessProof Gateway.

This is a read-only STATIC topology check. Passing is not production
certification, and failing must block claims of comprehensive protection.
The tool never prints Compose environment values, secret mounts or API keys.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
from typing import Any

from apps.gateway.accessproof_gateway.network_boundary import (
    NetworkBoundaryError, verify_reference_compose_isolation,
)


def examine_topology(
    config: dict[str, Any], *, rag_service: str, gateway_service: str,
    model_url: str, expected_route_env: str, model_provider: str,
) -> dict[str, Any]:
    try:
        if not model_url:
            raise NetworkBoundaryError("MODEL_ENDPOINT_NOT_CONFIGURED")
        verify_reference_compose_isolation(
            config, rag_service=rag_service, gateway_service=gateway_service,
            model_url=model_url, expected_route_env=expected_route_env,
            model_provider=model_provider,
        )
        return {
            "result": "STATIC_REFERENCE_TOPOLOGY_PASSED",
            "customer_protection_certified": False,
            "runtime_probe_required": True,
            "rag_service": rag_service,
            "gateway_service": gateway_service,
            "reason": "STATIC_ONLY_NOT_RUNTIME_NETWORK_OR_ROUTE_PROOF",
        }
    except (NetworkBoundaryError, TypeError, ValueError, KeyError) as exc:
        # Do not echo arbitrary raw Compose exception data.
        reason = str(exc)
        known = (
            "Gateway", "RAG", "Compose", "model", "network", "service",
            "isolation", "host", "relay", "runtime", "Unexpected",
            "unsafe", "Unsupported", "unreviewable", "Unreviewable",
            "Reference", "External", "No ", "Invalid", "MODEL_",
        )
        return {
            "result": "BLOCKED_UNVERIFIED_TOPOLOGY",
            "customer_protection_certified": False,
            "runtime_probe_required": True,
            "reason": reason[:160] if reason.startswith(known) else "TOPOLOGY_UNSUPPORTED",
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose-file", action="append", required=True)
    parser.add_argument("--profile", action="append", default=[])
    parser.add_argument("--rag-service", default="drive-rag")
    parser.add_argument("--gateway-service", default="gateway")
    parser.add_argument("--model-url", default=os.getenv("ACCESSPROOF_GATEWAY_MODEL_URL", ""))
    parser.add_argument("--model-provider", default="openai-compatible")
    parser.add_argument("--route-env", default="ACCESSPROOF_CHAT_URL")
    args = parser.parse_args()

    command = ["docker", "compose"]
    for file in args.compose_file:
        command.extend(("-f", file))
    for profile in args.profile:
        command.extend(("--profile", profile))
    command.extend(("config", "--format", "json"))
    try:
        process = subprocess.run(
            command, capture_output=True, text=True, timeout=30, check=False,
        )
        if process.returncode or len(process.stdout) > 5_000_000:
            raise ValueError("COMPOSE_UNAVAILABLE_OR_INVALID")
        config = json.loads(process.stdout)
        if not isinstance(config, dict):
            raise ValueError("COMPOSE_UNAVAILABLE_OR_INVALID")
        result = examine_topology(
            config, rag_service=args.rag_service,
            gateway_service=args.gateway_service,
            model_url=args.model_url, expected_route_env=args.route_env,
            model_provider=args.model_provider,
        )
    except (OSError, ValueError, subprocess.TimeoutExpired):
        result = {
            "result": "BLOCKED_UNVERIFIED_TOPOLOGY",
            "customer_protection_certified": False,
            "runtime_probe_required": True,
            "reason": "COMPOSE_UNAVAILABLE_OR_INVALID",
        }
    print(json.dumps(result, sort_keys=True))
    return 0 if result["result"] == "STATIC_REFERENCE_TOPOLOGY_PASSED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
