"""Safely adopt an already running, hash-pinned customer Gateway.

This reports existing installation metadata ONLY; it never alters Docker,
activates Protect, or issues a source/route certificate.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

from .installer import REQUIRED_LABELS


class ExistingGatewayError(ValueError):
    pass


def _docker(*args: str) -> object:
    try:
        p = subprocess.run(
            ["docker", *args], capture_output=True, text=True,
            check=True, timeout=18,
        )
        if args[0] == "ps":
            return [line for line in p.stdout.splitlines() if line.strip()]
        return json.loads(p.stdout)
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        raise ExistingGatewayError("DOCKER_GATEWAY_INSPECTION_FAILED") from exc


def _docker_listing() -> list[str]:
    result = _docker("ps", "--format", "{{json .}}")
    if not isinstance(result, list) or not all(isinstance(value, str) for value in result):
        raise ExistingGatewayError("DOCKER_GATEWAY_DISCOVERY_INVALID")
    return result


def _container_ids(lines: list[str]) -> list[str]:
    ids: list[str] = []
    for line in lines:
        try:
            candidate = json.loads(line)
        except ValueError as exc:
            raise ExistingGatewayError("DOCKER_GATEWAY_DISCOVERY_INVALID") from exc
        if isinstance(candidate, dict) and isinstance(candidate.get("ID"), str):
            ids.append(candidate["ID"])
    return ids


def detect(pairing: dict[str, str], *, container_name: str | None = None,
           release_path: Path | None = None) -> dict[str, object] | None:
    """Verify a uniquely identifiable Gateway and its running RAG peer."""
    releases = release_path or Path(__file__).resolve().parents[3] / "runtime-release.json"
    release = json.loads(releases.read_text())
    matches = []
    ids: list[str]
    if container_name:
        ids = [container_name]
    else:
        ids = _container_ids(_docker_listing())
    for ident in ids:
        if not isinstance(ident, str) or not ident:
            continue
        raw = _docker("inspect", ident)
        if not isinstance(raw, list) or len(raw) != 1:
            continue
        item = raw[0]
        if not isinstance(item, dict):
            continue
        labels = (item.get("Config") or {}).get("Labels") or {}
        if labels.get("com.docker.compose.service") != "accessproof-gateway":
            continue
        env = dict(x.split("=", 1) for x in item["Config"].get("Env", []) if "=" in x)
        # Other customer projects are ignored when auto-detecting.
        if env.get("ACCESSPROOF_GATEWAY_APPLICATION_ID") != pairing.get("application_id"):
            continue
        if env.get("ACCESSPROOF_GATEWAY_TENANT_ID") != pairing.get("organization_id"):
            if container_name:
                raise ExistingGatewayError("GATEWAY_TENANT_MISMATCH")
            continue  # Another isolated customer project can reuse the same app label.
        if (item["State"].get("Status") != "running"
                or item["State"].get("Health", {}).get("Status") != "healthy"):
            raise ExistingGatewayError("GATEWAY_NOT_HEALTHY")
        if item.get("Image") != release.get("image_id"):
            raise ExistingGatewayError("GATEWAY_RUNTIME_HASH_MISMATCH")
        host = item.get("HostConfig") or {}
        if (host.get("ReadonlyRootfs") is not True
                or "ALL" not in (host.get("CapDrop") or [])
                or "no-new-privileges:true" not in (host.get("SecurityOpt") or [])):
            raise ExistingGatewayError("GATEWAY_ISOLATION_INVALID")
        bindings = (item.get("NetworkSettings") or {}).get("Ports") or {}
        mapped = bindings.get("8090/tcp") or []
        if (len(mapped) != 1 or mapped[0].get("HostIp") != "127.0.0.1"
                or not str(mapped[0].get("HostPort", "")).isdigit()):
            raise ExistingGatewayError("GATEWAY_UNSAFE_HOST_BINDING")
        try:
            keys = json.loads(env.get("ACCESSPROOF_GATEWAY_ATTESTATION_PUBLIC_KEYS_JSON", ""))
        except ValueError as exc:
            raise ExistingGatewayError("GATEWAY_ATTESTATION_KEYS_INVALID") from exc
        if (not isinstance(keys, dict) or not keys
                or any(not isinstance(k,str) or not k or not isinstance(v,str) or not v
                       for k, v in keys.items())):
            raise ExistingGatewayError("GATEWAY_ATTESTATION_KEYS_INVALID")
        if (urlsplit(env.get("ACCESSPROOF_GATEWAY_MODEL_URL", "")).scheme != "http"
                or urlsplit(env.get("ACCESSPROOF_GATEWAY_GUARD_URL", "")).scheme != "http"):
            raise ExistingGatewayError("GATEWAY_ENDPOINT_UNSUPPORTED")
        project = labels.get("com.docker.compose.project")
        if not project:
            raise ExistingGatewayError("GATEWAY_COMPOSE_PROJECT_MISSING")
        matches.append((item, env, project, mapped[0]["HostPort"]))
    if not matches:
        if container_name:
            raise ExistingGatewayError("GATEWAY_NOT_FOUND_FOR_PAIRING_APPLICATION")
        return None
    if len(matches) != 1:
        raise ExistingGatewayError("MULTIPLE_GATEWAYS_REQUIRE_EXPLICIT_SELECTION")
    gateway, env, project, port = matches[0]

    peers = _container_ids(_docker_listing())
    rag_candidates = []
    for peer_id in peers:
        if peer_id == gateway.get("Id"):
            continue
        objects = _docker("inspect", peer_id)
        if not isinstance(objects, list) or len(objects) != 1:
            continue
        peer = objects[0]
        if not isinstance(peer, dict):
            continue
        plabels = peer.get("Config", {}).get("Labels") or {}
        if plabels.get("com.docker.compose.project") != project:
            continue
        if any(plabels.get(k) != v for k,v in REQUIRED_LABELS.items()):
            continue
        penv = dict(x.split("=",1) for x in peer.get("Config",{}).get("Env",[]) if "=" in x)
        route_key = plabels.get("com.accessproof.gateway.route_env", "")
        if (not route_key or
                penv.get(route_key) != "http://accessproof-gateway:8090/v1/chat/completions"
                or peer.get("State", {}).get("Status") != "running"):
            continue
        rag_candidates.append(peer)
    if len(rag_candidates) != 1:
        raise ExistingGatewayError("SIGNED_RAG_ROUTE_NOT_VERIFIED")

    bind = {
        "gateway_container_id": gateway["Id"],
        "gateway_image_id": gateway["Image"],
        "rag_container_id": rag_candidates[0]["Id"],
        "rag_image_id": rag_candidates[0]["Image"],
        "project": project,
        "application_id": pairing["application_id"],
        "public_port": int(port),
        "source_key_ids": sorted(json.loads(env["ACCESSPROOF_GATEWAY_ATTESTATION_PUBLIC_KEYS_JSON"])),
        "guard_url": env["ACCESSPROOF_GATEWAY_GUARD_URL"],
        "model_url": env["ACCESSPROOF_GATEWAY_MODEL_URL"],
    }
    canonical = json.dumps(bind,sort_keys=True,separators=(",",":")).encode()
    deployment_sha256 = hashlib.sha256(b"accessproof.existing-gateway/v1\0"+canonical).hexdigest()
    route_sha256 = hashlib.sha256(f"http://127.0.0.1:{port}/v1/chat/completions".encode()).hexdigest()
    return {
        "state":"INSTALLED_UNVERIFIED",
        "reference_contract":"accessproof.gateway/v1",
        "application_id": pairing["application_id"],
        "tenant_id": pairing["organization_id"],
        "deployment_sha256": deployment_sha256,
        "route_sha256": route_sha256,
        "existing_gateway_verified_locally": True,
        "customer_rag_traffic_changed": False,
        "production_certification": False,
    }
