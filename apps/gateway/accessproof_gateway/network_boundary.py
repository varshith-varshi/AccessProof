"""Conservative Compose-only reference RAG egress isolation verifier.

This is a **static** prerequisite, not full proof that a customer cannot bypass
AccessProof at runtime. Only accepts isolated, in-stack model backends and a
RAG restricted to internal networks with no access to its model network.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from .model_adapters import ModelProtocolError, selected_adapter


class NetworkBoundaryError(ValueError):
    """The inspected Docker Compose deployment cannot guarantee the reference path."""


def _unsafe_security_options(service: dict[str, Any]) -> bool:
    options = service.get("security_opt") or []
    # Docker accepts both key:value and key=value security options.
    # Apply the same validation to protected components and reachable peers.
    return not isinstance(options, list) or any(
        not isinstance(option, str)
        or option.lower().replace("=", ":", 1) in {
            "seccomp:unconfined", "apparmor:unconfined",
        }
        for option in options
    )


def _network_names(service: dict[str, Any]) -> set[str]:
    value = service.get("networks", {})
    if isinstance(value, dict):
        return set(value)
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return set(value)
    raise NetworkBoundaryError("Invalid Compose service network configuration")


def _has_host_runtime_mount(service: dict[str, Any]) -> bool:
    """Detect reachable peers with Docker/container runtime or host-root access.

    A container with the Docker socket can create a fresh network-attached
    container even when its *declared* Compose networks are isolated. Both
    short- and long-form mounts must be inspected, including the target path.
    """
    volumes = service.get("volumes") or []
    if not isinstance(volumes, list):
        raise NetworkBoundaryError("Unreviewable Compose volumes declaration")
    for volume in volumes:
        if isinstance(volume, str):
            paths = volume.split(":", 2)[:2]
        elif isinstance(volume, dict):
            paths = [volume.get("source", ""), volume.get("target", "")]
        else:
            raise NetworkBoundaryError("Unreviewable Compose volume mount")
        if any(not isinstance(path, str) for path in paths):
            raise NetworkBoundaryError("Unreviewable Compose volume path")
        if any(
            "docker.sock" in path or "containerd.sock" in path
            or path in {"/", "/run", "/var/run", "/proc", "/sys"}
            or path.startswith(("/run/docker/", "/run/containerd/", "/var/run/docker/"))
            for path in paths
        ):
            return True
    return False


def verify_reference_compose_isolation(
    compose: dict[str, Any],
    *, rag_service: str,
    gateway_service: str = "accessproof-gateway",
    model_url: str,
    expected_route_env: str,
    guard_url: str | None = None,
    model_provider: str = "openai-compatible",
) -> dict[str, Any]:
    services = compose.get("services")
    networks = compose.get("networks")
    if not isinstance(services, dict) or not isinstance(networks, dict):
        raise NetworkBoundaryError("Explicit Docker Compose services and isolated networks are required")
    rag = services.get(rag_service)
    gateway = services.get(gateway_service)
    if not isinstance(rag, dict) or not isinstance(gateway, dict):
        raise NetworkBoundaryError("RAG and Gateway services must both exist")
    parsed = urlsplit(model_url)
    model_name = parsed.hostname
    model = services.get(model_name)
    remote_native = model_provider in {"anthropic", "gemini"}
    if remote_native:
        # Official TLS provider destinations are reached by Gateway ONLY.
        # The customer RAG remains in internal networks without public egress.
        # This is a static topology prerequisite, not an external provider
        # certification or a runtime firewall audit.
        try:
            selected_adapter(model_provider).validate(
                model_url, "external-model" if model_provider == "anthropic" else None,
                "operator-managed-credential",
            )
        except ModelProtocolError as exc:
            raise NetworkBoundaryError("Unsupported external model endpoint") from exc
        if isinstance(model, dict):
            raise NetworkBoundaryError("External provider endpoint cannot be a Compose service")
    elif (not model_name or not isinstance(model, dict) or
          parsed.scheme not in {"http", "https"}):
        raise NetworkBoundaryError("Reference certification requires an in-stack model service")
    rag_networks = _network_names(rag)
    gateway_networks = _network_names(gateway)
    # In the non-native branch above the model must be an in-stack service.
    model_service: dict[str, Any] = model if isinstance(model, dict) else {}
    model_networks = set() if remote_native else _network_names(model_service)
    # Explicit Gateway-only non-internal bridge is required so loopback
    # customer-host probes reach the process. RAG/model/Guard must never be
    # connected to this bridge: that would bypass the reference isolation.
    host_network = "accessproof-gateway-host"
    if (host_network not in gateway_networks
            or not isinstance(networks.get(host_network), dict)
            # Docker Compose resolves an explicit internal:false into a
            # missing key (the default). Only True is an internal bridge.
            or networks[host_network].get("internal", False) is not False
            or host_network in rag_networks or host_network in model_networks):
        raise NetworkBoundaryError("Gateway host bridge must be restricted to Gateway only")
    if (not rag_networks or
            not rag_networks <= gateway_networks
            or (not remote_native and
                (not model_networks or not gateway_networks.intersection(model_networks)))
            or rag_networks.intersection(model_networks)):
        raise NetworkBoundaryError("RAG can bypass the Gateway or cannot reach the expected protected route")
    guard_name = None
    guard_networks: set[str] = set()
    if guard_url is not None:
        guard_parsed = urlsplit(guard_url)
        guard_name = guard_parsed.hostname
        guard = services.get(guard_name) if guard_name else None
        if (guard_parsed.scheme not in {"http", "https"}
                or not isinstance(guard, dict)):
            raise NetworkBoundaryError("Reference certification requires an in-stack enrolled Guard service")
        guard_networks = _network_names(guard)
        if host_network in guard_networks:
            raise NetworkBoundaryError("Enrolled Guard must not join Gateway's host-access bridge")
        if not guard_networks or not guard_networks.intersection(gateway_networks):
            raise NetworkBoundaryError("Gateway is not attached to its enrolled Guard network")
    if any(not isinstance(networks.get(name), dict) or
           networks[name].get("internal") is not True for name in rag_networks):
        raise NetworkBoundaryError("RAG network egress is not explicitly isolated")
    # A direct RAG <-> model network disjointness check is insufficient:
    # any other dual-homed service can act as an HTTP relay around Gateway.
    # Explore the transitive network graph through *all non-Gateway services*,
    # treating each peer as potentially untrusted, including sidecars. Never
    # infer protection from service names, image names, or declared labels.
    # Gateway is the only acceptable bridge; it is removed from this graph.
    # Compose network_mode: service:gateway / container:<id> shares a
    # container's network namespace without declaring a "networks" edge.
    # It can run an unprotected local model proxy inside Gateway or model's
    # namespace. Reject every namespace-sharing peer in the examined stack,
    # not only those with a named network intersecting the RAG subnet.
    for name, peer in services.items():
        if not isinstance(peer, dict):
            raise NetworkBoundaryError("Unreviewable Compose service")
        # Host daemon sockets can rewire the entire Docker stack regardless of
        # which network a peer currently declares. A nominally unrelated
        # service may create a new bridge into the RAG or model networks.
        if _has_host_runtime_mount(peer) or peer.get("volumes_from"):
            raise NetworkBoundaryError("Compose service has host runtime/control access")
        if peer.get("network_mode") or peer.get("pid") == "host" or peer.get("ipc") == "host":
            raise NetworkBoundaryError("Unreviewable shared container/host namespace")
        for value in (peer.get("pid"), peer.get("ipc")):
            if isinstance(value, str) and value.startswith(("service:", "container:")):
                raise NetworkBoundaryError("Unreviewable shared container/host namespace")
    unprotected_reachable = set(rag_networks)
    changed = True
    while changed:
        changed = False
        for name, peer in services.items():
            if name == gateway_service:
                continue
            if not isinstance(peer, dict):
                raise NetworkBoundaryError("Unreviewable Compose sidecar service")
            peer_networks = _network_names(peer)
            if peer_networks & unprotected_reachable:
                newly_reached = peer_networks - unprotected_reachable
                if newly_reached:
                    unprotected_reachable.update(newly_reached)
                    changed = True
                # Published sidecars, privileged peers or host aliases create
                # paths outside this reviewable container-network topology.
                if (name != rag_service and (
                    peer.get("ports") or peer.get("network_mode")
                    or peer.get("privileged") or peer.get("extra_hosts")
                    or peer.get("cap_add") or peer.get("devices")
                    or peer.get("pid") == "host"
                    or peer.get("volumes_from")
                    or _has_host_runtime_mount(peer)
                    or _unsafe_security_options(peer)
                )):
                    raise NetworkBoundaryError("RAG network has an unreviewable relay sidecar")
    if not remote_native and unprotected_reachable & model_networks:
        raise NetworkBoundaryError("RAG can reach model through an unprotected service relay")
    if any(
        not isinstance(networks.get(name), dict) or
        networks[name].get("internal") is not True
        for name in unprotected_reachable
    ):
        raise NetworkBoundaryError("RAG can reach a non-internal network through a sidecar")
    if (any(service.get("network_mode") or service.get("privileged")
            for service in (rag, gateway, *(tuple() if remote_native else (model_service,))))
            or any(service.get("extra_hosts") for service in (rag, gateway))
            or (not remote_native and model_service.get("ports"))):
        raise NetworkBoundaryError("Host networking, privileged networking or published model ports are incompatible")
    for label, service in (("RAG", rag), ("Gateway", gateway)):
        # NET_ADMIN and host device access can modify kernel networking or
        # manipulate egress even when Docker network topology looks isolated.
        # cap_drop: ALL is insufficient if cap_add later reintroduces powers.
        if service.get("cap_add") or service.get("devices"):
            raise NetworkBoundaryError(f"{label} must not add capabilities or host devices")
        if _unsafe_security_options(service):
            raise NetworkBoundaryError(f"{label} security profile is unreviewable")
    for service in (rag, gateway):
        if service.get("volumes_from") or _has_host_runtime_mount(service):
            raise NetworkBoundaryError("Host runtime/control mounts are not supported")
    if gateway.get("read_only") is not True or "ALL" not in gateway.get("cap_drop", []):
        raise NetworkBoundaryError("Gateway must be read-only and have no Linux capabilities")
    raw_env = rag.get("environment") or {}
    if isinstance(raw_env, list):
        env = dict(item.split("=", 1) for item in raw_env if isinstance(item, str) and "=" in item)
    elif isinstance(raw_env, dict):
        env = raw_env
    else:
        raise NetworkBoundaryError("Invalid RAG environment")
    if env.get(expected_route_env) != f"http://{gateway_service}:8090/v1/chat/completions":
        raise NetworkBoundaryError("RAG route is not bound to the approved Gateway")
    # This static proof deliberately excludes host compromise, runtime
    # network overrides, arbitrary in-process routes, provider API outages,
    # and DNS/firewall tampering. An external provider is NOT certified.
    return {
        "contract": "accessproof.gateway/v1",
        "static_egress_isolated": True,
        "rag_service": rag_service,
        "model_service": None if remote_native else model_name,
        "external_model_endpoint": remote_native,
        "model_provider": model_provider,
        "guard_service": guard_name,
        "guard_networks": sorted(guard_networks),
        "rag_networks": sorted(rag_networks),
        "gateway_networks": sorted(gateway_networks),
        "model_networks": sorted(model_networks),
        "customer_deployment_certified": False,
        "runtime_probes_still_required": True,
    }
