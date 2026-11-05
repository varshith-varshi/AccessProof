"""Customer-run, explicitly approved Docker Gateway installer.

The installer never asks the SaaS API for a Docker socket. It checks an
existing Compose service's declared integration contract and stages an isolated
override without modifying the customer's original file or source code.
Installing a Gateway is NOT a Protect certificate; real-route challenges are
still mandatory before activation.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .model_adapters import ModelProtocolError, selected_adapter

CONTRACT = "accessproof.gateway/v1"
REQUIRED_LABELS = {
    "com.accessproof.gateway.contract": CONTRACT,
    "com.accessproof.gateway.enforces": "attested-retrieval-and-buffered-output",
}
_ALLOWED_ENV = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_ALLOWED_NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$")


class InstallationError(ValueError):
    """An environment cannot be safely configured for reference integration."""


def _text(value: Any, label: str, *, max_length: int = 2048) -> str:
    if not isinstance(value, str) or not value or len(value) > max_length or "\n" in value or "\r" in value:
        raise InstallationError(f"Invalid {label}")
    return value


def _url(value: Any, label: str) -> str:
    raw = _text(value, label)
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password or parsed.fragment:
        raise InstallationError(f"Invalid {label}")
    return raw


def _public_keys(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or not value or len(value) > 10:
        raise InstallationError("Trusted ingestion public keys are required")
    keys: dict[str, str] = {}
    for key_id, encoded in value.items():
        if not _ALLOWED_NAME.fullmatch(_text(key_id, "key identifier", max_length=128)):
            raise InstallationError("Invalid trusted ingestion key identifier")
        encoded = _text(encoded, "public key", max_length=100)
        try:
            key_bytes = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
            Ed25519PublicKey.from_public_bytes(key_bytes)
        except (ValueError, TypeError) as exc:
            raise InstallationError("Invalid Ed25519 public key") from exc
        keys[key_id] = encoded
    return keys


_OUTPUT_HOST = re.compile(r"\.?[a-z0-9-]+(\.[a-z0-9-]+)+")


@dataclass(frozen=True)
class InstallationSpec:
    tenant_id: str
    application_id: str
    rag_service: str
    guard_url: str
    model_url: str
    trusted_public_keys: dict[str, str]
    gateway_image: str = "accessproof-gateway:0.1.0"
    model_name: str = ""
    model_token_env: str = ""
    model_provider: str = "openai-compatible"
    listen_port: int = 8090
    gateway_service: str = "accessproof-gateway"
    # Hosts allowed in released answers (e.g. the company's SharePoint), R-2.
    output_allowed_hosts: tuple[str, ...] = ()

    @classmethod
    def parse(cls, value: dict[str, Any]) -> "InstallationSpec":
        if not isinstance(value, dict):
            raise InstallationError("Installation specification must be an object")
        expected = {
            "tenant_id", "application_id", "rag_service", "guard_url", "model_url",
            "trusted_public_keys", "gateway_image", "model_name", "model_token_env", "model_provider", "listen_port", "gateway_service",
            "output_allowed_hosts",
        }
        if set(value) - expected:
            raise InstallationError("Unknown installation specification field")
        for required in ("tenant_id", "application_id", "rag_service", "guard_url", "model_url", "trusted_public_keys"):
            if required not in value:
                raise InstallationError(f"Missing {required}")
        tenant = _text(value["tenant_id"], "tenant_id", max_length=255)
        app = _text(value["application_id"], "application_id", max_length=255)
        service = _text(value["rag_service"], "rag_service", max_length=128)
        if not _ALLOWED_NAME.fullmatch(service):
            raise InstallationError("Invalid Compose service name")
        image = _text(value.get("gateway_image", "accessproof-gateway:0.1.0"), "gateway_image", max_length=255)
        if not re.fullmatch(r"[a-zA-Z0-9_./:@-]+", image):
            raise InstallationError("Invalid Gateway image")
        model_name = value.get("model_name", "")
        if model_name:
            model_name = _text(model_name, "model_name", max_length=255)
        model_token_env = value.get("model_token_env", "")
        if model_token_env and not _ALLOWED_ENV.fullmatch(model_token_env):
            raise InstallationError("Invalid model credential environment variable")
        provider = value.get("model_provider", "openai-compatible")
        if not isinstance(provider, str):
            raise InstallationError("Invalid model API provider")
        try:
            selected_adapter(provider).validate(
                _url(value["model_url"], "model_url"),
                model_name, "credential-checked-at-install" if model_token_env else None,
            )
        except ModelProtocolError as exc:
            raise InstallationError("Unsupported model API integration or missing provider settings") from exc
        port = value.get("listen_port", 8090)
        if type(port) is not int or not 1024 <= port <= 65535:
            raise InstallationError("Invalid loopback Gateway port")
        gateway_service = value.get("gateway_service", "accessproof-gateway")
        if (not isinstance(gateway_service, str)
                or not _ALLOWED_NAME.fullmatch(gateway_service)
                or not gateway_service.startswith("accessproof-gateway")):
            raise InstallationError("Invalid Gateway Compose service name")
        raw_hosts = value.get("output_allowed_hosts", [])
        if not isinstance(raw_hosts, list) or len(raw_hosts) > 20 or not all(isinstance(h, str) for h in raw_hosts):
            raise InstallationError("output_allowed_hosts must be a list of host names")
        hosts = tuple(sorted({h.strip().lower().rstrip(".") for h in raw_hosts if h.strip()}))
        # Same rule as packages.rag_core.output_safety.OutputLinkPolicy (kept
        # local so the customer installer has no runtime-package dependency).
        if any(not _OUTPUT_HOST.fullmatch(h) for h in hosts):
            raise InstallationError("output_allowed_hosts must contain host names only")
        return cls(
            tenant_id=tenant, application_id=app, rag_service=service,
            guard_url=_url(value["guard_url"], "guard_url"),
            model_url=_url(value["model_url"], "model_url"),
            trusted_public_keys=_public_keys(value["trusted_public_keys"]),
            gateway_image=image, model_name=model_name,
            model_token_env=model_token_env, model_provider=provider, listen_port=port,
            gateway_service=gateway_service, output_allowed_hosts=hosts,
        )


def _labels(value: Any) -> dict[str, str]:
    if isinstance(value, dict):
        return {str(key): str(item) for key, item in value.items()}
    if isinstance(value, list):
        result: dict[str, str] = {}
        for entry in value:
            if not isinstance(entry, str) or "=" not in entry:
                raise InstallationError("Invalid Compose service labels")
            key, item = entry.split("=", 1)
            result[key] = item
        return result
    return {}


def validate_reference_service(spec: InstallationSpec, resolved_compose: dict[str, Any]) -> str:
    """Labels only establish config compatibility, never security certification."""
    services = resolved_compose.get("services")
    if not isinstance(services, dict) or not isinstance(services.get(spec.rag_service), dict):
        raise InstallationError("The requested RAG service is not in this Docker Compose deployment")
    if spec.gateway_service in services:
        raise InstallationError("Existing Gateway service requires explicit migration review")
    labels = _labels(services[spec.rag_service].get("labels"))
    if any(labels.get(key) != value for key, value in REQUIRED_LABELS.items()):
        raise InstallationError("RAG does not declare a supported attested-manifest enforcement contract")
    route_env = labels.get("com.accessproof.gateway.route_env")
    if not route_env or not _ALLOWED_ENV.fullmatch(route_env):
        raise InstallationError("RAG does not declare its supported Gateway route environment variable")
    return route_env


def compose_override(spec: InstallationSpec, route_env: str, private_env_file: Path,
                     resolved_compose: dict[str, Any] | None = None) -> dict[str, Any]:
    """Stage routing configuration but do not activate customer traffic.

    Preserve an explicitly isolated customer RAG network and connect Gateway
    to both it and the distinct model network when topology is reviewable.
    Stage-only installers may lack this supported topology; certification
    rejects their resulting deployment rather than inventing connectivity.
    """
    gateway_networks: list[str] = []
    if resolved_compose:
        services = resolved_compose.get("services", {})
        networks = resolved_compose.get("networks", {})
        rag = services.get(spec.rag_service, {}) if isinstance(services, dict) else {}
        from urllib.parse import urlsplit
        model_name = urlsplit(spec.model_url).hostname
        guard_name = urlsplit(spec.guard_url).hostname
        model = services.get(model_name, {}) if isinstance(services, dict) else {}
        guard = services.get(guard_name, {}) if isinstance(services, dict) else {}
        def network_names(service: Any) -> set[str]:
            value = service.get("networks", {}) if isinstance(service, dict) else {}
            if isinstance(value, dict):
                return set(value)
            if isinstance(value, list) and all(isinstance(item, str) for item in value):
                return set(value)
            return set()
        rag_networks = network_names(rag)
        model_networks = network_names(model)
        guard_networks = network_names(guard)
        if (isinstance(networks, dict) and rag_networks
                and (model_networks or spec.model_provider in {"anthropic", "gemini"})
                and not rag_networks.intersection(model_networks)
                and all(isinstance(networks.get(name), dict)
                            and networks[name].get("internal") is True
                            for name in rag_networks)):
            gateway_networks = sorted(rag_networks | model_networks | guard_networks)
    # Docker's fully internal bridge networks cannot reliably accept even
    # loopback-published host connections. Give ONLY Gateway a separate
    # host-access bridge; never attach RAG, model or Guard to this network.
    gateway_networks = sorted(set(gateway_networks) | {"accessproof-gateway-host"})
    manifest: dict[str, Any] = {
        "networks": {"accessproof-gateway-host": {"internal": False}},
        "services": {
            spec.rag_service: {
                "environment": {route_env: f"http://{spec.gateway_service}:8090/v1/chat/completions"},
                "depends_on": {spec.gateway_service: {"condition": "service_healthy"}},
            },
            spec.gateway_service: {
                "image": spec.gateway_image,
                "restart": "unless-stopped",
                "env_file": [
                    {"path": str(private_env_file), "format": "raw", "required": True},
                    # D-02: written (0600) only after a successful pairing
                    # claim returns this installation's heartbeat credential.
                    {"path": str(private_env_file.parent / PRESENCE_ENV_NAME),
                     "format": "raw", "required": False},
                ],
                "read_only": True,
                "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "tmpfs": ["/tmp"],
                "ports": [f"127.0.0.1:{spec.listen_port}:8090"],
                "healthcheck": {
                    "test": ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8090/health/ready')"],
                    "interval": "15s", "timeout": "5s", "retries": 5,
                },
            },
        },
    }
    manifest["services"][spec.gateway_service]["networks"] = gateway_networks
    return manifest


PRESENCE_ENV_NAME = "gateway-presence.env"
_PRESENCE_KEYS = {
    "control_plane_url": "ACCESSPROOF_GATEWAY_PRESENCE_CONTROL_PLANE_URL",
    "organization_id": "ACCESSPROOF_GATEWAY_PRESENCE_ORGANIZATION_ID",
    "installation_id": "ACCESSPROOF_GATEWAY_PRESENCE_INSTALLATION_ID",
    "credential": "ACCESSPROOF_GATEWAY_PRESENCE_CREDENTIAL",
    "route_sha256": "ACCESSPROOF_GATEWAY_PRESENCE_ROUTE_SHA256",
}


def write_presence_environment(output_dir: Path, presence: dict[str, Any]) -> Path:
    """Persist the claim-issued heartbeat credential for the Gateway only.

    Replaces a previous file atomically (credential rotation on re-pair).
    Never printed; mode 0600 inside the private installation directory.
    """
    if (not isinstance(presence, dict) or output_dir.is_symlink() or not output_dir.is_dir()
            or not all(isinstance(presence.get(key), str) and presence[key] for key in _PRESENCE_KEYS)):
        raise InstallationError("Control plane returned an invalid Gateway presence credential")
    body = "".join(
        f"{env}={_text(presence[key], env, max_length=2048)}\n" for key, env in _PRESENCE_KEYS.items()
    )
    target = output_dir / PRESENCE_ENV_NAME
    staging = output_dir / (PRESENCE_ENV_NAME + ".new")
    staging.unlink(missing_ok=True)
    _write_new(staging, body, 0o600)
    os.replace(staging, target)
    return target


def private_environment(spec: InstallationSpec, environ: dict[str, str]) -> str:
    values = {
        "ACCESSPROOF_GATEWAY_TENANT_ID": spec.tenant_id,
        "ACCESSPROOF_GATEWAY_APPLICATION_ID": spec.application_id,
        "ACCESSPROOF_GATEWAY_GUARD_URL": spec.guard_url,
        "ACCESSPROOF_GATEWAY_MODEL_URL": spec.model_url,
        "ACCESSPROOF_GATEWAY_ATTESTATION_PUBLIC_KEYS_JSON": json.dumps(spec.trusted_public_keys, separators=(",", ":")),
        "ACCESSPROOF_GATEWAY_MODEL_NAME": spec.model_name,
        "ACCESSPROOF_GATEWAY_MODEL_PROVIDER": spec.model_provider,
        "ACCESSPROOF_GATEWAY_OUTPUT_ALLOWED_HOSTS": ",".join(spec.output_allowed_hosts),
    }
    if spec.model_token_env:
        token = environ.get(spec.model_token_env)
        if not token:
            raise InstallationError("Configured model credential is missing from the local environment")
        values["ACCESSPROOF_GATEWAY_MODEL_BEARER_TOKEN"] = _text(token, "model credential", max_length=16_384)
    # Compose's env_file format=raw prevents expansion of '$' within secret tokens.
    return "".join(f"{key}={_text(value, key, max_length=20_000)}\n" for key, value in values.items() if value)


def _write_new(path: Path, content: str, mode: int) -> None:
    fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def stage_installation(spec: InstallationSpec, compose_file: Path, output_dir: Path,
                       resolved_compose: dict[str, Any],
                       *, environ: dict[str, str] | None = None) -> dict[str, str]:
    """Generate restricted deployment files; do not invoke Docker or activate RAG."""
    route_env = validate_reference_service(spec, resolved_compose)
    if not compose_file.is_file():
        raise InstallationError("Customer Compose file does not exist")
    if output_dir.is_symlink() or output_dir.exists():
        raise InstallationError("Installation output directory must be new")
    env_data = private_environment(spec, dict(os.environ) if environ is None else environ)
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    private_env_file = (output_dir / "gateway.env").resolve()
    override = (output_dir / "gateway.override.json").resolve()
    instructions = (output_dir / "installation.json").resolve()
    try:
        _write_new(private_env_file, env_data, 0o600)
        override_body = json.dumps(compose_override(
            spec, route_env, private_env_file, resolved_compose,
        ), indent=2) + "\n"
        _write_new(override, override_body, 0o600)
        deploy_hash = hashlib.sha256(
            b"accessproof.gateway.compose/v1\0" + compose_file.read_bytes()
            + b"\0" + override_body.encode("utf-8")
        ).hexdigest()
        route_hash = hashlib.sha256(
            f"http://127.0.0.1:{spec.listen_port}/v1/chat/completions".encode()
        ).hexdigest()
        _write_new(instructions, json.dumps({
            "state": "INSTALLED_UNVERIFIED", "application_id": spec.application_id,
            "tenant_id": spec.tenant_id, "rag_service": spec.rag_service,
            "gateway_service": spec.gateway_service,
            "customer_compose": str(compose_file.resolve()), "override": str(override),
            "deployment_sha256": deploy_hash, "route_sha256": route_hash,
            "gateway_loopback_port": spec.listen_port, "reference_contract": CONTRACT,
            "security_note": "Routing is staged only; Protect activation requires independent real-route certification.",
        }, indent=2) + "\n", 0o600)
    except BaseException:
        for item in (private_env_file, override, instructions):
            item.unlink(missing_ok=True)
        output_dir.rmdir()
        raise
    return {"compose": str(compose_file.resolve()), "override": str(override), "env": str(private_env_file),
            "rag_service": spec.rag_service, "state": "INSTALLED_UNVERIFIED"}


def verify_existing_staged_installation(
    spec: InstallationSpec, compose_file: Path, output_dir: Path,
) -> dict[str, str]:
    """Apply only exact, non-symlinked, unchanged customer-owned staging files.

    A stage can be reviewed before deployment. Reusing it must never silently
    overwrite a secret, repoint to another Compose project or deploy an
    outdated/modified configuration.
    """
    if output_dir.is_symlink() or not output_dir.is_dir():
        raise InstallationError("The private staged installation does not exist")
    if stat.S_IMODE(output_dir.stat().st_mode) & 0o077:
        raise InstallationError("Staged installation directory must have mode 0700")
    files = [output_dir / name for name in (
        "installation.json", "gateway.override.json", "gateway.env",
    )]
    for path in files:
        if (path.is_symlink() or not path.is_file()
                or stat.S_IMODE(path.stat().st_mode) & 0o077):
            raise InstallationError("Staged installation files must be private 0600 regular files")
    instruction_path, override, private_env = files
    try:
        receipt = json.loads(instruction_path.read_text(encoding="utf-8"))
        override_bytes = override.read_bytes()
        env = {}
        for line in private_env.read_text(encoding="utf-8").splitlines():
            key, _, value = line.partition("=")
            if key and _:
                env[key] = value
    except (ValueError, OSError) as exc:
        raise InstallationError("Staged installation record is corrupted") from exc
    expected_deployment = hashlib.sha256(
        b"accessproof.gateway.compose/v1\0"
        + compose_file.read_bytes() + b"\0" + override_bytes
    ).hexdigest()
    expected_route = hashlib.sha256(
        f"http://127.0.0.1:{spec.listen_port}/v1/chat/completions".encode()
    ).hexdigest()
    if (receipt.get("reference_contract") != CONTRACT
            or receipt.get("state") != "INSTALLED_UNVERIFIED"
            or receipt.get("customer_compose") != str(compose_file.resolve())
            or receipt.get("override") != str(override.resolve())
            or receipt.get("application_id") != spec.application_id
            or receipt.get("tenant_id") != spec.tenant_id
            or receipt.get("rag_service") != spec.rag_service
            or receipt.get("gateway_service", "accessproof-gateway") != spec.gateway_service
            or receipt.get("deployment_sha256") != expected_deployment
            or receipt.get("route_sha256") != expected_route
            or env.get("ACCESSPROOF_GATEWAY_TENANT_ID") != spec.tenant_id
            or env.get("ACCESSPROOF_GATEWAY_APPLICATION_ID") != spec.application_id
            or env.get("ACCESSPROOF_GATEWAY_GUARD_URL") != spec.guard_url
            or env.get("ACCESSPROOF_GATEWAY_MODEL_URL") != spec.model_url
            or env.get("ACCESSPROOF_GATEWAY_MODEL_PROVIDER", "openai-compatible") != spec.model_provider
            or env.get("ACCESSPROOF_GATEWAY_ATTESTATION_PUBLIC_KEYS_JSON") !=
            json.dumps(spec.trusted_public_keys, separators=(",", ":"))):
        raise InstallationError("Staged deployment or credential configuration changed")
    try:
        deployed = json.loads(override_bytes)
        actual_gateway = deployed["services"][spec.gateway_service]
        actual_rag = deployed["services"][spec.rag_service]
        if (actual_gateway["image"] != spec.gateway_image
                or actual_gateway["env_file"][0]["path"] != str(private_env.resolve())
                or actual_rag["environment"][
                    validate_reference_service(spec, {
                        "services": {spec.rag_service: {
                            "labels": REQUIRED_LABELS | {
                                "com.accessproof.gateway.route_env":
                                next(iter(actual_rag["environment"]))
                            },
                        }},
                    })
                ] != f"http://{spec.gateway_service}:8090/v1/chat/completions"):
            raise InstallationError("Staged service route changed")
    except (ValueError, TypeError, KeyError, IndexError) as exc:
        raise InstallationError("Staged Compose override is not valid") from exc
    return {
        "compose": str(compose_file.resolve()),
        "override": str(override.resolve()),
        "env": str(private_env.resolve()),
        "rag_service": spec.rag_service,
        "state": "INSTALLED_UNVERIFIED",
    }


def _checked(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=True, text=True, capture_output=True, timeout=120)


def wait_for_gateway_liveness(port: int, *, attempts: int = 50,
                              interval_seconds: float = 0.25) -> None:
    """A successful Docker "up" means started, not an accepting HTTP socket.

    The Gateway must pass real process liveness before the local installer
    reports success. Guard authorization readiness is separately required
    for Protect certification, and must not be forged by this check.
    """
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    url = f"http://127.0.0.1:{port}/health/live"
    for attempt in range(attempts):
        try:
            with opener.open(url, timeout=1) as response:
                if response.status == 200 and response.read(128) == b'{"status":"ok"}':
                    return
        except (OSError, TimeoutError, urllib.error.URLError, urllib.error.HTTPError):
            pass
        if attempt + 1 < attempts:
            time.sleep(interval_seconds)
    raise InstallationError("Gateway failed its local HTTP liveness check")


def _remove_new_gateway(paths: dict[str, str], spec: InstallationSpec) -> None:
    """Rollback only this installer-created service, never the RAG stack."""
    try:
        subprocess.run(
            ["docker", "compose", "-f", paths["compose"], "-f", paths["override"],
             "rm", "--stop", "--force", spec.gateway_service],
            check=False, capture_output=True, text=True, timeout=25,
        )
    except (OSError, subprocess.TimeoutExpired):
        # Cleanup is best-effort; never report an insecure deployment healthy.
        pass


def main() -> int:
    parser = argparse.ArgumentParser(description="Stage or install a verified-compatible local Docker Gateway. Never enables Protect.")
    parser.add_argument("--spec", type=Path, required=True, help="Customer-approved JSON integration spec")
    parser.add_argument("--compose", type=Path, required=True, help="Existing customer's Docker Compose file")
    parser.add_argument("--output", type=Path, required=True, help="New directory for private generated files")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true", help="Stage and start only a new Gateway (does not redirect customer RAG)")
    mode.add_argument("--apply-staged", action="store_true", help="Verify previously reviewed staging files and start only that Gateway")
    args = parser.parse_args()
    try:
        spec = InstallationSpec.parse(json.loads(args.spec.read_text(encoding="utf-8")))
        compose_file = args.compose.resolve(strict=True)
        inspect = _checked(["docker", "compose", "-f", str(compose_file), "config", "--format", "json"])
        resolved = json.loads(inspect.stdout)
        paths = (verify_existing_staged_installation(spec, compose_file, args.output)
                 if args.apply_staged else stage_installation(spec, compose_file, args.output, resolved))
        if args.apply or args.apply_staged:
            repo = Path(__file__).resolve().parents[3]
            compose_cmd = ["docker", "compose", "-f", paths["compose"], "-f", paths["override"]]
            # Do not silently restart/remove an existing customer-side Gateway
            # from an older installation or another operator's changes.
            existing = _checked([*compose_cmd, "ps", "--all", "--quiet", spec.gateway_service])
            if existing.stdout.strip():
                raise InstallationError("An existing Gateway container requires explicit migration review")
            # The customer ZIP imports a verified runtime before this point and
            # has no Dockerfile. Rebuilding would replace that pinned image.
            image = subprocess.run(
                ["docker", "image", "inspect", spec.gateway_image],
                check=False, capture_output=True, text=True, timeout=30,
            )
            if image.returncode != 0:
                _checked(["docker", "build", "-f", str(repo / "apps/gateway/Dockerfile"),
                          "-t", spec.gateway_image, str(repo)])
            started = True  # No pre-existing Gateway; even a partial Compose up is ours to clean.
            try:
                _checked([*compose_cmd, "up", "-d", "--no-deps", spec.gateway_service])
                wait_for_gateway_liveness(spec.listen_port)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
                    InstallationError, OSError):
                if started:
                    _remove_new_gateway(paths, spec)
                raise InstallationError("Gateway installation failed; local Gateway rollback attempted") from None
        print(json.dumps({
            "state": "INSTALLED_UNVERIFIED" if args.apply or args.apply_staged else "STAGED_UNVERIFIED",
            "files": {"override": paths["override"], "installation": str(args.output / "installation.json")},
            "customer_rag_traffic_changed": False,
            "next": "Run authenticated customer-side real-route certification before applying route override and Protect activation.",
        }))
        return 0
    except (InstallationError, ValueError, FileNotFoundError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired) as exc:
        # Never print subprocess stderr or environment contents; they may contain credentials.
        print(f"INSTALLATION_FAILED: {type(exc).__name__}: {str(exc) if isinstance(exc, InstallationError) else 'deployment prerequisite failed'}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
