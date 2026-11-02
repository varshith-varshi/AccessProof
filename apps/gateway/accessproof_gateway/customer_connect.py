"""Customer-side guided Gateway pairing for supported Docker Compose RAGs.

No SaaS-initiated shell access, no live-route cutover, and no auto certification.
Stage/Install requires the same reviewed contract as integration_wizard.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from apps.gateway.accessproof_gateway.challenge_cli import read_private_json
from apps.gateway.accessproof_gateway.application_discovery import (
    DiscoveryError, discover, docker_inventory, published_host_ports,
)
from apps.gateway.accessproof_gateway.selection_planner import SelectionPlanError, plan_selection
from apps.gateway.accessproof_gateway.integration_wizard import (
    IntegrationWizardError,
    _resolved_compose,
    run_wizard,
)
from apps.gateway.accessproof_gateway.installer import REQUIRED_LABELS, _labels


class ConnectError(ValueError):
    pass


def load_pairing(path: Path) -> dict[str, str]:
    if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ConnectError("Pairing file must be an existing private mode-0600 file (chmod 600).")
    data = read_private_json(path)
    if (
        not isinstance(data, dict)
        or data.get("schema") != "accessproof.gateway_pairing/v1"
        or not all(
            isinstance(data.get(x), str) and data[x]
            for x in ("application_id", "control_plane_url", "pairing_token", "expires_at")
        )
    ):
        raise ConnectError(
            "Invalid pairing file. Generate a new one from your AccessProof application."
        )
    url = urlsplit(data["control_plane_url"])
    if (
        (
            url.scheme != "https"
            and not (url.scheme == "http" and url.hostname in {"127.0.0.1", "localhost"})
        )
        or not url.hostname
        or url.username
        or url.password
        or url.fragment
        or url.path not in {"", "/"}
    ):
        raise ConnectError("Untrusted pairing control plane URL")
    if url.hostname not in {"api.accessproof.in", "localhost", "127.0.0.1"}:
        raise ConnectError("Unrecognized AccessProof control plane origin")
    try:
        expires = datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise ConnectError("Invalid pairing expiration") from exc
    if expires.tzinfo is None or expires <= datetime.now(timezone.utc):
        raise ConnectError("Pairing expired. Generate a new pairing file from your dashboard.")
    return data


def public_key_from_private(path: Path) -> str:
    if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ConnectError("Signing key must be a private, non-symlink mode-0600 file.")
    private = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(private, Ed25519PrivateKey):
        raise ConnectError("The supported ingestion signing key must be Ed25519.")
    raw = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def create_spec(
    pairing: dict[str, str],
    *,
    rag_service: str,
    guard_url: str,
    model_url: str,
    signing_key: Path,
    key_id: str,
    gateway_image: str,
    model_provider: str,
    model_name: str,
) -> dict[str, object]:
    # Server uses the application_id from the issued, short-lived pairing, not
    # an operator-edited manifest field. Source private key never leaves host.
    return {
        "tenant_id": pairing.get("organization_id") or pairing["application_id"],
        "application_id": pairing["application_id"],
        "rag_service": rag_service,
        "guard_url": guard_url,
        "model_url": model_url,
        "model_provider": model_provider,
        "model_name": model_name,
        "trusted_public_keys": {key_id: public_key_from_private(signing_key)},
        "gateway_image": gateway_image,
    }


def inspect_supported_rag(compose: Path, service: str | None) -> str:
    """Reject unsupported RAGs before asking for signing keys or model URLs.

    Compose config inspection is read-only; a matching label is never proof
    that provenance, cache return paths or traffic cutover are safe.
    """
    if not compose.is_file() or compose.is_symlink():
        raise ConnectError("Select an existing, regular Docker Compose file on this host.")
    resolved = _resolved_compose(compose.resolve())
    services = resolved.get("services", {})
    if not isinstance(services, dict):
        raise ConnectError("Invalid Docker Compose service configuration.")
    if service is None:
        candidates = [
            name
            for name, spec in services.items()
            if isinstance(spec, dict)
            and all(_labels(spec.get("labels")).get(k) == v for k, v in REQUIRED_LABELS.items())
        ]
        if len(candidates) == 1:
            service = candidates[0]
        elif "rag" in services:
            service = "rag"
        else:
            service = _prompt(None, "Name of your Docker Compose RAG service")
    config = services.get(service)
    if not isinstance(config, dict):
        raise ConnectError(f"RAG service {service!r} does not exist in the provided Compose file.")
    labels = _labels(config.get("labels"))
    if any(labels.get(key) != value for key, value in REQUIRED_LABELS.items()):
        raise ConnectError(
            "RAG_ADAPTER_REQUIRED: Your application does not yet use the supported "
            "signed-retrieval + buffered-output AccessProof adapter. "
            "Do not add labels alone: the actual route and cache enforcement "
            "must first be integrated and independently tested. "
            "No signing key was accessed and no traffic was changed."
        )
    return service


def verify_and_prepare_gateway_runtime(image: str) -> None:
    """Load the bundled, hash-pinned Gateway runtime after safe preflight.

    Never fetch executable images from arbitrary URLs or silently overwrite
    another installed image. This operation requires --approve-install.
    """
    root = Path(__file__).resolve().parents[3]
    manifest_path = root / "runtime-release.json"
    archive_path = root / "accessproof-gateway-runtime.tar.gz"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise ConnectError("Missing official Gateway runtime manifest from the setup bundle.")
    release = json.loads(manifest_path.read_text())
    if (
        release.get("schema") != "accessproof.gateway_runtime/v1"
        or not isinstance(release.get("image_id"), str)
        or not isinstance(release.get("archive_sha256"), str)
        or image != release.get("image")
    ):
        raise ConnectError("Unrecognized or mismatched Gateway image in installer bundle.")
    inspect = subprocess.run(
        ["docker", "image", "inspect", image, "--format", "{{.Id}}"],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    if inspect.returncode == 0:
        if inspect.stdout.strip() != release["image_id"]:
            raise ConnectError(
                "An unexpected Gateway image already uses this version. Review before replacing it."
            )
        print("Verified existing AccessProof Gateway runtime image.")
        return
    if not archive_path.is_file() or archive_path.is_symlink():
        raise ConnectError("Missing official Gateway runtime from the installer ZIP.")
    checksum = hashlib.sha256()
    with archive_path.open("rb") as archive:
        for chunk in iter(lambda: archive.read(1024 * 1024), b""):
            checksum.update(chunk)
    if checksum.hexdigest() != release["archive_sha256"]:
        raise ConnectError("Gateway runtime archive checksum mismatch; discard this download.")
    # Only the private approved customer host executes docker load; the SaaS
    # control plane has no Docker socket access or host installation rights.
    loaded = subprocess.run(
        ["docker", "load", "--input", str(archive_path)],
        check=False,
        capture_output=True,
        text=True,
        timeout=180,
    )
    if loaded.returncode != 0:
        raise ConnectError("Unable to import the approved Gateway runtime image.")
    installed = subprocess.run(
        ["docker", "image", "inspect", image, "--format", "{{.Id}}"],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    if installed.returncode != 0 or installed.stdout.strip() != release["image_id"]:
        raise ConnectError("Installed Gateway runtime image does not match the approved release.")
    print("Official AccessProof Gateway runtime imported and verified.")


def report_claim(pairing: dict[str, str], manifest: dict[str, object]) -> dict[str, object]:
    url = pairing["control_plane_url"].rstrip("/") + "/api/v1/gateway-pairings/claim"
    with httpx.Client(timeout=15, follow_redirects=False, trust_env=False) as http:
        response = http.post(
            url, json=manifest, headers={"Authorization": "Bearer " + pairing["pairing_token"]}
        )
    if response.status_code != 202:
        raise ConnectError(
            f"Control plane did not accept the installation report (HTTP {response.status_code}). No protection was activated."
        )
    payload = response.json()
    if not isinstance(payload, dict):
        raise ConnectError("Control plane returned an invalid installation response.")
    if payload.get("state") != "installation_reported_unverified":
        raise ConnectError("Control plane did not acknowledge unverified installation.")
    return payload


def summarize_automatic_verification(claim: dict[str, object]) -> list[str]:
    """Present server-calculated facts; NEVER treat a pairing claim as Protect."""
    report = claim.get("verification")
    if not isinstance(report, dict):
        return ["Cloud security checks: unavailable. Refresh the onboarding dashboard.",
                "Protect is NOT certified or active."]
    state = report.get("state")
    checked = report.get("checks_passed")
    total = report.get("checks_total")
    failures = report.get("failed_check_codes")
    if (state not in {"action_required", "checks_passed_requires_independent_review",
                      "verification_unavailable"}
            or type(checked) is not int or type(total) is not int
            or not 0 <= checked <= total <= 100
            or not isinstance(failures, list)
            or len(failures) > 100
            or any(not isinstance(code, str) or not code
                   or len(code) > 90 or not code.replace("_", "").isalnum()
                   for code in failures)
            or report.get("production_certification") is not False
            or report.get("protect_activated") is not False
            or (state == "checks_passed_requires_independent_review" and failures)):
        return ["Cloud security results: INVALID or unavailable; fail closed.",
                "Protect is NOT certified or active."]
    lines = [f"Automatic cloud security preflight: {checked}/{total} checks passed."]
    for code in failures[:15]:
        lines.append("  - Needs verification: " + code)
    if len(failures) > 15:
        lines.append("  - Additional checks available in AccessProof dashboard.")
    lines.append("Protect is NOT certified or active. Independent Guard evidence and approved cutover still required.")
    return lines


def _prompt(value: str | None, message: str) -> str:
    if value:
        return value
    if not sys.stdin.isatty():
        raise ConnectError(f"Missing configuration: {message}")
    entered = input(message + ": ").strip()
    if not entered:
        raise ConnectError(f"Missing configuration: {message}")
    return entered


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Connect a compatible Docker RAG to AccessProof in one guided flow"
    )
    p.add_argument("--pairing-file", type=Path)
    p.add_argument(
        "--discover", action="store_true",
        help="Read-only local Docker discovery; does not pair, install, or modify any service",
    )
    p.add_argument(
        "--plan", action="store_true",
        help="Create a read-only Gateway plan for explicit discovered application IDs",
    )
    p.add_argument(
        "--select", action="append", default=[], metavar="DISCOVERED_ID",
        help="Application stable ID to include in --plan; repeat for each selected RAG",
    )
    p.add_argument("--compose", type=Path, help="Your RAG Compose file (auto-detected when omitted)")
    p.add_argument("--auto-detect", action="store_true", help="Detect running RAG and any installed Gateway")
    p.add_argument("--adopt-existing", action="store_true", help="Pair an already-installed official Gateway without reinstalling")
    p.add_argument("--gateway-container", help="Explicit existing Gateway container name when multiple exist")
    p.add_argument("--output", type=Path, default=Path(".accessproof-gateway"))
    p.add_argument("--rag-service")
    p.add_argument("--guard-url")
    p.add_argument("--model-url")
    p.add_argument("--ingestion-signing-key", type=Path)
    p.add_argument("--ingestion-key-id", default="customer-ingestion")
    p.add_argument("--gateway-image", default="accessproof-gateway:customer-v3-20261031-r1")
    p.add_argument("--model-provider", default="openai-compatible")
    p.add_argument("--model-name", default="")
    p.add_argument("--approve-install", action="store_true")
    p.add_argument(
        "--challenge-file",
        type=Path,
        help="Run independent Guard reference challenge after installation",
    )
    p.add_argument(
        "--guard-credentials", type=Path, help="Private enrolled Guard machine credential file"
    )
    args = p.parse_args(argv)
    try:
        if args.discover or args.plan:
            if any((args.approve_install, args.adopt_existing, args.challenge_file, args.pairing_file)):
                raise ConnectError("--discover/--plan are read-only and cannot be combined with installation, pairing, or verification options.")
            if args.discover and args.plan:
                raise ConnectError("Choose --discover to list applications or --plan with one or more --select IDs.")
            rows = docker_inventory()
            applications = discover(rows)
            if args.plan:
                planned = plan_selection(applications, args.select, occupied_ports=published_host_ports(rows))
                print(json.dumps({
                    "schema": "accessproof.host_installation_plan/v1",
                    "certification_status": "NOT_CERTIFIED",
                    "applications": [item.__dict__ for item in planned],
                    "notice": "Plan only. No containers, Compose files, routes, pairings, or protections were changed.",
                }, sort_keys=True))
                return 0
            print(json.dumps({
                "schema": "accessproof.host_discovery/v1",
                "certification_status": "NOT_CERTIFIED",
                "applications": [entry.as_dict() for entry in applications],
                "notice": "Discovery is read-only. Select applications explicitly before any compatibility plan or installation.",
            }, sort_keys=True))
            return 0
        if args.challenge_file:
            if args.compose is None:
                raise ConnectError("A Compose file is required for security challenges; pass --compose /path/to/docker-compose.yml")
            if not args.guard_credentials:
                raise ConnectError(
                    "A private enrolled Guard credentials file is required for verification."
                )
            # Stage metadata, source public keys and exact route binding are
            # retained locally; the pairing token is NOT needed for checks.
            spec_path = args.output / "approved-spec.json"
            result = run_wizard(
                mode="verify",
                spec_path=spec_path,
                compose=args.compose,
                output=args.output,
                challenge_path=args.challenge_file,
                machine_path=args.guard_credentials,
            )
            print("Independent reference test status:", result["state"])
            print("Protect is NOT active unless the control plane confirms every security check.")
            return 0
        if args.pairing_file is None:
            raise ConnectError(
                "Download the short-lived pairing file from your AccessProof setup page first."
            )
        pairing = load_pairing(args.pairing_file)
        if args.auto_detect or args.adopt_existing:
            from apps.gateway.accessproof_gateway.existing_gateway import (
                detect, ExistingGatewayError,
            )
            try:
                existing = detect(pairing, container_name=args.gateway_container)
            except ExistingGatewayError as exc:
                raise ConnectError(str(exc)) from exc
            if existing is not None:
                if not args.approve_install:
                    print("Matching existing Gateway verified. No installation or pairing requested.")
                    print("Rerun with --approve-install to report this existing installation.")
                    return 0
                claim = report_claim(pairing, existing)
                print("Existing Gateway paired:", claim["state"])
                print("No Docker containers or RAG routes changed.")
                for message in summarize_automatic_verification(claim):
                    print(message)
                return 0
            if args.adopt_existing:
                raise ConnectError("No existing healthy Gateway matches this application. Use --auto-detect from your RAG project folder.")
        if args.compose is None and args.auto_detect:
            base = Path(os.getenv("ACCESSPROOF_RAG_WORKDIR") or os.getcwd())
            names = ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml")
            found = [base / name for name in names if (base / name).is_file()]
            if len(found) != 1:
                raise ConnectError("Could not identify one RAG Compose file. Run the command from your RAG project folder, or pass --compose /your/real/docker-compose.yml")
            args.compose = found[0]
            print("Detected RAG Compose file:", args.compose)
        if args.compose is None:
            raise ConnectError("Run from your RAG project with --auto-detect, or provide --compose /your/real/docker-compose.yml")
        rag_service = inspect_supported_rag(args.compose, args.rag_service)
        source_key = args.ingestion_signing_key or Path(
            _prompt(None, "Path to existing private ingestion Ed25519 key")
        )
        spec = create_spec(
            pairing,
            rag_service=rag_service,
            guard_url=_prompt(args.guard_url, "Guard URL inside Docker"),
            model_url=_prompt(args.model_url, "Model API URL inside Docker"),
            signing_key=source_key,
            key_id=args.ingestion_key_id,
            gateway_image=args.gateway_image,
            model_provider=args.model_provider,
            model_name=args.model_name,
        )
        # A transient mode-0600 spec replaces manually editing JSON files.
        from tempfile import TemporaryDirectory

        with TemporaryDirectory(prefix="accessproof-setup-") as folder:
            spec_path = Path(folder) / "spec.json"
            fd = os.open(spec_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "w") as stream:
                json.dump(spec, stream)
            preview = run_wizard(
                mode="plan", spec_path=spec_path, compose=args.compose, output=args.output
            )
            blockers = preview.get("blocking_issues", [])
            if blockers:
                print("This RAG requires changes before safe Gateway installation:")
                for issue in blockers:
                    print(" -", issue)
                print(
                    "No files installed; existing RAG traffic unchanged. Review advanced compatibility requirements."
                )
                return 2
            if not args.approve_install:
                print("Compatibility preview passed; installation not started.")
                print(
                    "Rerun with --approve-install after reviewing the selected Compose deployment."
                )
                return 0
            verify_and_prepare_gateway_runtime(args.gateway_image)
            result = run_wizard(
                mode="install",
                spec_path=spec_path,
                compose=args.compose,
                output=args.output,
                approve_gateway_install=True,
            )
        # Keep a private copy of the public installation *specification* for
        # a later operator-approved enrolled Guard challenge. Never export the
        # private source-signing key, model token, or employee test tokens.
        approved_spec = Path(result["installation"]).parent / "approved-spec.json"
        fd = os.open(approved_spec, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(spec, stream, indent=2)
        manifest = read_private_json(Path(result["installation"]))
        claim = report_claim(pairing, manifest)
        print("Gateway installed and paired:", claim["state"])
        for message in summarize_automatic_verification(claim):
            print(message)
        print("No RAG route cutover has occurred.")
        return 0
    except (ConnectError, DiscoveryError, SelectionPlanError, IntegrationWizardError, ValueError, OSError, KeyError) as exc:
        guidance = {
            "SUPPORTED_RAG_CONTRACT_REQUIRED": (
                "The RAG has not implemented AccessProof's signed retrieval and "
                "buffered Layer 2 contract. A verified adapter is required; "
                "adding labels alone would not make it safe."
            ),
            "INTEGRATION_PREFLIGHT_NOT_SUPPORTED": (
                "The RAG has unsafe or unknown cache, model-egress, identity "
                "or networking paths. Ask the application owner to review the "
                "compatibility report and install the supported route adapter."
            ),
            "STAGED_INSTALLATION_UNSAFE": "Review or remove the old staging folder; it will never be overwritten automatically.",
        }
        code = str(exc)
        print("AccessProof setup stopped safely:", guidance.get(code, code), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
