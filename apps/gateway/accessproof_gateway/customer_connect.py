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
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from apps.gateway.accessproof_gateway.challenge_cli import read_private_json
from apps.gateway.accessproof_gateway.application_discovery import (
    DiscoveryError, compose_for_selected, discover, docker_inventory, published_host_ports,
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
        elif len(candidates) > 1:
            raise ConnectError(
                "Multiple supported chatbots exist in this Compose project. "
                "Choose ONE with --rag-service SERVICE or --select DISCOVERED_ID."
            )
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


def await_dashboard_chatbot(
    pairing: dict[str, str], applications: list[object], *,
    poll_seconds: float = 3.0, max_seconds: float = 660.0,
    client: httpx.Client | None = None,
) -> str:
    """Send only sanitized discovery fields and wait for ONE admin-approved ID.

    The pairing token is application-scoped, short-lived and never printed.
    No cloud endpoint can send Docker commands or enable Protect.
    """
    if not 0.1 <= poll_seconds <= 10 or not 0.1 <= max_seconds <= 720:
        raise ConnectError("Invalid bounded dashboard selection wait")
    available = [
        {"stable_id": x.stable_id, "display_name": x.display_name,
         "compose_project": x.compose_project, "service": x.service,
         "state": x.state}
        for x in applications
        if (x.compose_project and x.service
            and x.state in {"SUPPORTED", "REQUIRES_INTEGRATION", "AMBIGUOUS", "NON_AI_SERVICE"})
    ]
    if not any(x["state"] == "SUPPORTED" for x in available):
        raise ConnectError("No compatible running RAG detected. Complete the Gateway adapter integration first.")
    # Dashboard inventory is intentionally bounded; do not export all Docker
    # metadata, labels, environment, source paths, or document content.
    if len(available) > 32:
        raise ConnectError("More than 32 Docker applications discovered. Reduce scan scope before pairing.")
    base = pairing["control_plane_url"].rstrip("/")
    headers = {"Authorization": "Bearer " + pairing["pairing_token"]}
    own = client is None
    http = client or httpx.Client(timeout=12, follow_redirects=False, trust_env=False)
    try:
        try:
            response = http.post(base + "/api/v1/gateway-pairings/discovery",
                                 json={"applications": available}, headers=headers)
        except httpx.HTTPError as exc:
            raise ConnectError("Cannot publish chatbot inventory; check your API connection.") from exc
        if response.status_code != 200:
            raise ConnectError(f"Dashboard discovery rejected (HTTP {response.status_code}). No installation occurred.")
        print("Chatbots discovered. In AccessProof → Get Started, select ONE chatbot.", flush=True)
        print("Waiting for your dashboard selection. No Docker containers will change until it is received.", flush=True)
        deadline = time.monotonic() + max_seconds
        valid_ids = {x["stable_id"] for x in available if x["state"] == "SUPPORTED"}
        while time.monotonic() < deadline:
            try:
                result = http.get(base + "/api/v1/gateway-pairings/discovery/selection",
                                  headers=headers)
            except httpx.HTTPError as exc:
                raise ConnectError("Cannot check dashboard selection. No installation occurred.") from exc
            if result.status_code != 200:
                raise ConnectError(f"Dashboard selection unavailable (HTTP {result.status_code}). No installation occurred.")
            payload = result.json()
            if payload.get("state") == "selected":
                selected = payload.get("selected_id")
                if not isinstance(selected, str) or selected not in valid_ids:
                    raise ConnectError("Dashboard returned an invalid/unsupported chatbot selection.")
                return selected
            if payload.get("state") not in {"not_ready", "awaiting_selection"}:
                raise ConnectError("Unexpected dashboard selection status.")
            time.sleep(poll_seconds)
        raise ConnectError("Dashboard selection expired. Generate a fresh 15-minute pairing file and retry.")
    finally:
        if own:
            http.close()


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
        help="Read-only plan for exactly one selected discovered chatbot",
    )
    p.add_argument(
        "--select", action="append", default=[], metavar="DISCOVERED_ID",
        help="Select exactly one discovered chatbot to preview or connect",
    )
    p.add_argument("--compose", type=Path, help="Your RAG Compose file (auto-detected when omitted)")
    p.add_argument("--choose-one", action="store_true",
                   help="Legacy terminal selection (advanced mode)")
    p.add_argument("--dashboard-select", action="store_true",
                   help="Publish sanitized local inventory and wait for one dashboard-approved selection")
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
        if args.dashboard_select and (args.select or args.choose_one or args.adopt_existing
                                      or args.compose or args.rag_service):
            raise ConnectError("Dashboard selection cannot be combined with another chatbot selection.")
        if len(args.select) > 1:
            raise ConnectError("Select exactly one chatbot. Other applications must remain untouched.")
        if args.discover or args.plan:
            if (any((args.approve_install, args.adopt_existing, args.challenge_file,
                     args.pairing_file, args.auto_detect, args.choose_one, args.dashboard_select, args.guard_credentials,
                     args.compose, args.gateway_container, args.rag_service, args.guard_url,
                     args.model_url, args.ingestion_signing_key))
                    or (args.discover and args.select)):
                raise ConnectError("--discover/--plan are read-only; do not combine with installation, pairing, or verification.")
            if args.discover and args.plan:
                raise ConnectError("Choose --discover or --plan --select ONE_ID.")
            rows = docker_inventory()
            applications = discover(rows)
            if args.plan:
                planned = plan_selection(applications, args.select, occupied_ports=published_host_ports(rows))
                print(json.dumps({
                    "schema": "accessproof.host_installation_plan/v1",
                    "certification_status": "NOT_CERTIFIED",
                    "applications": [item.__dict__ for item in planned],
                    "notice": "One-chatbot preview only; no routes, pairing or protection changed.",
                }, sort_keys=True))
                return 0
            print(json.dumps({
                "schema": "accessproof.host_discovery/v1",
                "certification_status": "NOT_CERTIFIED",
                "applications": [entry.as_dict() for entry in applications],
                "notice": "Choose ONE supported chatbot. Other services remain untouched.",
            }, sort_keys=True))
            return 0
        if args.challenge_file:
            if args.select or args.choose_one:
                raise ConnectError("Security challenge verification does not select applications; use the approved installed route.")
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
                if args.select:
                    raise ConnectError("An existing Gateway is already paired for this application. Review that Gateway before selecting a different chatbot.")
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
        if args.dashboard_select:
            rows = docker_inventory()
            applications = discover(rows)
            args.select = [await_dashboard_chatbot(pairing, applications)]
        if args.select or (args.choose_one and args.compose is None):
            rows = docker_inventory()
            applications = discover(rows)
            available = [item for item in applications if item.state == "SUPPORTED"]
            if args.select:
                chosen = next((item for item in available if item.stable_id == args.select[0]), None)
                if chosen is None:
                    raise ConnectError("Selected chatbot is no longer a supported running Docker RAG; rediscover and retry.")
            elif len(available) == 1:
                chosen = available[0]
            elif len(available) > 1:
                print("Select ONE compatible chatbot to connect:", flush=True)
                for number, item in enumerate(available, start=1):
                    print(f"  {number}. {item.display_name} (project: {item.compose_project})  [{item.stable_id}]", flush=True)
                if not sys.stdin.isatty():
                    raise ConnectError("Multiple compatible chatbots found. Run --discover, then --select ONE_ID to choose explicitly.")
                entered = input("Chatbot number to connect: ").strip()
                if not entered.isascii() or not entered.isdecimal() or not 1 <= int(entered) <= len(available):
                    raise ConnectError("Choose exactly one valid chatbot number; no changes were made.")
                chosen = available[int(entered) - 1]
            else:
                chosen = None
                if args.select:
                    raise ConnectError("Selected chatbot is unavailable.")
            if chosen is not None:
                # The current product installs ONE standard Gateway on 8090.
                # Do not offer an install if another service already publishes it.
                plan_selection(applications, [chosen.stable_id],
                               occupied_ports=published_host_ports(rows))
                args.compose = compose_for_selected(chosen, rows, explicit_compose=args.compose)
                if args.rag_service and args.rag_service != chosen.service:
                    raise ConnectError("Selected chatbot conflicts with --rag-service.")
                args.rag_service = chosen.service
                print(f"Selected ONE chatbot: {chosen.display_name} (project {chosen.compose_project})", flush=True)
                print("All other discovered services remain unchanged.", flush=True)
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
