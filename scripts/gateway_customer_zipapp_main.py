"""One-command customer installer, executed directly from the downloaded ZIP.

Customer runs: python3 ~/Downloads/accessproof-gateway-connector.zip
No credentials are embedded in the archive. Only customer-owned local Docker
is inspected; Protect is never activated without independent checks.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath


def fail(message: str) -> None:
    print("AccessProof setup stopped safely:", message, file=sys.stderr)
    raise SystemExit(2)



def verify_cached_payload(bundle: Path, destination: Path) -> None:
    """Never execute a cached extraction that differs from its downloaded ZIP.

    The archive itself comes from an authenticated HTTPS download. An attacker
    or an interrupted prior run must not silently replace one of its scripts.
    """
    expected_root = PurePosixPath("accessproof-gateway-connector")
    with zipfile.ZipFile(bundle) as archive:
        entries = archive.infolist()
        if len(entries) > 500 or sum(i.file_size for i in entries) > 500 * 1024 * 1024:
            fail("Installer archive exceeds safe extraction limits.")
        for item in entries:
            name = PurePosixPath(item.filename)
            if (name.is_absolute() or ".." in name.parts or not name.parts
                    or stat.S_ISLNK(item.external_attr >> 16)):
                fail("Installer archive contains an unsafe path.")
            if item.filename == "__main__.py":
                continue
            if not name.is_relative_to(expected_root):
                fail("Installer archive contains an unexpected path.")
            relative = name.relative_to(expected_root)
            target = destination.joinpath(*relative.parts)
            if not relative.parts or item.is_dir():
                if not target.is_dir() or target.is_symlink():
                    fail("Cached installer directory has been modified.")
                continue
            if (target.is_symlink() or not target.is_file()
                    or any(parent.is_symlink() for parent in target.parents
                           if parent == destination or destination in parent.parents)):
                fail("Cached installer has an unsafe file or directory.")
            if target.stat().st_size != item.file_size:
                fail("Cached installer files differ from the downloaded ZIP.")
            with archive.open(item) as expected, target.open("rb") as actual:
                while True:
                    chunk = expected.read(1024 * 1024)
                    if not chunk:
                        if actual.read(1):
                            fail("Cached installer contains extra bytes.")
                        break
                    if actual.read(len(chunk)) != chunk:
                        fail("Cached installer files differ from the downloaded ZIP.")


def diagnose_local_gateway(*, project: str, gateway_container: str | None = None) -> tuple[bool, list[str]]:
    """Read-only, no pairing token, no Protect mutation. Host-local signals only."""
    import json
    import http.client

    notes: list[str] = []
    try:
        proc = subprocess.run(
            ["docker", "ps", "--format", "{{json .}}"],
            capture_output=True, check=True, text=True, timeout=8,
        )
        rows = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
    except (OSError, subprocess.SubprocessError, ValueError):
        return False, ["Docker is unavailable. Start Docker and check your local access permissions."]
    candidates = [
        row for row in rows
        if "accessproof-gateway" in str(row.get("Names", ""))
        and (gateway_container and row.get("Names") == gateway_container
             or not gateway_container and (
                 str(row.get("Names", "")).startswith(project + "-")
                 or str(row.get("Names", "")) == project + "_accessproof-gateway_1"
             ))
    ]
    if len(candidates) != 1:
        notes.append(
            "Gateway: no unique running Gateway found for this RAG project. "
            "Run from its Docker Compose directory or choose --gateway-container NAME."
        )
    else:
        row = candidates[0]
        # This is a *liveness* signal, not attested route verification.
        state = str(row.get("Status", "")).lower()
        if "(healthy)" in state:
            notes.append("Gateway: running and Docker reports healthy (not a Protect certificate).")
        else:
            notes.append("Gateway: not healthy; inspect the customer Gateway container.")
    try:
        connection = http.client.HTTPConnection("127.0.0.1", 8080, timeout=4)
        connection.request("GET", "/health")
        response = connection.getresponse()
        body = response.read(8193)
        connection.close()
        if response.status != 200 or len(body) > 8192:
            raise ValueError("Guard readiness response invalid")
        health = json.loads(body)
    except (OSError, ValueError, KeyError):
        notes.append("Guard: cannot get local readiness from 127.0.0.1:8080/health. Check Guard installation.")
    else:
        if health.get("ready") is True and health.get("status") == "ok":
            notes.append("Guard: ready (current policy, source health and bound applications).")
        elif health.get("policy_fresh") is False:
            notes.append("Guard: source policy stale. Restore Guard synchronization and check the source connection.")
        elif health.get("sync_error"):
            notes.append("Guard: sync failed; inspect Guard sync diagnostics.")
        else:
            notes.append(
                "Guard: NOT READY despite its policy version. Check source ACL certification, "
                "bound applications, and cloud readiness checks; do not bypass this condition."
            )
    ready = len(candidates) == 1 and "(healthy)" in str(candidates[0].get("Status", "")).lower() \
        and any(note.startswith("Guard: ready") for note in notes)
    return ready, notes


def run_doctor(*, gateway_container: str | None = None) -> int:
    ready, messages = diagnose_local_gateway(
        project=Path.cwd().resolve().name, gateway_container=gateway_container,
    )
    print("AccessProof local preflight (read-only; never activates Protect):")
    for message in messages:
        print("  - " + message)
    print("Cloud provider certification and live employee-route tests are separate checks on the dashboard.")
    return 0 if ready else 2


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Connect your approved Docker RAG to AccessProof in one command"
    )
    parser.add_argument("--check", action="store_true", help="Preview without pairing or installing")
    parser.add_argument("--doctor", action="store_true", help="Check local Guard/Gateway readiness without downloading any pairing or challenge")
    parser.add_argument("--no-auto-verify", action="store_true",
                        help="Skip automatic local post-install preflight (troubleshooting only; never certifies Protect)")
    parser.add_argument("--challenge-file", type=Path, help="Check prerequisites for the downloaded Guard security challenge")
    parser.add_argument("--guard-credentials", type=Path, help="Matching enrolled Guard machine credential JSON, mode 0600")
    parser.add_argument("--pairing-file", type=Path, default=Path.home() / "Downloads" / "accessproof-gateway-pairing.json")
    parser.add_argument("--compose", type=Path, help="Explicit Compose file (if multiple or not in project folder)")
    parser.add_argument("--gateway-container", help="Explicit existing Gateway container for a multi-project host")
    args = parser.parse_args()
    if sys.version_info < (3, 11):
        fail("Python 3.11+ is required.")
    if args.doctor:
        if args.check or args.challenge_file:
            fail("Choose --doctor OR --check/--challenge-file, not both.")
        raise SystemExit(run_doctor(gateway_container=args.gateway_container))
    if args.challenge_file is not None:
        # This diagnostic must not require (or consume) a new pairing token.
        import json
        from datetime import datetime, timezone
        from urllib.error import URLError
        challenge = args.challenge_file.expanduser()
        if challenge.is_symlink() or not challenge.is_file():
            fail("Download a fresh AccessProof security challenge JSON before verifying.")
        if stat.S_IMODE(challenge.stat().st_mode) & 0o077:
            fail("Challenge file must be private. Run: chmod 600 ~/Downloads/accessproof-security-challenge.json")
        try:
            meta = json.loads(challenge.read_text())
            expiry = datetime.fromisoformat(meta["expires_at"].replace("Z", "+00:00"))
        except (ValueError, KeyError, TypeError):
            fail("Challenge JSON is invalid; download a new one from AccessProof.")
        if expiry <= datetime.now(timezone.utc):
            fail("Security challenge has expired; download a fresh one from AccessProof.")
        if "request_ids" in meta and "probes" not in meta:
            fail("This is a server-issued audited challenge, not the legacy four-probe test configuration. The existing-Gateway adoption route needs certified machine/audit submission; local preview alone cannot satisfy Protect. Run --doctor and complete the dashboard's source/identity prerequisites first.")
        try:
            import urllib.request
            with urllib.request.urlopen("http://127.0.0.1:8080/health", timeout=4) as response:
                health = json.load(response)
        except (OSError, URLError, ValueError):
            fail("Cannot reach local Guard health endpoint at 127.0.0.1:8080. Verify the enrolled Guard is running on the approved host.")
        if health.get("ready") is not True or health.get("status") != "ok":
            fail("Guard is not ready. In particular, ACL/source health or bound application readiness may still be failing. Check source synchronization and Guard /health; do not bypass this gate.")
        if args.guard_credentials is None:
            fail("Security verification requires the *matching enrolled Guard machine credentials* (0600). The installer cannot use a pairing key or credentials from another Guard. Pass --guard-credentials /your/private/enrolled-guard.json once available.")
        machine_file = args.guard_credentials.expanduser()
        if (machine_file.is_symlink() or not machine_file.is_file()
                or stat.S_IMODE(machine_file.stat().st_mode) & 0o077):
            fail("Guard credential JSON is missing or not private 0600.")
        try:
            machine = json.loads(machine_file.read_text())
        except (OSError, ValueError):
            fail("Guard credential file is not valid JSON.")
        if machine.get("guard_id") != meta.get("guard_id"):
            fail("Guard credential does not belong to the Guard selected for this challenge. Use the enrolled credentials for this application.")
        # Existing-Gateway adoption is a pairing report, not a verified staged
        # deployment. Never fabricate installation.json or signed route evidence.
        output = Path.cwd() / ".accessproof-gateway"
        if not (output / "approved-spec.json").is_file() or not (output / "installation.json").is_file():
            fail("Existing Gateway is paired but has no independently verified staged installation. Security challenge cannot be submitted by the legacy verifier. A certified adoption workflow is required; no Protect activation occurred.")
        if args.compose is None or not args.compose.expanduser().is_file():
            fail("Specify the verified, existing Docker Compose file with --compose /actual/path/to/docker-compose.yml")
        connector = Path.home() / "accessproof-setup/accessproof-gateway-connector/connect.sh"
        if not connector.is_file():
            fail("Gateway verifier script was not found; use the official verified customer connector bundle.")
        command = ["bash", str(connector), "--compose", str(args.compose.expanduser()),
                   "--challenge-file", str(challenge), "--guard-credentials", str(machine_file)]
        raise SystemExit(subprocess.call(command))
    pairing = args.pairing_file.expanduser().resolve(strict=False)
    if args.pairing_file.is_symlink() or not pairing.is_file():
        fail("Download your private pairing key from the AccessProof setup page.")
    if pairing.stat().st_uid != os.getuid():
        fail("Your pairing key must be owned by the current user.")
    if stat.S_IMODE(pairing.stat().st_mode) & 0o077:
        pairing.chmod(0o600)
    if shutil.which("docker") is None:
        fail("Docker is not installed on this RAG host.")
    compose_check = subprocess.run(
        ["docker", "compose", "version"], capture_output=True, timeout=10,
    )
    if compose_check.returncode != 0:
        fail("Docker Compose v2 is required.")
    bundle = Path(sys.argv[0]).expanduser().resolve()
    if not bundle.is_file() or bundle.is_symlink():
        fail("The downloaded installer ZIP could not be found.")
    with bundle.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    # Cache extracted runtime per immutable archive hash; do not overwrite an
    # existing customer's Gateway configuration or alter their RAG project.
    root = Path.home() / ".local" / "share" / "accessproof"
    if root.is_symlink():
        fail("Unsafe setup directory symlink.")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    root.chmod(0o700)
    dest = root / ("gateway-connector-" + digest[:20])
    if dest.is_symlink():
        fail("Unsafe existing installer directory symlink.")
    if not dest.exists():
        temp = Path(tempfile.mkdtemp(prefix=".gateway-", dir=root))
        try:
            with zipfile.ZipFile(bundle) as archive:
                items = archive.infolist()
                if len(items) > 500 or sum(i.file_size for i in items) > 500 * 1024 * 1024:
                    fail("Installer archive exceeds safe extraction limits.")
                for item in items:
                    name = PurePosixPath(item.filename)
                    if (name.is_absolute() or ".." in name.parts or not name.parts
                            or (name.parts[0] != "accessproof-gateway-connector"
                                and item.filename != "__main__.py")
                            or stat.S_ISLNK(item.external_attr >> 16)):
                        fail("Installer archive contains an unsafe path.")
                archive.extractall(temp)
            extracted = temp / "accessproof-gateway-connector"
            if not (extracted / "connect.sh").is_file():
                fail("The ZIP does not contain the official Gateway connector.")
            extracted.rename(dest)
        finally:
            shutil.rmtree(temp, ignore_errors=True)
    # Revalidate every packaged file even when the same archive was installed
    # previously. Unverified local caches are never executable code.
    verify_cached_payload(bundle, dest)
    connector = dest / "connect.sh"
    if not connector.is_file() or connector.is_symlink():
        fail("The cached installer is incomplete or unsafe.")
    command = [
        "bash", str(connector),
        "--pairing-file", str(pairing),
        "--auto-detect",
    ]
    if not args.check:
        command.append("--approve-install")
    if args.compose:
        command.extend(("--compose", str(args.compose.expanduser().resolve())))
    if args.gateway_container:
        command.extend(("--gateway-container", args.gateway_container))
    environment = os.environ.copy()
    environment["ACCESSPROOF_RAG_WORKDIR"] = str(Path.cwd())
    print("AccessProof: detecting your RAG and existing Gateway...", flush=True)
    installed = subprocess.call(command, env=environment)
    if installed != 0 or args.check:
        raise SystemExit(installed)
    if not args.no_auto_verify:
        print("\nAccessProof: automatically checking Gateway and Guard readiness...", flush=True)
        ready, notes = diagnose_local_gateway(
            project=Path.cwd().resolve().name,
            gateway_container=args.gateway_container,
        )
        for note in notes:
            print("  - " + note, flush=True)
        if not ready:
            print(
                "Automatic local preflight requires attention. Gateway pairing remains "
                "reported but Protect is NOT certified; no employee traffic was changed.",
                flush=True,
            )
        else:
            print(
                "Local preflight passed. Independent live source permissions, "
                "Guard challenge and customer-approved cutover remain separate gates.",
                flush=True,
            )
    print("Security verification progress refreshes automatically in the AccessProof dashboard.", flush=True)
    raise SystemExit(0)


if __name__ == "__main__":
    main()
