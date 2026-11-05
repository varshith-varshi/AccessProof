"""Customer-run, loopback-only synthetic reference route diagnostics.

Results are NEVER Protect certificates. The control plane must still receive
and independently verify enrolled-machine source/route/bypass evidence.
Input can contain synthetic bearer credentials and must be stored mode 0600.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
from pathlib import Path
from typing import Any

from .challenge_agent import GatewayRouteChallenge, Probe, RouteChallengeError


def read_private_json(path: Path, *, max_bytes: int = 2_000_000) -> dict[str, Any]:
    try:
        descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            metadata = os.fstat(descriptor)
            if (not stat.S_ISREG(metadata.st_mode)
                    or stat.S_IMODE(metadata.st_mode) & 0o077):
                raise RouteChallengeError("Challenge input must be a private regular file with mode 0600")
            if metadata.st_size < 2 or metadata.st_size > max_bytes:
                raise RouteChallengeError("Challenge configuration size is invalid")
            raw = os.read(descriptor, max_bytes + 1)
            if len(raw) > max_bytes:
                raise RouteChallengeError("Challenge configuration is too large")
        finally:
            os.close(descriptor)
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise RouteChallengeError("Challenge input must contain a JSON object")
        return data
    except RouteChallengeError:
        raise
    except (ValueError, UnicodeDecodeError) as exc:
        raise RouteChallengeError("Invalid challenge configuration") from exc
    except OSError as exc:
        raise RouteChallengeError("Unable to securely open challenge input") from exc


def parse_challenge(data: dict[str, Any]) -> GatewayRouteChallenge:
    supported = {
        "url", "application_id", "challenge_nonce", "forbidden_canary",
        "allowed_canary", "probes", "max_response_bytes", "timeout_seconds",
    }
    if set(data) - supported:
        raise RouteChallengeError("Unsupported challenge configuration fields")
    values = data.get("probes")
    if not isinstance(values, list):
        raise RouteChallengeError("Exactly four synthetic probes are required")
    probes = []
    for value in values:
        if not isinstance(value, dict) or set(value) - {
            "name", "employee_token", "retrieved_resources", "expect_status",
            "must_contain",
        }:
            raise RouteChallengeError("Invalid probe description")
        try:
            if not isinstance(value["expect_status"], list) or not all(
                type(item) is int for item in value["expect_status"]
            ):
                raise RouteChallengeError("Invalid expected HTTP status")
            probes.append(Probe(
                name=value["name"], employee_token=value["employee_token"],
                retrieved_resources=value["retrieved_resources"],
                expect_status=tuple(value["expect_status"]),
                must_contain=value.get("must_contain", ""),
            ))
        except (KeyError, TypeError) as exc:
            raise RouteChallengeError("Incomplete synthetic probe") from exc
    try:
        return GatewayRouteChallenge(
            url=data["url"], application_id=data["application_id"],
            challenge_nonce=data["challenge_nonce"],
            forbidden_canary=data["forbidden_canary"],
            allowed_canary=data["allowed_canary"],
            probes=tuple(probes),
            max_response_bytes=data.get("max_response_bytes", 1_000_000),
            timeout_seconds=float(data.get("timeout_seconds", 12.0)),
        )
    except (KeyError, TypeError) as exc:
        raise RouteChallengeError("Incomplete route challenge") from exc


def merge_issued_challenge(config: dict[str, Any], issued: dict[str, Any]) -> dict[str, Any]:
    """Bind an operator probe config to the control plane's issued challenge.

    The API response (`POST .../protection/challenge`) carries `nonce`, while
    the probe config uses `challenge_nonce`; passing the response directly was
    rejected. Only the nonce and application are taken from it, the config may
    not pre-set a nonce, and an expired or mismatched challenge is refused.
    """
    from datetime import datetime, timezone

    if "challenge_nonce" in config:
        raise RouteChallengeError("Remove challenge_nonce from the config when --challenge is used")
    nonce = issued.get("nonce")
    if issued.get("state", "issued") != "issued" or not isinstance(nonce, str) or not nonce:
        raise RouteChallengeError("Issued challenge is not usable")
    app = issued.get("application_id")
    if not isinstance(app, str) or not app or config.get("application_id", app) != app:
        raise RouteChallengeError("Issued challenge belongs to a different application")
    try:
        expires = datetime.fromisoformat(str(issued["expires_at"]))
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
    except (KeyError, ValueError) as exc:
        raise RouteChallengeError("Issued challenge has no valid expiry") from exc
    if expires <= datetime.now(timezone.utc):
        raise RouteChallengeError("Issued challenge has expired; request a new one")
    return {**config, "application_id": app, "challenge_nonce": nonce}


def write_private_result(path: Path, result: dict[str, Any]) -> None:
    if not path.parent.is_dir():
        raise RouteChallengeError("Challenge output parent directory must exist")
    try:
        descriptor = os.open(
            str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL |
            getattr(os, "O_NOFOLLOW", 0), 0o600,
        )
    except OSError as exc:
        raise RouteChallengeError("Challenge output could not be exclusively created") from exc
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(result, sort_keys=True) + "\n")
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run local-only synthetic RAG Gateway challenges. Never activates Protect.",
    )
    parser.add_argument("--config", required=True, type=Path, help="Mode-0600 private synthetic JSON config")
    parser.add_argument("--output", required=True, type=Path, help="New private diagnostic result filename")
    parser.add_argument("--challenge", type=Path,
                        help="Mode-0600 JSON response saved from the control plane's challenge request")
    args = parser.parse_args()
    try:
        config = read_private_json(args.config)
        if args.challenge is not None:
            config = merge_issued_challenge(config, read_private_json(args.challenge))
        challenge = parse_challenge(config)
        evidence = challenge.run()
        write_private_result(args.output, evidence)
        print(json.dumps({
            "status": evidence["status"], "output": str(args.output),
            "production_certification": False, "probes": len(evidence["probes"]),
        }))
        return 0
    except RouteChallengeError as exc:
        # Refuse to echo user-provided tokens, route bodies, canaries or HTTP
        # error texts. Only emit the known diagnostic failure type.
        print("LOCAL_CHALLENGE_FAILED:", str(exc))
        return 2
    except (OSError, ValueError):
        print("LOCAL_CHALLENGE_FAILED: Local diagnostic could not complete")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
