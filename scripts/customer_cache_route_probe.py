"""Opt-in loopback test of ONE customer answer-cache return route.

Customer runs this on their approved RAG host, with synthetic employee tokens
and synthetic canaries from a private 0600 JSON config. It warms the cache,
proves a cache hit, then checks the *same answer* is denied to another identity.
It NEVER certifies other routes or makes network requests except to loopback.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

SCHEMA = "accessproof.cache_route_probe/v1"


class CacheRouteProbeError(ValueError):
    pass


def _read_private(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 100_000:
        raise CacheRouteProbeError("PRIVATE_CONFIG_MISSING_OR_UNSAFE")
    if os.name == "posix" and (path.stat().st_mode & 0o077):
        raise CacheRouteProbeError("PRIVATE_CONFIG_PERMISSIONS_TOO_BROAD")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise CacheRouteProbeError("CONFIG_INVALID")
    return data


def _validate(config: dict[str, Any]) -> tuple[str, str, str, str, dict[str, Any], str]:
    expected = {
        "url", "allowed_token", "denied_token", "request_body",
        "allowed_canary", "forbidden_canary", "cache_hit_field",
    }
    if set(config) != expected:
        raise CacheRouteProbeError("CONFIG_FIELDS_INVALID")
    url = config["url"]
    if not isinstance(url, str):
        raise CacheRouteProbeError("LOOPBACK_URL_REQUIRED")
    parsed = urlsplit(url)
    try:
        host = ipaddress.ip_address(parsed.hostname or "")
    except ValueError as exc:
        raise CacheRouteProbeError("LOOPBACK_URL_REQUIRED") from exc
    if (parsed.scheme != "http" or not host.is_loopback or parsed.username
            or parsed.password or parsed.query or parsed.fragment
            or not parsed.path.startswith("/") or parsed.path == "/" or not parsed.port):
        raise CacheRouteProbeError("LOOPBACK_URL_REQUIRED")
    allowed = config["allowed_token"]
    denied = config["denied_token"]
    positive = config["allowed_canary"]
    forbidden = config["forbidden_canary"]
    if (any(not isinstance(value, str) or not 12 <= len(value) <= 16_384
            for value in (allowed, denied, positive, forbidden))
            or allowed == denied or positive == forbidden):
        raise CacheRouteProbeError("SYNTHETIC_PROBES_REQUIRED")
    body = config["request_body"]
    if not isinstance(body, dict) or not body:
        raise CacheRouteProbeError("SYNTHETIC_REQUEST_BODY_REQUIRED")
    field = config["cache_hit_field"]
    if not isinstance(field, str) or not 1 <= len(field) <= 80 or not all(
        part.isidentifier() for part in field.split(".")
    ):
        raise CacheRouteProbeError("CACHE_HIT_FIELD_INVALID")
    return url, allowed, denied, positive, body, field


def _cache_hit(payload: Any, field: str) -> bool:
    node = payload
    for part in field.split("."):
        if not isinstance(node, dict):
            return False
        node = node.get(part)
    return node is True


def probe(config: dict[str, Any], *, client: httpx.Client | None = None) -> dict[str, Any]:
    url, allowed, denied, positive, body, hit_field = _validate(config)
    forbidden = config["forbidden_canary"]
    own = client is None
    if client is None:
        client = httpx.Client(timeout=10, follow_redirects=False, trust_env=False)
    responses: list[dict[str, Any]] = []
    try:
        for name, token, expected in (
            ("warm", allowed, 200), ("hit", allowed, 200),
            ("denied_hit", denied, 403),
        ):
            with client.stream(
                "POST", url, headers={"Authorization": "Bearer " + token},
                json=body, follow_redirects=False,
            ) as response:
                count = 0
                chunks: list[bytes] = []
                for chunk in response.iter_bytes():
                    count += len(chunk)
                    if count > 1_000_000:
                        raise CacheRouteProbeError("RESPONSE_TOO_LARGE")
                    chunks.append(chunk)
                raw = b"".join(chunks)
                try:
                    decoded: Any = json.loads(raw)
                except (UnicodeDecodeError, ValueError) as exc:
                    raise CacheRouteProbeError("INVALID_RESPONSE") from exc
                # Match canary after JSON decoding to rule out escaped-json bypass.
                plaintext = json.dumps(decoded, ensure_ascii=False)
                if response.status_code != expected:
                    raise CacheRouteProbeError("UNEXPECTED_HTTP_RESULT_" + name.upper())
                if forbidden in plaintext or forbidden.encode() in raw:
                    raise CacheRouteProbeError("FORBIDDEN_CONTENT_RELEASED")
                if name == "hit" and not _cache_hit(decoded, hit_field):
                    raise CacheRouteProbeError("CACHE_HIT_NOT_OBSERVED")
                if name == "denied_hit" and (
                    positive in plaintext or positive.encode() in raw
                ):
                    raise CacheRouteProbeError("UNAUTHORIZED_CACHE_ANSWER_RELEASED")
                if name == "warm" and positive not in plaintext:
                    raise CacheRouteProbeError("POSITIVE_CONTROL_NOT_OBSERVED")
                responses.append({
                    "probe": name, "status": response.status_code,
                    "sha256": hashlib.sha256(raw).hexdigest(), "body_bytes": len(raw),
                    "content_released_to_denied_identity": False,
                })
    except httpx.HTTPError as exc:
        raise CacheRouteProbeError("CACHE_PROBE_TRANSPORT_FAILED") from exc
    finally:
        if own:
            client.close()
    return {
        "schema": SCHEMA, "status": "PASS_SINGLE_SYNTHETIC_CACHE_RETURN_ROUTE",
        "cache_hit_observed": True, "unauthorized_cache_return_blocked": True,
        "tested_route_sha256": hashlib.sha256(url.encode()).hexdigest(),
        "observations": responses,
        "certification_status": "NOT_CERTIFIED",
        "scope": "ONE_SYNTHETIC_EMPLOYEE_ROUTE_ONLY",
        "other_cache_and_model_paths_verified": False,
        "live_revocation_timing_verified": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path, help="Private synthetic 0600 JSON config")
    parser.add_argument("--output", required=True, type=Path, help="New private report path")
    args = parser.parse_args(argv)
    try:
        if args.output.is_symlink() or args.output.exists():
            raise CacheRouteProbeError("OUTPUT_EXISTS_OR_UNSAFE")
        result = probe(_read_private(args.config))
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(result, stream, indent=2, sort_keys=True)
            stream.write("\n")
    except (CacheRouteProbeError, OSError, TypeError, KeyError, ValueError):
        print("CACHE_ROUTE_PROBE_FAILED: inspect the private local integration; no certificate issued")
        return 2
    print(json.dumps({
        "status": result["status"], "certification_status": "NOT_CERTIFIED",
        "output": str(args.output),
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
