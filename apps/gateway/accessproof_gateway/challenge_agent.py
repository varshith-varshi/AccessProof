"""Read-only, customer-run HTTP byte observer for a supported Gateway route.

This is a diagnostic component, NOT a customer Protect certificate. The
control-plane still requires enrolled-machine evidence of actual authorization,
source freshness, alternate-route coverage and Guard acknowledgement.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx


class RouteChallengeError(ValueError):
    """The actual HTTP response violated a configured security challenge."""


@dataclass(frozen=True)
class Probe:
    name: str
    employee_token: str
    retrieved_resources: list[dict[str, Any]]
    expect_status: tuple[int, ...]
    must_contain: str = ""


@dataclass(frozen=True)
class GatewayRouteChallenge:
    url: str
    application_id: str
    challenge_nonce: str
    forbidden_canary: str
    allowed_canary: str
    probes: tuple[Probe, ...]
    max_response_bytes: int = 1_000_000

    def __post_init__(self) -> None:
        parsed = urlsplit(self.url)
        if (parsed.scheme != "http" or parsed.username or parsed.password or parsed.query
                or parsed.fragment or parsed.path != "/v1/chat/completions"):
            raise RouteChallengeError("Local reference challenge requires an explicit loopback Gateway route")
        try:
            if not ipaddress.ip_address(parsed.hostname or "").is_loopback:
                raise RouteChallengeError("Local reference challenges may only contact loopback")
        except ValueError as exc:
            raise RouteChallengeError("Local reference challenges may only contact loopback") from exc
        if (len(self.challenge_nonce) < 32 or not self.application_id
                or not self.forbidden_canary or not self.allowed_canary
                or self.forbidden_canary == self.allowed_canary
                or not 1 <= self.max_response_bytes <= 4_000_000):
            raise RouteChallengeError("Invalid route challenge configuration")
        names = {probe.name for probe in self.probes}
        if names != {"allow", "deny", "tamper", "layer2_revoke"} or len(self.probes) != 4:
            raise RouteChallengeError("Allow, deny, tamper and Layer 2 revocation cases are mandatory")
        if any(not probe.employee_token or not probe.retrieved_resources for probe in self.probes):
            raise RouteChallengeError("Authenticated synthetic test identities and signed resources are required")
        # Validate the exact reference-route failure, not just a convenient
        # HTTP 503. "Everything unavailable" is NOT a successful security test.
        required_status = {
            "allow": (200,), "deny": (403,),
            "tamper": (503,), "layer2_revoke": (403,),
        }
        if any(probe.expect_status != required_status[probe.name] for probe in self.probes):
            raise RouteChallengeError("Reference challenge requires exact outcome status codes")

    def run(self, client: httpx.Client | None = None) -> dict[str, Any]:
        """Read every response byte, require negative canaries to be absent.

        All cases are sent to the actual HTTP endpoint; caller must arrange
        the synthetic source ACL/revocation transition before layer2_revoke.
        A 503 alone cannot prove an ACL denial, so the output is diagnostic.
        """
        own_client = client is None
        if client is None:
            client = httpx.Client(timeout=12, follow_redirects=False, trust_env=False)
        else:
            actual = urlsplit(str(client.base_url).rstrip("/"))
            target = urlsplit(self.url)
            if (actual.scheme, actual.hostname, actual.port) != (target.scheme, target.hostname, target.port):
                raise RouteChallengeError("Probe client origin does not match the configured Gateway")
        results: list[dict[str, Any]] = []
        try:
            ready_url = self.url.rsplit("/v1/chat/completions", 1)[0] + "/health/ready"
            if client.get(ready_url).status_code != 200:
                raise RouteChallengeError("Gateway and Guard are not ready for security probes")
            for probe in self.probes:
                request_id = f"ap-challenge-{hashlib.sha256(self.challenge_nonce.encode()).hexdigest()[:24]}-{probe.name}"
                with client.stream(
                    "POST", self.url, follow_redirects=False,
                    headers={"Authorization": f"Bearer {probe.employee_token}"},
                    json={"application_id": self.application_id,
                          "employee_question": f"Approved test-only security challenge: {probe.name}.",
                          "retrieved_resources": probe.retrieved_resources,
                          "request_id": request_id},
                ) as response:
                    count = 0
                    parts: list[bytes] = []
                    for part in response.iter_bytes():
                        count += len(part)
                        if count > self.max_response_bytes:
                            raise RouteChallengeError("Actual HTTP response exceeded the challenge buffer")
                        parts.append(part)
                    body = b"".join(parts)
                    if response.status_code not in probe.expect_status:
                        raise RouteChallengeError(f"{probe.name} returned unexpected status {response.status_code}")
                    try:
                        result_json = json.loads(body)
                    except (ValueError, UnicodeDecodeError) as exc:
                        raise RouteChallengeError(f"{probe.name} returned malformed JSON") from exc
                    if not isinstance(result_json, dict):
                        raise RouteChallengeError(f"{probe.name} returned an invalid response object")
                    if probe.name != "allow":
                        expected_reasons = {
                            "deny": "NO_AUTHORIZED_RESOURCES",
                            "tamper": "SOURCE_CONTENT_ATTESTATION_FAILED",
                            "layer2_revoke": "LAYER2_ACCESS_REVOKED",
                        }
                        detail = result_json.get("detail")
                        reason = detail.get("code") if isinstance(detail, dict) else None
                        if reason != expected_reasons[probe.name]:
                            raise RouteChallengeError(f"{probe.name} has no verified refusal reason")
                    else:
                        if result_json.get("accessproof", {}).get("decision") != "allow":
                            raise RouteChallengeError("Allowed response lacks confirmed Protect decision")
                    # Decode JSON escapes, not just raw transport bytes:
                    # forbidden canaries may be represented as escaped strings.
                    try:
                        decoded = json.dumps(json.loads(body), ensure_ascii=False) if body else ""
                    except (ValueError, UnicodeDecodeError):
                        decoded = body.decode("utf-8", errors="replace")
                    if self.forbidden_canary in decoded or self.forbidden_canary.encode() in body:
                        raise RouteChallengeError(f"{probe.name} released unauthorized canary bytes")
                    if probe.name != "allow" and (
                        self.allowed_canary in decoded or self.allowed_canary.encode() in body
                    ):
                        raise RouteChallengeError(f"{probe.name} leaked the authorized-answer canary")
                    if probe.must_contain and probe.must_contain not in decoded:
                        raise RouteChallengeError(f"{probe.name} positive control was not observed")
                    if probe.name == "allow":
                        try:
                            metadata = json.loads(body)["accessproof"]
                            if (metadata.get("decision") != "allow"
                                    or not isinstance(metadata.get("decision_id"), str)
                                    or not metadata["decision_id"]):
                                raise ValueError("missing Guard decision")
                        except (ValueError, KeyError, TypeError):
                            raise RouteChallengeError("Positive control lacks Gateway/Guard decision evidence") from None
                    detail = result_json.get("detail")
                    results.append({
                        "name": probe.name, "request_id": request_id,
                        "http_status": response.status_code,
                        "response_sha256": hashlib.sha256(body).hexdigest(),
                        "response_byte_count": len(body),
                        "forbidden_content_observed": False,
                        "reason_code": detail.get("code") if isinstance(detail, dict) else None,
                        "decision": result_json.get("accessproof", {}).get("decision")
                        if isinstance(result_json.get("accessproof"), dict) else None,
                        "decision_id": result_json.get("accessproof", {}).get("decision_id")
                        if isinstance(result_json.get("accessproof"), dict) else None,
                    })
            if client.get(ready_url).status_code != 200:
                raise RouteChallengeError("Gateway/Guard readiness was lost during security probes")
        finally:
            if own_client:
                client.close()
        return {
            "status": "PASS_LOCAL_REFERENCE_ONLY",
            "real_http_bytes_observed": True,
            "production_certification": False,
            "complete_customer_rag_route_certification": False,
            "challenge_nonce_sha256": hashlib.sha256(self.challenge_nonce.encode()).hexdigest(),
            "route_sha256": hashlib.sha256(self.url.encode()).hexdigest(),
            "probes": results,
        }
