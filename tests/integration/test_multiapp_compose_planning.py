"""End-to-end *read-only* Docker Compose validation for selected Gateway boundaries.

Requires the local Docker Compose CLI but never starts, stops, or changes a container.
"""
from __future__ import annotations

import base64
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from apps.gateway.accessproof_gateway.installer import InstallationSpec, stage_installation

pytestmark = pytest.mark.skipif(shutil.which("docker") is None, reason="Docker CLI unavailable")


def _spec(service: str, gateway: str, port: int) -> InstallationSpec:
    key = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return InstallationSpec.parse({
        "tenant_id": "approved-test-org", "application_id": "approved-test-" + service,
        "rag_service": service, "gateway_service": gateway, "listen_port": port,
        "guard_url": "http://guard:8080", "model_url": "http://model:8000/v1/chat/completions",
        "trusted_public_keys": {"test-key": base64.urlsafe_b64encode(key).decode().rstrip("=")},
    })


def test_multiapp_overrides_preserve_unselected_service_with_real_compose(tmp_path: Path) -> None:
    customer = tmp_path / "customer-compose.yaml"
    labels = {
        "com.accessproof.gateway.contract": "accessproof.gateway/v1",
        "com.accessproof.gateway.enforces": "attested-retrieval-and-buffered-output",
        "com.accessproof.gateway.route_env": "ACCESSPROOF_CHAT_URL",
    }
    original = {"services": {
        "finance-rag": {"image": "alpine:3", "labels": labels},
        "hr-rag": {"image": "alpine:3", "labels": labels},
        "sales-rag": {"image": "alpine:3", "environment": {"UNRELATED": "preserve"}},
    }}
    customer.write_text(json.dumps(original))
    original_bytes = customer.read_bytes()

    finance = stage_installation(
        _spec("finance-rag", "accessproof-gateway-finance-test", 18090),
        customer, tmp_path / "finance", original,
    )
    hr = stage_installation(
        _spec("hr-rag", "accessproof-gateway-hr-test", 18091),
        customer, tmp_path / "hr", original,
    )
    command = [
        "docker", "compose", "-f", str(customer),
        "-f", finance["override"], "-f", hr["override"],
        "config", "--format", "json",
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, "Docker Compose rejected the combined private staged overrides"
    services = json.loads(result.stdout)["services"]
    assert services["finance-rag"]["environment"]["ACCESSPROOF_CHAT_URL"] == (
        "http://accessproof-gateway-finance-test:8090/v1/chat/completions"
    )
    assert services["hr-rag"]["environment"]["ACCESSPROOF_CHAT_URL"] == (
        "http://accessproof-gateway-hr-test:8090/v1/chat/completions"
    )
    assert services["sales-rag"]["environment"] == {"UNRELATED": "preserve"}
    assert services["finance-rag"]["image"] == services["sales-rag"]["image"]
    for gateway in ("accessproof-gateway-finance-test", "accessproof-gateway-hr-test"):
        assert services[gateway]["read_only"] is True
        assert services[gateway]["cap_drop"] == ["ALL"]
        assert services[gateway]["ports"][0]["host_ip"] == "127.0.0.1"
    assert customer.read_bytes() == original_bytes
