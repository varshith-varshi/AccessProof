from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from apps.gateway.accessproof_gateway.installer import (
    InstallationError, InstallationSpec, compose_override, private_environment,
    stage_installation, validate_reference_service,
)


def _spec(**overrides: object) -> InstallationSpec:
    key = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    values: dict[str, object] = {
        "tenant_id": "tenant-a", "application_id": "app-a",
        "rag_service": "customer-rag", "guard_url": "http://guard:8080",
        "model_url": "http://model:8000/v1/chat/completions",
        "trusted_public_keys": {"ingester": base64.urlsafe_b64encode(key).decode().rstrip("=")},
    }
    values.update(overrides)
    return InstallationSpec.parse(values)


def _compose(*, allowed: bool = True) -> dict:
    labels = {
        "com.accessproof.gateway.contract": "accessproof.gateway/v1",
        "com.accessproof.gateway.enforces": "attested-retrieval-and-buffered-output",
        "com.accessproof.gateway.route_env": "ACCESSPROOF_CHAT_URL",
    } if allowed else {}
    return {"services": {"customer-rag": {"image": "example/customer-rag", "labels": labels}}}


def test_installer_stages_gateway_with_no_customer_source_modifications(tmp_path: Path) -> None:
    spec = _spec()
    customer = tmp_path / "customer.compose.yml"
    customer.write_text("services:\n  customer-rag:\n    image: example/customer-rag\n")
    original = customer.read_bytes()
    outputs = stage_installation(spec, customer, tmp_path / "generated", _compose())
    assert outputs["state"] == "INSTALLED_UNVERIFIED"
    assert customer.read_bytes() == original
    assert os.stat(outputs["env"]).st_mode & 0o777 == 0o600
    override = json.loads(Path(outputs["override"]).read_text())
    assert override["services"]["customer-rag"]["environment"]["ACCESSPROOF_CHAT_URL"].startswith("http://accessproof-gateway:")
    assert override["services"]["accessproof-gateway"]["read_only"] is True
    assert "Bearer" not in Path(outputs["env"]).read_text()
    metadata = json.loads((tmp_path / "generated" / "installation.json").read_text())
    assert len(metadata["deployment_sha256"]) == 64
    assert len(metadata["route_sha256"]) == 64
    assert metadata["reference_contract"] == "accessproof.gateway/v1"


def test_multiple_selected_rags_get_independent_gateway_service_and_port(tmp_path: Path) -> None:
    compose = tmp_path / "customer.yml"
    compose.write_text("services: {}\n")
    resolved = {"services": {
        "finance-rag": {"labels": _compose()["services"]["customer-rag"]["labels"]},
        "hr-rag": {"labels": _compose()["services"]["customer-rag"]["labels"]},
    }}
    finance = _spec(rag_service="finance-rag", gateway_service="accessproof-gateway-finance", listen_port=18090)
    hr = _spec(rag_service="hr-rag", gateway_service="accessproof-gateway-hr", listen_port=18091)
    finance_paths = stage_installation(finance, compose, tmp_path / "finance", resolved)
    hr_paths = stage_installation(hr, compose, tmp_path / "hr", resolved)
    finance_override = json.loads(Path(finance_paths["override"]).read_text())
    hr_override = json.loads(Path(hr_paths["override"]).read_text())
    assert "accessproof-gateway-finance" in finance_override["services"]
    assert "accessproof-gateway-hr" in hr_override["services"]
    assert finance_override["services"]["finance-rag"]["environment"]["ACCESSPROOF_CHAT_URL"] == "http://accessproof-gateway-finance:8090/v1/chat/completions"
    assert hr_override["services"]["hr-rag"]["environment"]["ACCESSPROOF_CHAT_URL"] == "http://accessproof-gateway-hr:8090/v1/chat/completions"


def test_installer_never_deploys_unsupported_customer_rag(tmp_path: Path) -> None:
    spec = _spec()
    customer = tmp_path / "customer.yml"
    customer.write_text("services: {}\n")
    with pytest.raises(InstallationError, match="attested-manifest"):
        stage_installation(spec, customer, tmp_path / "generated", _compose(allowed=False))
    assert not (tmp_path / "generated").exists()


def test_installer_does_not_overwrite_existing_private_deployment(tmp_path: Path) -> None:
    spec = _spec()
    customer = tmp_path / "customer.yml"
    customer.write_text("services: {}\n")
    out = tmp_path / "generated"
    out.mkdir()
    secret = out / "gateway.env"
    secret.write_text("preserve_me\n")
    with pytest.raises(InstallationError, match="must be new"):
        stage_installation(spec, customer, out, _compose())
    assert secret.read_text() == "preserve_me\n"


@pytest.mark.parametrize("field,value", [
    ("model_url", "file:///etc/passwd"), ("guard_url", "http://name:secret@host/"),
    ("tenant_id", "abc\nFORGED=1"), ("rag_service", "x;rm -rf /"),
    ("gateway_image", "busybox; touch /tmp/leak"),
    ("model_token_env", "A=B"), ("listen_port", 22),
    ("trusted_public_keys", {"kid": "abcd"}),
])
def test_installer_rejects_unsafe_specs(field: str, value: object) -> None:
    with pytest.raises(InstallationError):
        _spec(**{field: value})


def test_secret_from_local_environment_is_not_in_command_or_override(tmp_path: Path) -> None:
    spec = _spec(model_token_env="MY_SECRET")
    data = private_environment(spec, {"MY_SECRET": "top$secret"})
    assert "ACCESSPROOF_GATEWAY_MODEL_BEARER_TOKEN=top$secret" in data
    out = compose_override(spec, "ACCESSPROOF_CHAT_URL", tmp_path / "gateway.env")
    assert "top$secret" not in json.dumps(out)


def test_installer_uses_only_internal_rag_network_when_loopback_health_bridge_exists(tmp_path: Path) -> None:
    """A pre-install health bridge must not disconnect Gateway from the RAG."""
    spec = _spec()
    resolved = {
        "networks": {
            "rag-internal": {"internal": True},
            "rag-edge": {"internal": False},
            "model-internal": {"internal": True},
        },
        "services": {
            "customer-rag": {
                "labels": _compose()["services"]["customer-rag"]["labels"],
                "networks": ["rag-internal", "rag-edge"],
            },
            "model": {"networks": ["model-internal"]},
        },
    }
    override = compose_override(spec, "ACCESSPROOF_CHAT_URL", tmp_path / "gateway.env", resolved)
    networks = override["services"]["accessproof-gateway"]["networks"]
    assert "rag-internal" in networks
    assert "model-internal" in networks
    assert "rag-edge" not in networks
    assert "accessproof-gateway-host" in networks


def test_installer_rejects_unknown_contract_version() -> None:
    with pytest.raises(InstallationError):
        validate_reference_service(_spec(), {"services": {"customer-rag": {"labels": {
            "com.accessproof.gateway.contract": "accessproof.gateway/v0",
            "com.accessproof.gateway.enforces": "attested-retrieval-and-buffered-output",
            "com.accessproof.gateway.route_env": "ACCESSPROOF_CHAT_URL",
        }}}})


def test_installer_waits_for_actual_http_liveness(monkeypatch) -> None:
    import urllib.error
    import urllib.request
    from apps.gateway.accessproof_gateway.installer import wait_for_gateway_liveness

    calls = []
    class Response:
        status = 200
        def __enter__(self):
            return self
        def __exit__(self, *_):
            return None
        def read(self, size):
            return b'{"status":"ok"}'
    class Opener:
        def open(self, url, timeout):
            calls.append(url)
            if len(calls) == 1:
                raise urllib.error.URLError("startup not complete")
            return Response()
    monkeypatch.setattr(urllib.request, "build_opener", lambda *args: Opener())
    monkeypatch.setattr("apps.gateway.accessproof_gateway.installer.time.sleep", lambda _: None)
    wait_for_gateway_liveness(18108, attempts=3, interval_seconds=0)
    assert calls == ["http://127.0.0.1:18108/health/live"] * 2


def test_installer_fails_if_gateway_never_becomes_live(monkeypatch) -> None:
    import urllib.error
    import urllib.request
    from apps.gateway.accessproof_gateway.installer import wait_for_gateway_liveness

    class Opener:
        def open(self, url, timeout):
            raise urllib.error.URLError("unavailable")
    monkeypatch.setattr(urllib.request, "build_opener", lambda *args: Opener())
    with pytest.raises(InstallationError, match="liveness"):
        wait_for_gateway_liveness(18108, attempts=2, interval_seconds=0)


def test_staged_installation_can_be_applied_without_overwriting_a_reviewed_file(tmp_path: Path) -> None:
    from apps.gateway.accessproof_gateway.installer import verify_existing_staged_installation
    spec = _spec()
    compose = tmp_path / "customer.yml"
    compose.write_text("services:\n  customer-rag:\n    image: customer/test\n")
    directory = tmp_path / "private-stage"
    stage_installation(spec, compose, directory, _compose())
    untouched = {file.name: file.read_bytes() for file in directory.iterdir()}
    resolved = verify_existing_staged_installation(spec, compose, directory)
    assert resolved["state"] == "INSTALLED_UNVERIFIED"
    assert {file.name: file.read_bytes() for file in directory.iterdir()} == untouched


@pytest.mark.parametrize("changed", ["compose", "override", "environment", "mode"])
def test_staged_installation_invalidates_tampering(tmp_path: Path, changed: str) -> None:
    from apps.gateway.accessproof_gateway.installer import verify_existing_staged_installation
    spec = _spec()
    compose = tmp_path / "customer.yml"
    compose.write_text("services:\n  customer-rag:\n    image: customer/test\n")
    directory = tmp_path / "private-stage"
    stage_installation(spec, compose, directory, _compose())
    if changed == "compose":
        compose.write_text("services:\n  customer-rag:\n    image: unauthorized/version\n")
    elif changed == "override":
        path = directory / "gateway.override.json"
        path.write_text(path.read_text().replace("accessproof-gateway:0.1.0", "unknown-gateway:latest"))
    elif changed == "environment":
        path = directory / "gateway.env"
        path.write_text(path.read_text().replace("http://guard:8080", "http://unsafe:8080"))
    else:
        (directory / "gateway.env").chmod(0o644)
    with pytest.raises(InstallationError):
        verify_existing_staged_installation(spec, compose, directory)
