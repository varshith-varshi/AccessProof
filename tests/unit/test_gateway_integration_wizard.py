"""Customer-owned guided Docker onboarding preserves route/certification gates."""
from __future__ import annotations

import base64
import json
import os

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from apps.gateway.accessproof_gateway import integration_wizard as wizard
from apps.gateway.accessproof_gateway.installer import InstallationSpec


def _spec():
    pub = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return InstallationSpec.parse({
        "tenant_id": "tenant-1", "application_id": "app-1",
        "rag_service": "rag", "guard_url": "http://guard:8080",
        "model_url": "http://model:8000/v1/chat/completions",
        "trusted_public_keys": {"key": base64.urlsafe_b64encode(pub).decode()},
    })


def _resolved(cache="none", *, contract=True, cache_return=True):
    labels = {
        "com.accessproof.gateway.contract": "accessproof.gateway/v1",
        "com.accessproof.gateway.enforces": "attested-retrieval-and-buffered-output",
        "com.accessproof.gateway.route_env": "MODEL_ROUTE",
    } if contract else {}
    if cache_return:
        labels["com.accessproof.cache.return_path"] = "signed-manifest-guard-reauthorization/v1"
    if cache == "none":
        labels["com.accessproof.cache.mode"] = "none"
    env = {"ACCESSPROOF_DEMO_CACHE_BACKEND": cache} if cache != "none" else {}
    return {
        "services": {
            "rag": {"image": "rag:v1", "labels": labels, "environment": env,
                    "networks": ["rag-isolated"]},
            "model": {"image": "model:v1", "networks": ["model-isolated"]},
            "guard": {"image": "guard:v1", "networks": ["rag-isolated"]},
        },
        "networks": {"rag-isolated": {"internal": True},
                     "model-isolated": {"internal": True}},
    }


def _private(path, value):
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    return path


def _setup(tmp_path, monkeypatch, cache="none", cache_return=True):
    spec = _spec()
    spec_data = {
        "tenant_id": spec.tenant_id, "application_id": spec.application_id,
        "rag_service": spec.rag_service, "guard_url": spec.guard_url,
        "model_url": spec.model_url,
        "trusted_public_keys": spec.trusted_public_keys,
    }
    spec_file = _private(tmp_path / "spec.json", spec_data)
    compose = tmp_path / "customer.compose.yml"
    compose.write_text("services: {}\n")
    resolved = _resolved(cache, cache_return=cache_return)
    monkeypatch.setattr(wizard, "_resolved_compose", lambda _: resolved)
    return spec_file, compose, tmp_path / "generated", spec, resolved


def test_wizard_detects_unreviewed_cache_return_path():
    report = wizard.analyze_reference(_spec(), _resolved("memcached", cache_return=False))
    assert report["supported_reference_contract"] is True
    assert "CACHE_RESPONSE_PATH_NOT_DECLARED" in report["blocking_issues"]
    assert not report["production_certification"]


def test_wizard_rejects_unknown_contract_and_privileged_rag():
    with pytest.raises(wizard.IntegrationWizardError, match="SUPPORTED_RAG_CONTRACT_REQUIRED"):
        wizard.analyze_reference(_spec(), _resolved(contract=False))
    resolved = _resolved()
    resolved["services"]["rag"]["privileged"] = True
    assert "RAG_UNSAFE_NETWORK_MODE" in wizard.analyze_reference(
        _spec(), resolved,
    )["blocking_issues"]


def test_plan_never_creates_files_or_starts_services(tmp_path, monkeypatch):
    spec_file, compose, out, _, _ = _setup(tmp_path, monkeypatch, "redis")
    report = wizard.run_wizard(
        mode="plan", spec_path=spec_file, compose=compose, output=out,
    )
    assert report["state"] == "PLAN_ONLY"
    assert report["detected_cache_backend"] == "redis"
    assert not report["blocking_issues"]
    assert not out.exists()


def test_wizard_stages_private_files_preserving_customer_compose(tmp_path, monkeypatch):
    spec_file, compose, out, spec, _ = _setup(tmp_path, monkeypatch)
    original = compose.read_bytes()
    staged = wizard.run_wizard(
        mode="stage", spec_path=spec_file, compose=compose, output=out,
    )
    assert staged["state"] == "STAGED_UNVERIFIED"
    assert staged["customer_rag_traffic_changed"] is False
    assert compose.read_bytes() == original
    assert os.stat(out / "gateway.env").st_mode & 0o777 == 0o600
    assert os.stat(out).st_mode & 0o777 == 0o700
    # Idempotent resume requires stage fingerprint unchanged.
    resumed = wizard.run_wizard(
        mode="stage", spec_path=spec_file, compose=compose, output=out,
    )
    assert resumed["state"] == "STAGED_UNVERIFIED"


def test_install_requires_explicit_approval_and_never_starts_rag(tmp_path, monkeypatch):
    spec_file, compose, out, spec, _ = _setup(tmp_path, monkeypatch)
    calls = []
    monkeypatch.setattr(wizard, "_run_installer_apply", lambda *args: calls.append(args))
    with pytest.raises(wizard.IntegrationWizardError, match="EXPLICIT_GATEWAY_INSTALL"):
        wizard.run_wizard(
            mode="install", spec_path=spec_file, compose=compose, output=out,
        )
    assert not calls
    applied = wizard.run_wizard(
        mode="install", spec_path=spec_file, compose=compose, output=out,
        approve_gateway_install=True,
    )
    assert applied["state"] == "INSTALLED_UNVERIFIED"
    assert len(calls) == 1
    assert applied["customer_rag_traffic_changed"] is False


def test_tampered_staged_config_is_not_deployed(tmp_path, monkeypatch):
    spec_file, compose, out, spec, _ = _setup(tmp_path, monkeypatch)
    wizard.run_wizard(mode="stage", spec_path=spec_file, compose=compose, output=out)
    (out / "gateway.override.json").write_text('{"tampered":true}')
    calls = []
    monkeypatch.setattr(wizard, "_run_installer_apply", lambda *args: calls.append(args))
    with pytest.raises(ValueError):
        wizard.run_wizard(
            mode="install", spec_path=spec_file, compose=compose, output=out,
            approve_gateway_install=True,
        )
    assert not calls


def test_unenrolled_verify_cannot_self_certify(tmp_path, monkeypatch):
    spec_file, compose, out, spec, _ = _setup(tmp_path, monkeypatch)
    wizard.run_wizard(mode="stage", spec_path=spec_file, compose=compose, output=out)
    with pytest.raises(wizard.IntegrationWizardError, match="SERVER_ISSUED_CHALLENGE_REQUIRED"):
        wizard.run_wizard(
            mode="verify", spec_path=spec_file, compose=compose, output=out,
        )


def test_wizard_uses_independent_machine_challenge_before_cutover(tmp_path, monkeypatch):
    spec_file, compose, out, spec, _ = _setup(tmp_path, monkeypatch)
    wizard.run_wizard(mode="stage", spec_path=spec_file, compose=compose, output=out)
    challenge = _private(tmp_path / "challenge.json", {"challenge_id": "from-server"})
    machine = _private(tmp_path / "machine.json", {"guard_id": "enrolled-guard"})
    order = []
    monkeypatch.setattr(wizard, "_docker_compose_json", lambda *args: {})
    monkeypatch.setattr(wizard, "verify_deployment_contract",
                        lambda **kwargs: order.append("contract"))
    monkeypatch.setattr(wizard, "submit_customer_reference_probe",
                        lambda **kwargs: order.append("challenge") or {"production_certification": False})
    result = wizard.run_wizard(
        mode="verify", spec_path=spec_file, compose=compose, output=out,
        challenge_path=challenge, machine_path=machine,
    )
    assert order == ["contract", "challenge"]
    assert result["state"] == "REFERENCE_TESTS_SUBMITTED"
    assert result["production_certification"] is False


def test_cutover_never_restarts_rag_without_explicit_approval(tmp_path, monkeypatch):
    spec_file, compose, out, spec, _ = _setup(tmp_path, monkeypatch)
    wizard.run_wizard(mode="stage", spec_path=spec_file, compose=compose, output=out)
    challenge = _private(tmp_path / "challenge.json", {"challenge_id": "issued"})
    machine = _private(tmp_path / "machine.json", {"guard_id": "enrolled"})
    monkeypatch.setattr(wizard, "_docker_compose_json", lambda *args: {})
    monkeypatch.setattr(wizard, "verify_deployment_contract", lambda **kwargs: None)
    calls = []
    monkeypatch.setattr(wizard, "approved_docker_cutover",
                        lambda **kwargs: calls.append(kwargs) or {"state": "CUSTOMER_CUTOVER_VERIFIED"})
    with pytest.raises(wizard.IntegrationWizardError, match="EXPLICIT_CUSTOMER_RAG_CUTOVER"):
        wizard.run_wizard(
            mode="cutover", spec_path=spec_file, compose=compose, output=out,
            challenge_path=challenge, machine_path=machine,
        )
    assert calls == []


def test_complete_one_command_prechecks_all_inputs_before_gateway_start(tmp_path, monkeypatch):
    spec_file, compose, out, spec, _ = _setup(tmp_path, monkeypatch)
    wizard.run_wizard(mode="stage", spec_path=spec_file, compose=compose, output=out)
    calls = []
    monkeypatch.setattr(wizard, "_run_installer_apply", lambda *args: calls.append(args))
    with pytest.raises(wizard.IntegrationWizardError, match="SERVER_ISSUED_CHALLENGE_REQUIRED"):
        wizard.run_wizard(
            mode="complete", spec_path=spec_file, compose=compose, output=out,
            approve_gateway_install=True, approve_route_cutover=True,
        )
    assert calls == []


def test_complete_one_command_reuses_enrolled_security_agent_before_cutover(tmp_path, monkeypatch):
    spec_file, compose, out, spec, _ = _setup(tmp_path, monkeypatch)
    wizard.run_wizard(mode="stage", spec_path=spec_file, compose=compose, output=out)
    challenge = _private(tmp_path / "challenge.json", {"challenge_id": "issued"})
    machine = _private(tmp_path / "machine.json", {"guard_id": "guard-enrolled"})
    probe = _private(tmp_path / "probe.json", {
        "url": "http://127.0.0.1:18124/v1/chat/completions",
        "allowed_token": "allow-synthetic",
        "denied_token": "deny-synthetic",
        "allowed_resources": [{"source_id": "s", "resource_id": "r", "content": "allowed"}],
        "denied_resources": [{"source_id": "s", "resource_id": "r", "content": "blocked"}],
        "allowed_canary": "synthetic-positive-canary",
        "forbidden_canary": "synthetic-negative-canary",
    })
    order = []
    monkeypatch.setattr(wizard, "_run_installer_apply",
                        lambda *args: order.append("install"))
    monkeypatch.setattr(wizard, "_docker_compose_json", lambda *args: {})
    monkeypatch.setattr(wizard, "verify_deployment_contract",
                        lambda **kwargs: order.append("contract"))
    monkeypatch.setattr(wizard, "submit_customer_reference_probe",
                        lambda **kwargs: order.append("challenge") or {"state": "tested"})
    monkeypatch.setattr(wizard, "approved_docker_cutover",
                        lambda **kwargs: order.append("cutover") or {
                            "state": "CUSTOMER_CUTOVER_VERIFIED",
                        })
    result = wizard.run_wizard(
        mode="complete", spec_path=spec_file, compose=compose, output=out,
        approve_gateway_install=True, approve_route_cutover=True,
        challenge_path=challenge, machine_path=machine, probe_path=probe,
    )
    assert order == ["install", "contract", "challenge", "cutover"]
    assert result["state"] == "CUSTOMER_CUTOVER_VERIFIED"
    assert result["production_certification"] is False
    order.clear()
    monkeypatch.setattr(wizard, "submit_customer_reference_probe",
                        lambda **kwargs: order.append("challenge") or (
                            (_ for _ in ()).throw(wizard.CustomerAgentError("denied"))
                        ))
    with pytest.raises(wizard.CustomerAgentError):
        wizard.run_wizard(
            mode="complete", spec_path=spec_file, compose=compose, output=out,
            approve_gateway_install=True, approve_route_cutover=True,
            challenge_path=challenge, machine_path=machine, probe_path=probe,
        )
    assert "cutover" not in order


def test_protect_request_requires_control_plane_guard_ack_not_just_status():
    import httpx
    token = "synthetic-admin-" + "a" * 40
    approval = {
        "control_plane_url": "http://127.0.0.1:8000",
        "admin_session_token": token,
    }
    responses = iter([
        {"state": "action_required", "guard_acknowledged": False, "checks": [{"ok": False}]},
        {"state": "protected", "guard_acknowledged": False, "checks": [{"ok": True}]},
        {"state": "protected", "guard_acknowledged": True, "checks": [{"ok": True}]},
    ])
    def handler(req: httpx.Request):
        assert req.method == "POST"
        assert req.url.path.endswith("/app-1/protection/enable")
        assert req.headers["authorization"] == f"Bearer {token}"
        return httpx.Response(202, json=next(responses))
    with httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False) as client:
        first = wizard.request_guard_protect_activation(application_id="app-1", approval=approval, client=client)
        second = wizard.request_guard_protect_activation(application_id="app-1", approval=approval, client=client)
        third = wizard.request_guard_protect_activation(application_id="app-1", approval=approval, client=client)
    assert not first["protect_active"]
    assert not second["protect_active"]
    assert third == {"state": "protected", "protect_active": True}


def test_protect_request_rejects_redirect_and_insecure_admin_url():
    import httpx
    approval = {
        "control_plane_url": "https://api.customer.example",
        "admin_session_token": "synthetic-admin-" + "a" * 40,
    }
    with httpx.Client(transport=httpx.MockTransport(
        lambda _: httpx.Response(302, headers={"Location": "https://evil.example"})
    )) as client:
        with pytest.raises(wizard.IntegrationWizardError, match="CONTROL_PLANE_PROTECT_PREFLIGHT_REJECTED"):
            wizard.request_guard_protect_activation(
                application_id="app-1", approval=approval, client=client,
            )
    with pytest.raises(wizard.IntegrationWizardError, match="CONTROL_PLANE_URL_UNSAFE"):
        wizard.request_guard_protect_activation(
            application_id="app-1", approval={
                **approval, "control_plane_url": "http://external.example",
            },
        )


def test_protect_request_must_be_after_cutover_and_user_approved(tmp_path, monkeypatch):
    spec_file, compose, out, spec, _ = _setup(tmp_path, monkeypatch)
    approved = _private(tmp_path / "admin.json", {
        "control_plane_url": "http://127.0.0.1:8000",
        "admin_session_token": "synthetic-admin-" + "a" * 40,
    })
    with pytest.raises(wizard.IntegrationWizardError, match="PROTECT_REQUEST_REQUIRES_VERIFIED_CUTOVER"):
        wizard.run_wizard(
            mode="install", spec_path=spec_file, compose=compose, output=out,
            approve_protect_request=True, admin_credentials_path=approved,
        )
    assert not out.exists()



def test_unsafe_network_is_rejected_before_staging(tmp_path, monkeypatch):
    spec_file, compose, out, spec, resolved = _setup(tmp_path, monkeypatch)
    resolved["services"]["rag"]["networks"] = ["rag-isolated", "model-isolated"]
    monkeypatch.setattr(wizard, "_resolved_compose", lambda _: resolved)
    preview = wizard.run_wizard(
        mode="plan", spec_path=spec_file, compose=compose, output=out,
    )
    assert "DIRECT_RAG_MODEL_EGRESS_BYPASS" in preview["blocking_issues"]
    with pytest.raises(wizard.IntegrationWizardError, match="INTEGRATION_PREFLIGHT_NOT_SUPPORTED"):
        wizard.run_wizard(
            mode="stage", spec_path=spec_file, compose=compose, output=out,
        )
    assert not out.exists()


def test_protect_request_rejects_malformed_control_plane_without_traceback():
    with pytest.raises(wizard.IntegrationWizardError, match="CONTROL_PLANE_URL_UNSAFE"):
        wizard.request_guard_protect_activation(
            application_id="app-1",
            approval={"control_plane_url": 42, "admin_session_token": "a" * 45},
        )


def test_wizard_unknown_cache_is_never_misreported_as_none():
    compose = _resolved()
    compose["services"]["rag"]["labels"].pop("com.accessproof.cache.mode")
    report = wizard.analyze_reference(_spec(), compose)
    assert report["detected_cache_backend"] == "unknown"
    assert report["cache_identification_confidence"] == "UNKNOWN"
    assert "CACHE_CONFIGURATION_UNKNOWN" in report["blocking_issues"]
    assert report["cache_inventory_complete"] is False
    assert report["cache_return_path_verified"] is False


def test_wizard_rejects_conflicting_or_multiple_cache_configs():
    compose = _resolved("redis")
    compose["services"]["rag"]["environment"]["MEMCACHED_HOST"] = "memcached"
    result = wizard.analyze_reference(_spec(), compose)
    assert "CACHE_BACKEND_DECLARATION_CONFLICT" in result["blocking_issues"]

    compose = _resolved()
    compose["services"]["rag"]["labels"].pop("com.accessproof.cache.mode")
    compose["services"]["rag"]["environment"] = {
        "REDIS_URL": "redis://cache", "MEMCACHED_HOST": "memcache",
    }
    result = wizard.analyze_reference(_spec(), compose)
    assert result["detected_cache_backend"] == "ambiguous"
    assert "CACHE_MULTIPLE_BACKENDS_DETECTED" in result["blocking_issues"]


def test_no_cache_declaration_conflicting_with_redis_is_blocked():
    compose = _resolved()
    compose["services"]["rag"]["environment"]["REDIS_URL"] = "redis://cache"
    report = wizard.analyze_reference(_spec(), compose)
    assert "CACHE_NO_CACHE_DECLARATION_CONFLICT" in report["blocking_issues"]


def test_custom_cache_hint_without_reference_config_is_blocked():
    compose = _resolved()
    compose["services"]["rag"]["environment"]["LANGCHAIN_CACHE_URL"] = "local://unknown"
    report = wizard.analyze_reference(_spec(), compose)
    assert "CACHE_POSSIBLY_UNINSTRUMENTED" in report["blocking_issues"]


def test_loopback_only_diagnostic_edge_does_not_block_private_rag_staging():
    compose = _resolved()
    compose["networks"]["rag-edge"] = {"internal": False}
    compose["services"]["rag"]["networks"] = ["rag-isolated", "rag-edge"]
    compose["services"]["rag"]["ports"] = [{
        "host_ip": "127.0.0.1", "published": "28189", "target": 8187,
    }]
    report = wizard.analyze_reference(_spec(), compose)
    assert "RAG_NETWORK_NOT_ISOLATED" not in report["blocking_issues"]


def test_public_rag_edge_remains_blocked_even_with_private_network():
    compose = _resolved()
    compose["networks"]["rag-edge"] = {"internal": False}
    compose["services"]["rag"]["networks"] = ["rag-isolated", "rag-edge"]
    compose["services"]["rag"]["ports"] = [{
        "host_ip": "0.0.0.0", "published": "28189", "target": 8187,
    }]
    report = wizard.analyze_reference(_spec(), compose)
    assert "RAG_NETWORK_NOT_ISOLATED" in report["blocking_issues"]
