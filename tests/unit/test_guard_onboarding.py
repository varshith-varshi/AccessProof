from __future__ import annotations

import json
import stat
from pathlib import Path

import httpx
import pytest

from apps.guard.accessproof_guard.onboarding import (
    EnrollmentError,
    enroll_guard,
    public_status,
    setup_page,
    validate_control_plane_url,
)


def test_control_plane_requires_https_except_local_development() -> None:
    assert validate_control_plane_url("https://api.accessproof.in/") == "https://api.accessproof.in"
    assert validate_control_plane_url("http://127.0.0.1:8000") == "http://127.0.0.1:8000"
    with pytest.raises(EnrollmentError, match="HTTPS"):
        validate_control_plane_url("http://accessproof.example.com")


def test_browser_enrollment_persists_private_atomic_machine_state(tmp_path: Path) -> None:
    def exchange(request: httpx.Request) -> httpx.Response:
        assert request.url == "https://api.accessproof.in/api/v1/guards/exchange"
        assert json.loads(request.content) == {"enrollment_token": "one-time", "version": "1.2.3"}
        return httpx.Response(200, json={"guard_id": "guard-123456789", "guard_credential": "private-machine-secret"})

    with httpx.Client(transport=httpx.MockTransport(exchange)) as client:
        settings = enroll_guard(
            server="https://api.accessproof.in",
            token="one-time",
            version="1.2.3",
            state_dir=tmp_path,
            issuer="https://issuer.example.com/",
            audience="api://rag",
            tenant_id="tenant-1",
            client=client,
        )

    destination = tmp_path / "credentials.json"
    persisted = json.loads(destination.read_text())
    assert settings == persisted
    assert persisted["credential"] == "private-machine-secret"
    assert persisted["issuer"] == "https://issuer.example.com"
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o700
    assert not (tmp_path / ".credentials.json.tmp").exists()

    status = public_status(persisted, None)
    assert status == {
        "enrolled": True,
        "control_plane": "https://api.accessproof.in",
        "guard_id_short": "guard-12…",
        "sync_error": None,
    }
    assert "credential" not in status
    assert "private-machine-secret" not in json.dumps(status)


def test_setup_page_is_self_contained_and_does_not_persist_token_in_browser() -> None:
    page = setup_page()
    assert "AccessProof Guard setup" in page
    assert "http://" not in page
    assert "https://api.accessproof.in" in page
    assert "localStorage" not in page
    assert "sessionStorage" not in page
    assert "src=\"http" not in page
    assert "autocomplete=\"off\"" in page
    assert "Create a Guard in web-v2" not in page
    assert "Create a Guard in your AccessProof dashboard" in page
    assert "Microsoft Entra ID employees" in page
    assert "host==='login.microsoftonline.com'" in page
    assert "subjectInput.value=" in page


def test_used_or_invalid_enrollment_token_has_safe_error(tmp_path: Path) -> None:
    transport = httpx.MockTransport(lambda _: httpx.Response(401, json={"detail": "internal"}))
    with httpx.Client(transport=transport) as client, pytest.raises(EnrollmentError, match="invalid, expired, or already used"):
        enroll_guard(
            server="https://api.accessproof.in",
            token="bad",
            version="1.0.0",
            issuer="https://issuer.example",
            audience="rag",
            state_dir=tmp_path,
            client=client,
        )
    assert not (tmp_path / "credentials.json").exists()


def test_browser_enrollment_requires_valid_oidc_before_token_exchange(tmp_path: Path) -> None:
    calls = []
    def unexpected(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={"guard_id": "abc", "guard_credential": "secret"})
    with httpx.Client(transport=httpx.MockTransport(unexpected)) as client:
        for issuer, audience in [(None, "rag"), ("http://insecure.example", "rag"), ("https://oidc.example", "")]:
            with pytest.raises(EnrollmentError):
                enroll_guard(server="https://api.accessproof.in", token="one-time", version="1",
                             issuer=issuer, audience=audience, state_dir=tmp_path, client=client)
    assert calls == []
    assert not (tmp_path / "credentials.json").exists()


def test_existing_machine_identity_cannot_be_overwritten_or_rebound(tmp_path: Path) -> None:
    state = tmp_path / "credentials.json"
    state.write_text('{"credential":"existing-customer"}')
    calls = []
    def exchange(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={"guard_id": "different", "guard_credential": "bad"})
    with httpx.Client(transport=httpx.MockTransport(exchange)) as client:
        with pytest.raises(EnrollmentError, match="already enrolled"):
            enroll_guard(server="https://api.accessproof.in", token="valid",
                         version="1", state_dir=tmp_path, issuer="https://issuer.example",
                         audience="rag", client=client)
    assert calls == []
    assert "existing-customer" in state.read_text()
