"""The Gateway must not forward signed RAG context or employee JWTs over public HTTP.

Explicit internal Docker-service/RFC1918/loopback HTTP remains supported.
This is a configuration-time security gate, not a replacement for Docker network
isolation, encrypted public ingress, or the post-deployment route challenge.
"""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from apps.gateway.accessproof_gateway.app import GatewaySettings
from packages.rag_core import SourceAttestationVerifier


def _settings(**changed):
    key = Ed25519PrivateKey.generate()
    params = {
        "guard_url": "http://guard:8080",
        "model_url": "http://model:8000/v1/chat/completions",
        "tenant_id": "tenant-a",
        "application_id": "staff-rag",
        "verifier": SourceAttestationVerifier(
            tenant_id="tenant-a", trusted_keys={"ingester": key.public_key()},
        ),
    }
    params.update(changed)
    return GatewaySettings(**params)


@pytest.mark.parametrize("upstream", ("guard_url", "model_url"))
@pytest.mark.parametrize("url", (
    "http://public-gateway.example:8090/v1/chat/completions",
    "http://8.8.8.8/v1/chat/completions",
    "http://100.100.100.100/v1/chat/completions",
    "http://host.docker.internal:8090/v1/chat/completions",
    "http://model.private.example:443/v1/chat/completions",
    "http://[2001:4860:4860::8888]:8090/v1/chat/completions",
))
def test_public_plaintext_upstream_is_refused(upstream: str, url: str):
    with pytest.raises(ValueError, match="requires HTTPS"):
        _settings(**{upstream: url})


@pytest.mark.parametrize("upstream", ("guard_url", "model_url"))
@pytest.mark.parametrize("url", (
    "http://169.254.169.254/latest/meta-data",
    "https://169.254.169.254/latest/meta-data",
    "http://0.0.0.0/",
    "http://[fe80::1]/",
    "http://[::]/",
))
def test_metadata_and_special_use_ip_is_refused_even_over_https(upstream: str, url: str):
    with pytest.raises(ValueError, match="special-use IP"):
        _settings(**{upstream: url})


@pytest.mark.parametrize("url", (
    "http://guard:8080",
    "http://model:8000/v1/chat/completions",
    "http://localhost:9000/v1/chat/completions",
    "http://127.0.0.1:9000/",
    "http://10.8.0.12:8080",
    "http://172.16.5.7:8080",
    "http://192.168.100.10:8080",
    "http://[::1]:8090",
    "http://[fd12:3456::7]:8090",
    "https://api.openai.com/v1/chat/completions",
    "https://model.private.example:9443/v1/chat/completions",
))
def test_local_or_encrypted_upstreams_are_allowed(url: str):
    assert _settings(model_url=url).model_url == url


def test_insecure_guard_must_not_be_saved_even_if_model_uses_https():
    with pytest.raises(ValueError, match="guard URL requires HTTPS"):
        _settings(
            guard_url="http://outside.example/guard",
            model_url="https://api.example/v1/chat/completions",
        )
