"""Existing Gateway discovery must fail closed on malformed Docker output."""
from __future__ import annotations

import pytest

from apps.gateway.accessproof_gateway import existing_gateway
from apps.gateway.accessproof_gateway import customer_connect


def test_listing_rejects_non_string_docker_rows(monkeypatch):
    monkeypatch.setattr(existing_gateway, "_docker", lambda *args: ["{}", 7])
    with pytest.raises(existing_gateway.ExistingGatewayError, match="DISCOVERY_INVALID"):
        existing_gateway._docker_listing()


def test_container_ids_rejects_malformed_json():
    with pytest.raises(existing_gateway.ExistingGatewayError, match="DISCOVERY_INVALID"):
        existing_gateway._container_ids(["not-json"])


def test_container_ids_ignores_rows_without_safe_id():
    assert existing_gateway._container_ids(["{}", '{"ID":"abc"}', "[]"]) == ["abc"]


def test_installation_claim_rejects_non_object_response(monkeypatch):
    class Response:
        status_code = 202

        @staticmethod
        def json():
            return ["not", "a", "claim"]

    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        @staticmethod
        def post(*args, **kwargs):
            return Response()

    monkeypatch.setattr(customer_connect.httpx, "Client", lambda **kwargs: Client())
    with pytest.raises(customer_connect.ConnectError, match="invalid installation response"):
        customer_connect.report_claim(
            {"control_plane_url": "https://api.accessproof.in", "pairing_token": "test"},
            {"application_id": "test"},
        )


def test_runtime_is_approved_under_both_docker_image_stores() -> None:
    from apps.gateway.accessproof_gateway.existing_gateway import approved_image_ids

    classic, containerd = "sha256:" + "a" * 64, "sha256:" + "b" * 64
    assert approved_image_ids({"image_id": containerd, "image_ids": [classic, containerd]}) == {classic, containerd}
    assert approved_image_ids({"image_id": classic}) == {classic}
    assert approved_image_ids({"image_id": "nope", "image_ids": [None]}) == set()


def test_explicit_legacy_gateway_requires_reviewed_migration(monkeypatch, tmp_path):
    """A manual legacy image cannot be paired or credentialed by accident."""
    release = tmp_path / "runtime-release.json"
    release.write_text('{"image_id":"sha256:' + "a" * 64 + '"}')
    legacy = [{
        "Config": {"Image": "accessproof-gateway:legacy", "Labels": {}},
        "State": {"Status": "running"},
    }]
    monkeypatch.setattr(existing_gateway, "_docker", lambda *args: legacy)
    with pytest.raises(existing_gateway.ExistingGatewayError, match="LEGACY_GATEWAY_MIGRATION_REQUIRED"):
        existing_gateway.detect(
            {"application_id": "app", "organization_id": "org"},
            container_name="manual-gateway", release_path=release,
        )
