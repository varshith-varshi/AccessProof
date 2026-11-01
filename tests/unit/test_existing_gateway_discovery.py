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
