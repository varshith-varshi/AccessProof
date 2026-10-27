"""Client-side rejection of forged or incomplete multi-source retrieval scopes."""
import httpx
import pytest

from packages.rag_core.protection import GuardClient


def _client(payload):
    return GuardClient(
        "https://guard.synthetic",
        client=httpx.Client(transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json=payload)
        )),
        multisource=True,
    )


def _scope():
    return {
        "mode": "protect", "decision": "allow", "scope_complete": True,
        "authorization_revision": 1, "authorization_revision_hash": "a" * 64,
        "sources": [
            {"source_id": "google", "allowed_resource_ids": ["g1"]},
            {"source_id": "sharepoint", "allowed_resource_ids": ["s1"]},
        ],
    }


def _ask(client):
    return client.multisource_authorization_scope(
        employee_token="signed-synthetic-token",
        application_id="test-app", request_id="r1",
        source_ids=["google", "sharepoint"],
    )


def test_multisource_scoped_ann_contract_accepts_exact_source_set():
    assert _ask(_client(_scope()))["sources"][1]["allowed_resource_ids"] == ["s1"]


@pytest.mark.parametrize("invalid", [
    {"sources": [{"source_id": "google", "allowed_resource_ids": ["g1"]}]},
    {"sources": [{"source_id": "google", "allowed_resource_ids": ["g1"]},
                 {"source_id": "unbound", "allowed_resource_ids": ["x"]}]},
    {"sources": [{"source_id": "google", "allowed_resource_ids": ["g1"]},
                 {"source_id": "google", "allowed_resource_ids": ["g1"]}]},
    {"authorization_revision_hash": "incorrect"},
    {"scope_complete": False},
    {"mode": "shadow"},
])
def test_multisource_scoped_ann_contract_rejects_malformed_guard_return(invalid):
    payload = {**_scope(), **invalid}
    with pytest.raises(ValueError, match="(INVALID_MULTISOURCE_AUTHORIZATION_SCOPE|invalid authorization revision)"):
        _ask(_client(payload))
