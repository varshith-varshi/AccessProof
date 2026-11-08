"""One unauthorized signed chunk must not suppress an authorized answer.

Both chunks model an untrusted retrieval-cache hit. Current employee Guard
ACLs filter them before model invocation; the final release guard remains.
"""
from __future__ import annotations

import json

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from apps.gateway.accessproof_gateway.app import GatewaySettings, create_app
from packages.rag_core import (
    ContentBinding, SourceAttestationSigner, SourceAttestationVerifier,
)


def _gateway():
    private = Ed25519PrivateKey.generate()
    signer = SourceAttestationSigner(key_id="ingest", private_key=private)
    verifier = SourceAttestationVerifier(tenant_id="tenant", trusted_keys={"ingest":private.public_key()})
    seen = {"model": [], "guard_filter": [], "guard_output": []}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("/filter-resources"):
            content = json.loads(req.content)
            seen["guard_filter"].append(content)
            # Guard grants only the shared file; private content is DENIED.
            return httpx.Response(200, json={
                "decision_id": "test-l1", "decision": "allow", "mode": "protect",
                "allowed": [{"source_id": "sharepoint", "resource_id": "shared",
                             "chunk_ids": ["chunk-shared"]}],
                "denied": [{"source_id": "sharepoint", "resource_id": "private",
                            "chunk_ids": ["chunk-private"]}],
                "unknown": [],
            })
        if req.url.path.endswith("/check-output"):
            record = json.loads(req.content)
            seen["guard_output"].append(record)
            assert record["used_resource_ids"] == ["shared"]
            return httpx.Response(200, json={"decision":"allow","reason":"AUTHORIZED_SOURCE_LINEAGE"})
        if req.url.host == "model.test":
            body=req.content.decode()
            seen["model"].append(body)
            assert "ALLOWED_SHAREPOINT_TEXT" in body
            assert "PRIVATE_SHAREPOINT_TEXT" not in body
            return httpx.Response(200,json={
                "choices":[{"message":{"content":"Answer based on shared document"},
                            "finish_reason":"stop"}],
            })
        raise AssertionError("Unexpected URL")

    config=GatewaySettings(
        guard_url="https://guard.test",model_url="https://model.test/v1/chat/completions",
        application_id="demo",tenant_id="tenant",verifier=verifier,
        model_provider="openai-compatible",
    )
    app=create_app(config,client=httpx.Client(transport=httpx.MockTransport(handler)))
    return TestClient(app),signer,seen


def _attested(signer, rid, chunk, content):
    b=ContentBinding(tenant_id="tenant",application_id="demo",source_id="sharepoint",
                     resource_id=rid,chunk_id=chunk,content_version="v1",content=content)
    return {"source_id":"sharepoint","resource_id":rid,"chunk_id":chunk,
            "content_version":"v1","content":content,"content_attestation":signer.issue(b)}


def test_mixed_cache_candidate_permissions_only_send_allowed_chunks_to_model():
    client,signer,seen=_gateway()
    with client:
        result=client.post("/v1/chat/completions",
            headers={"Authorization":"Bearer signed-in-employee-test"},
            json={"application_id":"demo","employee_question":"Summarize company",
                  "retrieved_resources":[
                    _attested(signer,"shared","chunk-shared","ALLOWED_SHAREPOINT_TEXT"),
                    _attested(signer,"private","chunk-private","PRIVATE_SHAREPOINT_TEXT"),
                  ]})
    assert result.status_code==200,result.text
    assert result.json()["accessproof"]["decision"]=="allow"
    assert result.json()["choices"][0]["message"]["content"]=="Answer based on shared document"
    assert len(seen["model"])==1
    assert len(seen["guard_filter"])==1
    assert len(seen["guard_output"])==1
    assert len(seen["guard_filter"][0]["resources"])==2


def test_all_private_cache_candidates_never_reach_model():
    client,signer,seen=_gateway()
    with client:
        response=client.post("/v1/chat/completions",
            headers={"Authorization":"Bearer signed-in-employee-test"},
            json={"application_id":"demo","employee_question":"Summarize private",
                  "retrieved_resources":[
                    _attested(signer,"private","chunk-private","PRIVATE_SHAREPOINT_TEXT"),
                  ]})
    # Mock Guard response is intentionally inconsistent (claims allow for a
    # shared chunk that was never retrieved); protected code still fails closed.
    assert response.status_code==403
    assert seen["model"]==[]
    assert "PRIVATE_SHAREPOINT_TEXT" not in response.text
