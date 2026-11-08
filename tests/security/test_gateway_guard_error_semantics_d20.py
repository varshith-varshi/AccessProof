"""D-20: the Gateway reports Guard identity/policy refusals as 401/403, never as
a generic 503 outage, and still never generates or releases content."""
import httpx
import pytest

from packages.rag_core.protection import GuardClient, ProtectedRAG, RetrievedResource

DOC = RetrievedResource("src", "doc", content="ACCESSPROOF_CANARY_D20 secret")


def _rag(status: int, detail: str):
    def handler(request):
        return httpx.Response(status, json={"detail": detail})
    return ProtectedRAG(GuardClient("http://guard.invalid", client=httpx.Client(transport=httpx.MockTransport(handler))),
                        allow_unattested_metadata=True)


@pytest.mark.parametrize(("status", "detail", "reason"), [
    (401, "IDENTITY_TOKEN_INVALID", "IDENTITY_REJECTED"),
    (403, "IDENTITY_MAPPING_UNRESOLVED", "GUARD_POLICY_DENIED"),
    (403, "APPLICATION_NOT_BOUND", "GUARD_POLICY_DENIED"),
    (503, "SOURCE_ACL_STALE", "SOURCE_ACL_STALE"),
    (503, "POLICY_SYNC_STALE", "POLICY_SYNC_STALE"),
    (503, "AUTHORIZATION_REVISION_NOT_SYNCED", "AUTHORIZATION_REVISION_NOT_SYNCED"),
    (503, "AUTHORIZATION_REVISION_MISSING", "AUTHORIZATION_REVISION_MISSING"),
    (503, "unexpected untrusted detail", "GUARD_REQUEST_FAILED"),
    (500, "SOURCE_ACL_STALE", "GUARD_REQUEST_FAILED"),
])
def test_layer1_refusals_are_named_and_never_generate(status, detail, reason):
    generated = []
    result = _rag(status, detail).run(employee_token="t", application_id="app", retrieved=[DOC],
                                      generate=lambda docs: generated.append(docs) or "LEAK")
    assert result.decision == "block" and result.response is None and result.reason == reason
    assert generated == []  # Layer 1 refused: nothing reached the model


def test_gateway_status_mapping_source_contract():
    from pathlib import Path
    src = Path(__file__).resolve().parents[2].joinpath("apps/gateway/accessproof_gateway/app.py").read_text()
    assert '401 if result.reason == "IDENTITY_REJECTED"' in src
    assert '"GUARD_POLICY_DENIED"}' in src
