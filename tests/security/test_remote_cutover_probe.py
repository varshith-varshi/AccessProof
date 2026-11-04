"""Remote-mode cutover: refused unless the control plane reports the remote
route CERTIFIED; otherwise the same allow/deny/tamper evidence is produced."""
import json

import httpx
import pytest

from apps.gateway.accessproof_gateway.cutover_agent import EmployeeRouteProbe, probe_remote_employee_route
from apps.gateway.accessproof_gateway.customer_agent import CustomerAgentError

NONCE = "n" * 40
RES = [{"source_id": "s", "resource_id": "r", "chunk_id": "c", "content": "shared ALLOWCANARY", "content_version": "v",
        "content_attestation": "att"}]


def _client():
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        rid = body["request_id"]
        if rid.endswith("-deny"):
            return httpx.Response(403, json={"detail": {"code": "NO_AUTHORIZED_RESOURCES"}})
        if rid.endswith("-tamper"):
            return httpx.Response(503, json={"detail": {"code": "SOURCE_CONTENT_ATTESTATION_FAILED"}})
        return httpx.Response(200, json={"choices": [{"message": {"content": "ALLOWCANARY"}}],
                                         "accessproof": {"decision": "allow", "decision_id": "d1"}})
    return httpx.Client(transport=httpx.MockTransport(handler), base_url="http://127.0.0.1:9444")


def _probe():
    return EmployeeRouteProbe(url="http://127.0.0.1:9444/v1/chat/completions", allowed_token="a" * 20, denied_token="b" * 20,
                              allowed_resources=RES, denied_resources=RES, allowed_canary="ALLOWCANARY",
                              forbidden_canary="FORBIDDENCANARY")


@pytest.mark.parametrize("status", [None, {}, {"applicable": False, "certified": False},
                                    {"applicable": True, "certified": False}])
def test_remote_cutover_refused_without_certified_remote_route(status):
    with pytest.raises(CustomerAgentError, match="REMOTE_ROUTE_NOT_CERTIFIED"):
        probe_remote_employee_route(remote_route_status=status, application_id="app", nonce=NONCE, probe=_probe(),
                                    client=_client())


def test_remote_cutover_evidence_when_certified():
    ev = probe_remote_employee_route(remote_route_status={"applicable": True, "certified": True}, application_id="app",
                                     nonce=NONCE, probe=_probe(), client=_client())
    assert ev["negative_reason_code"] == "NO_AUTHORIZED_RESOURCES" and ev["tamper_reason_code"] == "SOURCE_CONTENT_ATTESTATION_FAILED"
    assert ev["decision_id"] == "d1" and ev["application_request_id"].startswith("ap-cutover-")
