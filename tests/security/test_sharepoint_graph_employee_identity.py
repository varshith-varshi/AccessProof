"""Graph identity binding must reject spoofed UPNs and cross-identity replies."""
import httpx
import pytest

from connectors.microsoft365.graph_employee_identity import (
    GraphEmployeeIdentityResolver, MicrosoftIdentityResolutionError,
)

TENANT = "6479e7ca-b256-4ebc-a408-871b9046547c"
ALICE_ID = "11111111-2222-3333-4444-555555555555"
BOB_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
UPN = "alice@neuralmatrix093.onmicrosoft.com"


def client_with_status(status: int, data: object) -> httpx.AsyncClient:
    def respond(request: httpx.Request) -> httpx.Response:
        assert str(request.url).startswith("https://graph.microsoft.com/v1.0/users/" + ALICE_ID)
        assert "Authorization" in request.headers
        if status == 302:
            return httpx.Response(302, headers={"Location": "https://evil.invalid/"})
        return httpx.Response(status, json=data)
    return httpx.AsyncClient(transport=httpx.MockTransport(respond))


@pytest.mark.asyncio
async def test_graph_employee_id_binds_a_verified_member_login_name():
    row = {"id": ALICE_ID, "userPrincipalName": UPN.upper(), "accountEnabled": True, "userType": "Member"}
    async with client_with_status(200, row) as http:
        resolver = GraphEmployeeIdentityResolver(tenant_id=TENANT, graph_access_token="synthetic", client=http)
        result = await resolver.verify_employee(object_id=ALICE_ID)
        assert result.object_id == ALICE_ID
        assert result.tenant_id == TENANT
        assert result.user_principal_name == UPN
        assert result.sharepoint_login_name == "i:0#.f|membership|" + UPN


@pytest.mark.parametrize("mutation", [
    {"id": BOB_ID},
    {"userPrincipalName": "attacker@evil.invalid\n"},
    {"userPrincipalName": "guest#EXT#@neuralmatrix093.onmicrosoft.com"},
    {"accountEnabled": False},
    {"accountEnabled": "true"},
    {"userType": "Guest"},
    {"userPrincipalName": None},
])
@pytest.mark.asyncio
async def test_identity_confusion_and_unverified_employee_rejected(mutation):
    row = {"id": ALICE_ID, "userPrincipalName": UPN, "accountEnabled": True, "userType": "Member"}
    row.update(mutation)
    async with client_with_status(200, row) as http:
        resolver = GraphEmployeeIdentityResolver(tenant_id=TENANT, graph_access_token="synthetic", client=http)
        with pytest.raises(MicrosoftIdentityResolutionError, match="IDENTITY_UNVERIFIED"):
            await resolver.verify_employee(object_id=ALICE_ID)


@pytest.mark.parametrize(("status", "code"), [
    (401, "MICROSOFT_GRAPH_USER_READ_PERMISSION_REQUIRED"),
    (403, "MICROSOFT_GRAPH_USER_READ_PERMISSION_REQUIRED"),
    (302, "MICROSOFT_GRAPH_DIRECTORY_UNAVAILABLE"),
    (503, "MICROSOFT_GRAPH_DIRECTORY_UNAVAILABLE"),
])
@pytest.mark.asyncio
async def test_graph_access_errors_fail_closed(status, code):
    async with client_with_status(status, {"detail": "synthetic"}) as http:
        resolver = GraphEmployeeIdentityResolver(tenant_id=TENANT, graph_access_token="synthetic", client=http)
        with pytest.raises(MicrosoftIdentityResolutionError, match=code):
            await resolver.verify_employee(object_id=ALICE_ID)


def test_non_guid_employee_id_rejected_before_network():
    resolver = GraphEmployeeIdentityResolver(tenant_id=TENANT, graph_access_token="synthetic")
    import asyncio
    async def run():
        with pytest.raises(MicrosoftIdentityResolutionError, match="OBJECT_ID_INVALID"):
            await resolver.verify_employee(object_id=UPN)
        await resolver.close()
    asyncio.run(run())
