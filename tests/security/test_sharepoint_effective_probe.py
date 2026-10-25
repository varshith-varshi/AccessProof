"""Controlled read-only SharePoint effective permission validation."""
import httpx
import pytest

from connectors.microsoft365.sharepoint_effective import (
    SharePointEffectiveAccessProbe, SharePointPermissionError,
    _parse_effective_permissions, _trusted_site_url,
)


def test_microsoft_sharepoint_effective_mask_explicit_read_and_deny():
    assert _parse_effective_permissions({"High": "0", "Low": "1"}) is True
    assert _parse_effective_permissions({
        "d": {"GetUserEffectivePermissions": {"High": "0", "Low": "0"}}
    }) is False
    assert _parse_effective_permissions({"High": "0", "Low": 2}) is False
    for malformed in (
        {}, [], {"Low": "1"}, {"High": "0", "Low": "-1"},
        {"High": "0", "Low": "not-an-int"}, {"High": "0", "Low": "4294967296"},
    ):
        with pytest.raises(SharePointPermissionError):
            _parse_effective_permissions(malformed)


@pytest.mark.parametrize("url", [
    "http://company.sharepoint.com/sites/Finance",
    "https://company.sharepoint.com.evil.test/sites/Finance",
    "https://localhost/sites/Finance",
    "https://169.254.169.254/latest/meta-data",
    "https://company.sharepoint.com:444/sites/Finance",
    "https://company.sharepoint.com/sites/../Admin",
    "https://company.sharepoint.com/sites/Finance?redirect=https://attacker.example",
])
def test_sharepoint_endpoint_rejects_untrusted_site_urls(url):
    with pytest.raises(SharePointPermissionError):
        _trusted_site_url(url)


@pytest.mark.asyncio
async def test_sharepoint_effective_probe_safely_encodes_verified_login_name():
    captured = []
    def handler(req: httpx.Request):
        captured.append(req)
        return httpx.Response(200, json={"High": "0", "Low": "1"})
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    probe = SharePointEffectiveAccessProbe(
        site_url="https://company.sharepoint.com/sites/Finance",
        sharepoint_access_token="fake-SPO-audience-token", client=client,
    )
    try:
        can_read = await probe.can_view_item(
            list_id="11111111-2222-3333-4444-555555555555",
            item_id=32,
            verified_login_name="i:0#.f|membership|rahul@company.com",
        )
        assert can_read is True
        assert captured[0].url.host == "company.sharepoint.com"
        assert captured[0].url.params["@u"] == "'i:0#.f|membership|rahul@company.com'"
        assert "/items(32)/getusereffectivepermissions(@u)" in captured[0].url.path.lower()
        assert captured[0].headers["authorization"] == "Bearer fake-SPO-audience-token"
        with pytest.raises(SharePointPermissionError):
            await probe.can_view_item(list_id="../wrong", item_id=1, verified_login_name="test")
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_sharepoint_effective_probe_rejects_partial_or_unauthorized_api():
    for status, body in ((200, {}), (403, {}), (500, {})):
        client = httpx.AsyncClient(transport=httpx.MockTransport(
            lambda _, code=status, payload=body: httpx.Response(code, json=payload)
        ))
        probe = SharePointEffectiveAccessProbe(
            site_url="https://company.sharepoint.com/sites/Finance",
            sharepoint_access_token="test", client=client,
        )
        try:
            with pytest.raises(SharePointPermissionError):
                await probe.can_view_item(
                    list_id="11111111-2222-3333-4444-555555555555",
                    item_id=1, verified_login_name="verified-user",
                )
        finally:
            await client.aclose()
