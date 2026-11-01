"""Fail-closed SharePoint REST permission diagnostics and provider release scope.

Synthetic JWTs in these tests are never accepted as authentication evidence.
"""
import base64
import json

import pytest

from apps.api.accessproof_api.config import (
    Settings,
    certified_sharepoint_scope_allowed,
    v1_source_provider_allowed,
)
from connectors.microsoft365.sharepoint_authorization import diagnose_sharepoint_rest_token

TENANT = "11111111-2222-3333-4444-555555555555"
APP = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
AUD = "00000003-0000-0ff1-ce00-000000000000"


def fake_unsigned_jwt(**payload: object) -> str:
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return "eyJhbGciOiJub25lIn0." + encoded + ".signature-not-verified"


def test_realistic_graph_only_sharepoint_token_fails_safe():
    token = fake_unsigned_jwt(aud=AUD, tid=TENANT, appid=APP, roles=[], appidacr="2")
    assert diagnose_sharepoint_rest_token(token, tenant_id=TENANT, application_id=APP) == [
        "SHAREPOINT_REST_SITES_SELECTED_APP_ROLE_MISSING"
    ]


@pytest.mark.parametrize(
    ("claim_changes", "code"),
    [
        ({"aud": "https://graph.microsoft.com"}, "SHAREPOINT_TOKEN_WRONG_AUDIENCE"),
        ({"tid": "99999999-2222-3333-4444-555555555555"}, "SHAREPOINT_TOKEN_WRONG_TENANT"),
        ({"appid": "99999999-bbbb-cccc-dddd-eeeeeeeeeeee"}, "SHAREPOINT_TOKEN_WRONG_APPLICATION"),
        ({"roles": ["Sites.Read.All"]}, "SHAREPOINT_REST_SITES_SELECTED_APP_ROLE_MISSING"),
    ],
)
def test_wrong_jwt_claims_are_rejected_for_preflight_only(claim_changes, code):
    token = fake_unsigned_jwt(**(dict(aud=AUD, tid=TENANT, appid=APP, roles=["Sites.Selected"], appidacr="2") | claim_changes))
    assert code in diagnose_sharepoint_rest_token(token, tenant_id=TENANT, application_id=APP)


def test_complete_scope_is_diagnostic_not_protect_authorization():
    token = fake_unsigned_jwt(aud=AUD, tid=TENANT, appid=APP, roles=["Sites.Selected"], appidacr="2")
    assert diagnose_sharepoint_rest_token(token, tenant_id=TENANT, application_id=APP) == []
    # Decoding an unsigned token cannot mint a real provider certificate.
    assert not certified_sharepoint_scope_allowed(
        "sharepoint", provider_profile="sharepoint_list_item_effective",
        certificate_verified=False, feature_enabled=True,
    )


def test_client_secret_app_token_is_never_accepted_for_sharepoint_rest_preflight():
    token = fake_unsigned_jwt(aud=AUD, tid=TENANT, appid=APP, roles=["Sites.Selected"], appidacr="1")
    assert diagnose_sharepoint_rest_token(token, tenant_id=TENANT, application_id=APP) == [
        "SHAREPOINT_APP_ONLY_CERTIFICATE_REQUIRED"
    ]


@pytest.mark.parametrize("token", ["", "not-a-jwt", "a.b.c", "a.@@@.c", "a.W10.c"])
def test_bad_token_format_fails_closed(token):
    assert diagnose_sharepoint_rest_token(token, tenant_id=TENANT, application_id=APP) == [
        "SHAREPOINT_JWT_UNREADABLE"
    ]


def test_sharepoint_explicit_release_and_valid_source_certificate_are_both_required():
    production = Settings(env="production")
    assert v1_source_provider_allowed("google-drive", production)
    assert not v1_source_provider_allowed("sharepoint", production)
    for enabled, certificate, expected in (
        (False, True, False), (True, False, False), (True, True, True),
    ):
        assert certified_sharepoint_scope_allowed(
            "sharepoint", provider_profile="sharepoint_list_item_effective",
            certificate_verified=certificate, feature_enabled=enabled,
        ) is expected
    # Existing canonical microsoft365 SharePoint profiles are supported,
    # but their OneDrive profiles and unknown sources are NEVER eligible.
    assert certified_sharepoint_scope_allowed(
        "microsoft365", provider_profile="sharepoint_list_item_effective",
        certificate_verified=True, feature_enabled=True,
    )
    for provider, profile in (
        ("onedrive", "onedrive_owner_and_sharing_effective"),
        ("microsoft365", "onedrive_owner_and_sharing_effective"),
        ("unknown", "sharepoint_list_item_effective"),
        ("SHAREPOINT", "sharepoint_list_item_effective"),
    ):
        assert not certified_sharepoint_scope_allowed(
            provider, provider_profile=profile,
            certificate_verified=True, feature_enabled=True,
        )
