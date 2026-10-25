"""Malformed OAuth refresh responses cannot replace existing credentials."""
import httpx
import pytest
from packages.auth.oauth_refresh import OAuthCredentials, OAuthRefreshError, refresh_credentials


@pytest.mark.parametrize("response_json", [
    {"access_token": "", "expires_in": 3600},
    {"access_token": "valid", "expires_in": -1},
    {"access_token": "valid", "expires_in": "not-a-number"},
    {"access_token": "valid"},
    {"expires_in": 3600},
    {"access_token": "valid", "expires_in": 0},
])
def test_invalid_oauth_refresh_response_never_overwrites_valid_credentials(response_json):
    saved = []
    client = httpx.Client(transport=httpx.MockTransport(
        lambda _: httpx.Response(200, json=response_json)
    ))
    with pytest.raises(OAuthRefreshError, match="DEGRADED"):
        refresh_credentials(
            OAuthCredentials("existing-token", "existing-refresh"),
            token_endpoint="https://issuer.test/token",
            client_id="id", client_secret="secret",
            save=saved.append, client=client,
        )
    assert saved == []
