import pytest
from packages.connector_sdk.http_target import validate_cloud_url


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com",
        "https://localhost/",
        "https://127.0.0.1/",
        "https://169.254.169.254/latest/meta-data/",
    ],
)
def test_cloud_target_ssrf_rejected(url):
    with pytest.raises(ValueError):
        validate_cloud_url(url)
