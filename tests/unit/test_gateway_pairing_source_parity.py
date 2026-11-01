"""Never silently delete production Gateway pairing routes on API rebuild."""
from apps.api.accessproof_api.app import app


def test_customer_gateway_pairing_routes_are_in_canonical_api_source():
    actual = {
        (route.path, verb)
        for route in app.routes
        if hasattr(route, "path")
        for verb in getattr(route, "methods", ())
    }
    required = {
        ("/api/v1/current/ai-applications/{application_id}/gateway-pairing", "POST"),
        ("/api/v1/current/ai-applications/{application_id}/gateway-pairing", "GET"),
        ("/api/v1/gateway-pairings/claim", "POST"),
    }
    assert required.issubset(actual)


def test_gateway_claim_does_not_return_200_without_machine_credential():
    from fastapi.testclient import TestClient

    result = TestClient(app).post("/api/v1/gateway-pairings/claim", json={})
    assert result.status_code == 401
    assert "PAIRING_TOKEN_REQUIRED" in result.text
