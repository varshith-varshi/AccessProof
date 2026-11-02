import pytest

from apps.gateway.accessproof_gateway import application_discovery
from apps.gateway.accessproof_gateway.application_discovery import DiscoveryError, discover, published_host_ports


def _row(name, project, service, image="customer-rag:1", labels=None):
    values = {"com.docker.compose.project": project, "com.docker.compose.service": service}
    values.update(labels or {})
    return {"Names": name, "Image": image, "Labels": values}


def test_only_declared_contract_is_supported_and_non_ai_is_not_presented_as_chatbot():
    rows = [
        _row("finance-rag-1", "finance", "finance-rag", labels={
            "com.accessproof.gateway.contract": "accessproof.gateway/v1",
            "com.accessproof.gateway.enforces": "attested-retrieval-and-buffered-output",
            "com.accessproof.gateway.route_env": "ACCESSPROOF_CHAT_URL",
        }),
        _row("finance-db-1", "finance", "postgres"),
        _row("accessproof-gateway-1", "finance", "accessproof-gateway"),
    ]
    result = discover(rows)
    assert [(item.display_name, item.state) for item in result] == [
        ("finance-rag", "SUPPORTED"), ("postgres", "NON_AI_SERVICE"),
    ]


def test_multiple_projects_same_service_name_have_distinct_stable_identities():
    result = discover([_row("hr-rag", "hr", "rag"), _row("finance-rag", "finance", "rag")])
    assert len(result) == 2
    assert result[0].stable_id != result[1].stable_id
    assert {item.state for item in result} == {"REQUIRES_INTEGRATION"}


def test_malformed_or_unidentified_rows_are_not_guessed_as_supported():
    result = discover([{"Names": "mystery", "Image": "x"}, {"Names": "bad", "Labels": 4}])
    assert [item.state for item in result] == ["AMBIGUOUS", "AMBIGUOUS"]


def test_docker_inventory_is_bounded_sanitized_and_read_only(monkeypatch):
    class Completed:
        stdout = '{"ID":"1","Names":"finance-rag","Image":"rag:1","Labels":"x=y","Env":"secret"}\n'

    seen = {}
    def fake_run(command, **kwargs):
        seen["command"] = command
        seen["kwargs"] = kwargs
        return Completed()

    monkeypatch.setattr(application_discovery.subprocess, "run", fake_run)
    assert application_discovery.docker_inventory() == [{
        "ID": "1", "Names": "finance-rag", "Image": "rag:1", "State": None,
        "Status": None, "Labels": "x=y", "Ports": None,
    }]
    assert seen["command"] == ["docker", "ps", "--format", "{{json .}}"]
    assert seen["kwargs"]["timeout"] == 15


def test_docker_inventory_rejects_malformed_rows(monkeypatch):
    class Completed:
        stdout = "not-json\n"

    monkeypatch.setattr(application_discovery.subprocess, "run", lambda *args, **kwargs: Completed())
    with pytest.raises(DiscoveryError, match="INVALID"):
        application_discovery.docker_inventory()


def test_connector_discovery_is_read_only_and_needs_no_pairing(monkeypatch, capsys):
    from apps.gateway.accessproof_gateway import customer_connect

    rows = [_row("finance-rag", "finance", "finance-rag", labels={
        "com.accessproof.gateway.contract": "accessproof.gateway/v1",
        "com.accessproof.gateway.enforces": "attested-retrieval-and-buffered-output",
        "com.accessproof.gateway.route_env": "ACCESSPROOF_CHAT_URL",
    })]
    monkeypatch.setattr(customer_connect, "docker_inventory", lambda: rows)
    assert customer_connect.main(["--discover"]) == 0
    output = capsys.readouterr().out
    assert '"certification_status": "NOT_CERTIFIED"' in output
    assert '"state": "SUPPORTED"' in output


def test_published_port_inventory_is_bounded_and_does_not_guess_unparseable_data():
    assert published_host_ports([
        {"Ports": "127.0.0.1:18090->8090/tcp, 0.0.0.0:5432->5432/tcp"},
        {"Ports": "not a docker port"},
    ]) == {18090, 5432}


def test_invalid_route_variable_never_counts_as_supported() -> None:
    rows = [_row("finance-rag", "finance", "finance-rag", labels={
        "com.accessproof.gateway.contract": "accessproof.gateway/v1",
        "com.accessproof.gateway.enforces": "attested-retrieval-and-buffered-output",
        "com.accessproof.gateway.route_env": "BAD-NAME",
    })]
    assert discover(rows)[0].state == "REQUIRES_INTEGRATION"


def test_rag_in_storage_is_not_a_chatbot() -> None:
    result = discover([_row("storage", "company", "storage")])
    assert result[0].state == "NON_AI_SERVICE"


def test_unidentified_service_with_forged_contract_is_not_supported() -> None:
    row = _row("mystery", "finance", "finance-rag", labels={
        "com.accessproof.gateway.contract": "accessproof.gateway/v1",
        "com.accessproof.gateway.enforces": "attested-retrieval-and-buffered-output",
        "com.accessproof.gateway.route_env": "VALID_CHAT_URL",
    })
    row["Labels"].pop("com.docker.compose.service")
    assert discover([row])[0].state == "AMBIGUOUS"


def test_malformed_row_does_not_suppress_following_valid_rag() -> None:
    found = discover([{"Names": "unknown"}, None, _row("finance-rag", "finance", "finance-rag")])
    assert any(item.service == "finance-rag" for item in found)


def test_oversized_docker_inventory_fails_instead_of_silently_truncating(monkeypatch) -> None:
    class Completed:
        stdout = ('{"Names":"unknown","Image":"rag:1"}\n') * (application_discovery.MAX_CONTAINERS + 1)
    monkeypatch.setattr(application_discovery.subprocess, "run", lambda *args, **kwargs: Completed())
    with pytest.raises(DiscoveryError, match="TRUNCATED"):
        application_discovery.docker_inventory()
