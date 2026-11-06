"""The customer chooses exactly one of several discovered RAG applications."""
from __future__ import annotations

from pathlib import Path

import pytest

from apps.gateway.accessproof_gateway import customer_connect
from apps.gateway.accessproof_gateway.application_discovery import discover


def _running_rag(project: str) -> dict:
    return {
        "ID": "a" * 12 if project == "finance" else "b" * 12,
        "Names": project + "-rag-1", "Image": "customer/rag:1", "Ports": "",
        "Labels": {
            "com.docker.compose.project": project,
            "com.docker.compose.service": "rag",
            "com.accessproof.gateway.contract": "accessproof.gateway/v1",
            "com.accessproof.gateway.enforces": "attested-retrieval-and-buffered-output",
            "com.accessproof.gateway.route_env": "ACCESSPROOF_CHAT_URL",
        },
    }


def _mock_candidate_selection(monkeypatch: pytest.MonkeyPatch):
    from apps.gateway.accessproof_gateway import existing_gateway
    rows = [_running_rag("finance"), _running_rag("hr")]
    monkeypatch.setattr(customer_connect, "load_pairing",
                        lambda _path: {"application_id": "test-app", "organization_id": "test-org"})
    monkeypatch.setattr(existing_gateway, "detect", lambda *args, **kwargs: None)
    monkeypatch.setattr(customer_connect, "docker_inventory", lambda: rows)
    selected = []
    def resolve(app, _rows, *, explicit_compose):
        selected.append((app.compose_project, app.service))
        return Path("/synthetic/customer/compose.yml")
    monkeypatch.setattr(customer_connect, "compose_for_selected", resolve)
    def end_before_credential_read(_compose, service):
        selected.append(("target", service))
        raise customer_connect.ConnectError("STOP_BEFORE_KEYS_OR_INSTALL")
    monkeypatch.setattr(customer_connect, "inspect_supported_rag", end_before_credential_read)
    return rows, selected


def test_explicit_choice_resolves_only_target_rag(monkeypatch, capsys):
    rows, selected = _mock_candidate_selection(monkeypatch)
    chosen = next(row for row in discover(rows) if row.compose_project == "hr")
    rc = customer_connect.main([
        "--auto-detect", "--pairing-file", "synthetic-not-read.json",
        "--select", chosen.stable_id, "--approve-install",
    ])
    assert rc == 1
    assert selected == [("hr", "rag"), ("target", "rag")]
    captured = capsys.readouterr()
    assert "Selected ONE chatbot" in captured.out
    assert "STOP_BEFORE_KEYS_OR_INSTALL" in captured.err


def test_invalid_selection_cannot_fall_back_to_another_rag(monkeypatch, capsys):
    rows, selected = _mock_candidate_selection(monkeypatch)
    rc = customer_connect.main([
        "--auto-detect", "--pairing-file", "synthetic-not-read.json",
        "--select", "host-app-does-not-exist", "--approve-install",
    ])
    assert rc == 1
    assert selected == []
    assert "no longer a supported" in capsys.readouterr().err


def test_interactive_selection_one_of_two(monkeypatch, capsys):
    _, selected = _mock_candidate_selection(monkeypatch)
    monkeypatch.setattr(customer_connect.sys, "stdin", type("TTY", (), {"isatty": lambda self: True})())
    monkeypatch.setattr("builtins.input", lambda prompt: "2")
    rc = customer_connect.main([
        "--auto-detect", "--pairing-file", "synthetic-not-read.json",
        "--choose-one", "--approve-install",
    ])
    assert rc == 1
    assert len(selected) == 2
    assert selected[0][0] in {"finance", "hr"}
    assert "Select ONE compatible chatbot" in capsys.readouterr().out


def test_noninteractive_multirag_refuses_to_guess(monkeypatch, capsys):
    _, selected = _mock_candidate_selection(monkeypatch)
    monkeypatch.setattr(customer_connect.sys, "stdin", type("TTY", (), {"isatty": lambda self: False})())
    assert customer_connect.main([
        "--auto-detect", "--pairing-file", "synthetic-not-read.json",
        "--choose-one",
    ]) == 1
    assert selected == []
    assert "--select ONE_ID" in capsys.readouterr().err


def test_repeated_selection_rejected_before_pairing(monkeypatch, capsys):
    monkeypatch.setattr(customer_connect, "load_pairing", lambda _: (_ for _ in ()).throw(AssertionError()))
    assert customer_connect.main(["--select", "a", "--select", "b"]) == 1
    assert "exactly one" in capsys.readouterr().err



def test_many_supported_services_same_compose_requires_explicit_choice(monkeypatch, tmp_path):
    compose = tmp_path / "compose.yaml"
    compose.write_text("services: {}\n")
    labels = {
        "com.accessproof.gateway.contract": "accessproof.gateway/v1",
        "com.accessproof.gateway.enforces": "attested-retrieval-and-buffered-output",
        "com.accessproof.gateway.route_env": "ACCESSPROOF_CHAT_URL",
    }
    monkeypatch.setattr(customer_connect, "_resolved_compose", lambda _: {
        "services": {"finance-rag": {"labels": labels}, "hr-rag": {"labels": labels}, "rag": {"labels": labels}},
    })
    with pytest.raises(customer_connect.ConnectError, match="Choose ONE"):
        customer_connect.inspect_supported_rag(compose, None)
    assert customer_connect.inspect_supported_rag(compose, "hr-rag") == "hr-rag"


def test_infer_key_id_from_selected_rag(monkeypatch, tmp_path):
    compose = tmp_path / "compose.yml"
    compose.write_text("services: {}\n")
    monkeypatch.setattr(customer_connect, "_resolved_compose", lambda _: {
        "services": {"rag": {"environment": {"LAB_ATTESTATION_KEY_ID": "human-validation-ingest-v1"}}},
    })
    assert customer_connect.key_id_from_customer_rag(compose, "rag", "customer-ingestion") == "human-validation-ingest-v1"
    with pytest.raises(customer_connect.ConnectError, match="conflicts"):
        customer_connect.key_id_from_customer_rag(compose, "rag", "wrong-key")
    monkeypatch.setattr(customer_connect, "_resolved_compose", lambda _: {
        "services": {"rag": {"environment": {"LAB_ATTESTATION_KEY_ID": "invalid/name"}}},
    })
    with pytest.raises(customer_connect.ConnectError, match="invalid"):
        customer_connect.key_id_from_customer_rag(compose, "rag", "customer-ingestion")
