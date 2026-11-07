"""D-17: adopting a Gateway that lacks installer metadata must keep the
claim-issued heartbeat credential (privately), not discard it."""
import stat

from apps.gateway.accessproof_gateway import customer_connect as cc
from apps.gateway.accessproof_gateway import existing_gateway

PRESENCE = {
    "control_plane_url": "https://api.accessproof.in", "organization_id": "org-1",
    "installation_id": "inst-1", "credential": "never-printed-heartbeat-credential",
    "route_sha256": "a" * 64,
}


def _run(monkeypatch, tmp_path, capsys, presence):
    monkeypatch.setattr(cc, "load_pairing", lambda path: {"application_id": "app", "control_plane_url": "https://api.accessproof.in", "pairing_token": "t", "expires_at": "2099-01-01T00:00:00Z"})
    monkeypatch.setattr(existing_gateway, "detect", lambda pairing, container_name=None: {"gateway": "manual", "_local_installation": None})
    claim = {"state": "installation_reported"}
    if presence is not None:
        claim["gateway_presence"] = presence
    monkeypatch.setattr(cc, "report_claim", lambda pairing, existing: claim)
    monkeypatch.setattr(cc, "summarize_automatic_verification", lambda claim: [])
    called = []
    monkeypatch.setattr(cc, "enable_gateway_presence", lambda *a, **k: called.append(a) or True)
    pairing = tmp_path / "pairing.json"
    pairing.write_text("{}")
    out = tmp_path / "out"
    rc = cc.main(["--pairing-file", str(pairing), "--adopt-existing", "--approve-install", "--output", str(out)])
    messages = capsys.readouterr()
    return rc, out, messages.out, called, messages.err


def test_manual_gateway_credential_is_saved_privately(monkeypatch, tmp_path, capsys):
    rc, out, printed, called, errors = _run(monkeypatch, tmp_path, capsys, PRESENCE)
    assert rc == 2 and not called  # no Docker recreate; unconnected must not report success
    env = out / "gateway-presence.env"
    assert env.is_file()
    assert stat.S_IMODE(env.stat().st_mode) == 0o600 and stat.S_IMODE(out.stat().st_mode) == 0o700
    body = env.read_text()
    assert "ACCESSPROOF_GATEWAY_PRESENCE_CREDENTIAL=never-printed-heartbeat-credential" in body
    assert "ACCESSPROOF_GATEWAY_PRESENCE_INSTALLATION_ID=inst-1" in body
    assert "never-printed-heartbeat-credential" not in printed
    assert "saved privately" in printed
    assert "SETUP_INCOMPLETE" in errors
    assert "No Docker containers or RAG routes changed" in printed


def test_no_credential_issued_reports_unknown(monkeypatch, tmp_path, capsys):
    rc, out, printed, _, errors = _run(monkeypatch, tmp_path, capsys, None)
    assert rc == 2 and not (out / "gateway-presence.env").exists()
    assert "SETUP_INCOMPLETE" in errors
    assert "Existing Gateway paired" in printed
