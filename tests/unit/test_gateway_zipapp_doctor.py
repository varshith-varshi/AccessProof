"""Read-only onboarding diagnostics must not mask an unhealthy source."""
import importlib.util
import json
from pathlib import Path
import subprocess
from unittest.mock import MagicMock, patch

PATH = Path(__file__).resolve().parents[2] / "scripts/gateway_customer_zipapp_main.py"
spec = importlib.util.spec_from_file_location("gateway_zipapp_main", PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

def check(
    health: dict, *,
    status: str = "Up 1 hour (healthy)",
    name: str = "sharepoint-rag-lab-accessproof-gateway-1",
    presence: bool = True,
    requested: str | None = None,
):
    env = ["ACCESSPROOF_GATEWAY_APPLICATION_ID=demo-rag"]
    if presence:
        env.extend([
            "ACCESSPROOF_GATEWAY_PRESENCE_CONTROL_PLANE_URL=https://api.accessproof.in",
            "ACCESSPROOF_GATEWAY_PRESENCE_ORGANIZATION_ID=org",
            "ACCESSPROOF_GATEWAY_PRESENCE_INSTALLATION_ID=install",
            "ACCESSPROOF_GATEWAY_PRESENCE_CREDENTIAL=SECRET-MUST-NOT-APPEAR",
            "ACCESSPROOF_GATEWAY_PRESENCE_ROUTE_SHA256=" + "a" * 64,
        ])
    responses = {
        "ps": subprocess.CompletedProcess(["docker", "ps"], 0,
            stdout=json.dumps({"Names": name, "Status": status}) + "\n"),
        "inspect": subprocess.CompletedProcess(["docker", "inspect"], 0,
            stdout=json.dumps([{"Config": {"Env": env}}])),
        "exec": subprocess.CompletedProcess(["docker", "exec"], 0,
            stdout=json.dumps({"status": health.get("http_status", 200),
                               "body": json.dumps(health)})),
    }
    calls = []
    def fake_run(command, **kwargs):
        calls.append(command)
        assert command[0] == "docker"
        assert all(part != "--privileged" for part in command)
        return responses[command[1]]
    with patch.object(module.subprocess, "run", side_effect=fake_run):
        result = module.diagnose_local_gateway(
            project="sharepoint-rag-lab", gateway_container=requested,
        )
    return result, calls


def test_ready_requires_actual_gateway_guard_and_presence():
    (ready, notes), calls = check({"status": "ok"})
    assert ready
    assert any("Gateway-to-Guard: enforcement readiness passed" in note for note in notes)
    assert any("heartbeat: locally configured" in note for note in notes)
    assert [call[1] for call in calls] == ["ps", "inspect", "exec"]
    assert "SECRET-MUST-NOT-APPEAR" not in repr(notes)


def test_missing_presence_fails_even_when_gateway_and_guard_are_healthy():
    (ready, notes), _ = check({"status": "ok"}, presence=False)
    assert not ready
    assert any("heartbeat: NOT CONFIGURED" in note for note in notes)


def test_gateway_guard_unavailable_has_specific_diagnosis():
    (ready, notes), _ = check(
        {"detail": "GUARD_UNAVAILABLE", "http_status": 503},
    )
    assert not ready
    assert any("GUARD_UNAVAILABLE" in note for note in notes)


def test_gateway_guard_not_ready_has_specific_diagnosis():
    (ready, notes), _ = check(
        {"detail": "GUARD_NOT_READY", "http_status": 503},
    )
    assert not ready
    assert any("GUARD_NOT_READY" in note for note in notes)


def test_unhealthy_gateway_fails_closed():
    (ready, notes), _ = check(
        {"status": "ok"}, status="Up 1 hour (unhealthy)",
    )
    assert not ready
    assert any("UNHEALTHY" in note for note in notes)


def test_another_tenant_gateway_does_not_match():
    (ready, notes), calls = check(
        {"status": "ok"}, name="other-customer-accessproof-gateway-1",
    )
    assert not ready
    assert any("no unique" in note for note in notes)
    assert [call[1] for call in calls] == ["ps"]


def test_explicit_legacy_name_is_inspected_not_implicitly_selected():
    (ready, notes), calls = check(
        {"status": "ok"}, name="ap-remote-gateway",
        requested="ap-remote-gateway",
    )
    assert ready
    assert len(calls) == 3


def test_pinned_https_doctor_never_overrides_missing_heartbeat(tmp_path, monkeypatch):
    ca = tmp_path / "customer-ca.pem"
    ca.write_text("synthetic-not-a-real-ca")
    entries = ["ACCESSPROOF_GATEWAY_APPLICATION_ID=reference-rag"]
    container = {"Config": {"Env": entries}, "NetworkSettings": {
        "Ports": {"8443/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8443"}]}
    }}
    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        if command[1] == "ps":
            return subprocess.CompletedProcess(command, 0,
                stdout=json.dumps({"Names": "ap-remote-gateway", "Status": "Up 3 days"}) + "\n")
        if command[1] == "inspect":
            return subprocess.CompletedProcess(command, 0, stdout=json.dumps([container]))
        raise AssertionError("HTTPS diagnosis must not shell into the container")

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    with patch.object(module, "pinned_tls_gateway_health", return_value=True) as tls:
        ready, notes = module.diagnose_local_gateway(
            project="manual", gateway_container="ap-remote-gateway",
            gateway_ca_file=ca, gateway_hostname="gateway.example.com",
        )
    assert not ready
    assert any("verified HTTPS readiness passed" in note for note in notes)
    assert any("heartbeat: NOT CONFIGURED" in note for note in notes)
    assert [cmd[1] for cmd in commands] == ["ps", "inspect"]
    assert tls.call_count == 1


def test_https_health_refuses_unsafe_bindings_and_tls_files(tmp_path):
    ca = tmp_path / "trusted.pem"
    ca.write_text("synthetic")
    for mapping in (
        [{"HostIp": "0.0.0.0", "HostPort": "8443"}],
        [{"HostIp": "127.0.0.1", "HostPort": "abc"}],
        [{"HostIp": "127.0.0.1", "HostPort": "8443"}] * 2,
        None,
    ):
        container = {"NetworkSettings": {"Ports": {"8443/tcp": mapping}}}
        assert not module.pinned_tls_gateway_health(
            container, ca_file=ca, hostname="gateway.example.com",
        )
    good = {"NetworkSettings": {"Ports": {"8443/tcp": [{
        "HostIp": "127.0.0.1", "HostPort": "8443"}]}}}
    assert not module.pinned_tls_gateway_health(
        good, ca_file=ca, hostname="bad..name",
    )
    link = tmp_path / "ca-link.pem"
    link.symlink_to(ca)
    assert not module.pinned_tls_gateway_health(
        good, ca_file=link, hostname="gateway.example.com",
    )


def test_install_runs_automatic_doctor_even_when_guard_is_not_ready(tmp_path, monkeypatch, capsys):
    """Installer succeeds as an install but never falsely certifies Guard."""
    import sys
    import zipfile

    workdir = tmp_path / "customer-rag"
    workdir.mkdir()
    monkeypatch.chdir(workdir)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    pairing = tmp_path / "private-pairing.json"
    pairing.write_text('{"synthetic":"credential-not-used"}')
    pairing.chmod(0o600)
    archive = tmp_path / "installer.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("__main__.py", "pass")
        z.writestr("accessproof-gateway-connector/connect.sh", "#!/bin/sh\nexit 0\n")
    monkeypatch.setattr(sys, "argv", [str(archive), "--pairing-file", str(pairing)])
    monkeypatch.setattr(module.shutil, "which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs:
                        subprocess.CompletedProcess(args[0], 0))
    paired = []
    monkeypatch.setattr(module.subprocess, "call", lambda command, env=None:
                        paired.append(command) or 0)
    diagnosed = []
    monkeypatch.setattr(module, "diagnose_local_gateway", lambda **kwargs:
                        (diagnosed.append(kwargs) or False, ["Guard: NOT READY"]))
    with __import__("pytest").raises(SystemExit) as exc:
        module.main()
    assert exc.value.code == 0
    assert len(paired) == 1
    assert "--approve-install" in paired[0]
    assert len(diagnosed) == 1
    output = capsys.readouterr().out
    assert "Guard: NOT READY" in output
    assert "Protect is NOT certified" in output
