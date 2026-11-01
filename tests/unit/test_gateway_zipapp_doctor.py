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

class FakeHTTP:
    def __init__(self, response):
        self.response = response
    def request(self, method, path):
        assert (method, path) == ("GET", "/health")
    def getresponse(self):
        return self.response
    def close(self):
        pass

def check(guard, status="Up 1 hour (healthy)", *, name="sharepoint-rag-lab-accessproof-gateway-1"):
    process = subprocess.CompletedProcess(
        args=["docker", "ps"], returncode=0,
        stdout=json.dumps({"Names": name, "Status": status}) + "\n",
    )
    response = MagicMock()
    response.status = 200
    response.read.return_value = json.dumps(guard).encode()
    with patch.object(module.subprocess, "run", return_value=process) as docker, patch(
        "http.client.HTTPConnection", return_value=FakeHTTP(response)
    ) as client:
        result = module.diagnose_local_gateway(project="sharepoint-rag-lab")
    assert docker.call_count == 1
    assert client.call_count == 1
    return result

def test_only_healthy_guard_and_gateway_ready():
    ready, notes = check({"ready": True, "status": "ok"})
    assert ready
    assert any("Guard: ready" in x for x in notes)

def test_source_acl_not_ready_fails_closed():
    ready, notes = check({"ready": False, "status": "degraded", "policy_version": 8})
    assert not ready
    assert any("NOT READY" in x for x in notes)
    assert not any(x.startswith("Guard: ready") for x in notes)

def test_stale_guard_fails_closed():
    ready, notes = check({"ready": False, "status": "degraded", "policy_fresh": False})
    assert not ready
    assert any("stale" in x for x in notes)

def test_unhealthy_gateway_fails_closed():
    ready, notes = check({"ready": True, "status": "ok"}, status="Up 1 hour (unhealthy)")
    assert not ready
    assert any("Gateway: not healthy" in x for x in notes)

def test_another_tenant_gateway_does_not_match():
    ready, notes = check({"ready": True, "status": "ok"}, name="other-customer-accessproof-gateway-1")
    assert not ready
    assert any("no unique" in x for x in notes)


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
