"""The compatibility scanner is read-only and evidence-oriented."""
import json
from pathlib import Path

from scripts.compatibility_scan import SCANNER_SCHEMA, main, payload, prometheus_text, scan


def _write(root: Path, name: str, content: str) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


def test_protected_route_and_reauth_cache_are_reported_without_certification(tmp_path):
    _write(tmp_path, "app.py", '''\
from fastapi import FastAPI
from packages.rag_sdk import ProtectedRAG

app = FastAPI()

@app.post("/v1/chat")
def chat():
    return protected.run(employee_token="synthetic", application_id="rag", retrieved=[],
                         generate=lambda _: "answer")

def cached():
    value = cache.get("key")
    return verify_cached_answer(manifest=value, employee_token="synthetic")
''')
    result = payload(tmp_path, scan(tmp_path))
    assert result["schema"] == SCANNER_SCHEMA
    assert result["certification_status"] == "NOT_CERTIFIED"
    assert result["scanner"]["read_only"] is True
    assert result["scanner"]["executed_target_code"] is False
    assert any(item["status"] == "SUPPORTED" for item in result["routes"])
    assert any(item["status"] == "PARTIAL" for item in result["cache_paths"])


def test_direct_model_streaming_cache_websocket_are_blockers(tmp_path):
    _write(tmp_path, "bad.py", '''\
from fastapi import FastAPI, WebSocket
from fastapi.responses import StreamingResponse
from openai import OpenAI
import redis

app = FastAPI()
client = OpenAI(base_url="https://api.openai.com/v1")
cache = redis.Redis()
cache.get("answer")

@app.post("/v1/chat/stream")
def stream():
    return StreamingResponse(iter(["token"]), media_type="text/event-stream")

@app.websocket("/ws")
async def ws(websocket: WebSocket):
    await websocket.accept()
''')
    data = payload(tmp_path, scan(tmp_path))
    blockers = " ".join(data["certification_blockers"])
    assert "Direct model provider endpoint" in blockers
    assert "Cache return path" in blockers
    assert "WebSocket" in blockers
    assert "streaming" in blockers.lower()
    types = {item["type"] for item in data["bypass_findings"]}
    assert {"DIRECT_MODEL_ENDPOINT", "CACHE_WITHOUT_REAUTH", "WEBSOCKET_ROUTE"} <= types
    assert all(item["status"] != "SUPPORTED" for item in data["cache_paths"])


def test_secret_files_and_symlinks_are_not_read_or_echoed(tmp_path):
    secret = tmp_path / ".env"
    secret.write_text("OPENAI_API_KEY=THIS_VALUE_MUST_NOT_APPEAR\n")
    outside = tmp_path.parent / f"{tmp_path.name}-outside.txt"
    outside.write_text("SYMLINK_VALUE_MUST_NOT_APPEAR")
    (tmp_path / "linked.py").symlink_to(outside)
    _write(tmp_path, "app.py", "print('safe')\n")
    data = payload(tmp_path, scan(tmp_path))
    encoded = json.dumps(data)
    assert "THIS_VALUE_MUST_NOT_APPEAR" not in encoded
    assert "SYMLINK_VALUE_MUST_NOT_APPEAR" not in encoded
    assert data["scanner"]["skipped_secret_or_key_files"] >= 1
    outside.unlink()


def test_scanner_does_not_execute_target_code(tmp_path, monkeypatch):
    marker = tmp_path / "executed.marker"
    _write(tmp_path, "danger.py", f"open({str(marker)!r}, 'w').write('executed')\n")
    monkeypatch.chdir(tmp_path)
    assert scan(tmp_path).files_scanned == 1
    assert not marker.exists()


def test_cli_outputs_json_and_prometheus_without_source_text(tmp_path, capsys):
    _write(tmp_path, "bad.py", "import redis\ncache = redis.Redis()\ncache.get('x')\n")
    assert main([str(tmp_path), "--format", "json"]) == 0
    output = capsys.readouterr().out
    assert SCANNER_SCHEMA in output
    assert "cache.get" not in output
    assert main([str(tmp_path), "--format", "prometheus"]) == 0
    metrics = capsys.readouterr().out
    assert "accessproof_scanner_bypass_finding_total" in metrics
    assert "CACHE_WITHOUT_REAUTH" in metrics
    data = payload(tmp_path, scan(tmp_path))
    assert prometheus_text(data).startswith("# HELP accessproof_scanner_bypass_finding_total")
