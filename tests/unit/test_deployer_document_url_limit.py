"""Offline regressions for long AWS STS presigned release URLs.

The SSM document uses RE2: counted repetitions >1000 fail document
registration, so inspect both the source builder and generated output.
"""
from __future__ import annotations

import base64
import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILDER = ROOT / "deploy/deployer/build_ssm_documents.py"
DOCUMENT = ROOT / "deploy/deployer/ssm/AccessProof-Deployer-ProductionRelease.json"


def _builder_document() -> dict:
    spec = importlib.util.spec_from_file_location("accessproof_deployer_doc", BUILDER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.release()


def test_release_document_has_consistent_generated_content() -> None:
    assert json.loads(DOCUMENT.read_text()) == _builder_document()


def test_long_aws_session_signed_urls_are_accepted_by_input_pattern() -> None:
    doc = json.loads(DOCUMENT.read_text())
    pattern = doc["parameters"]["artifactUrlB64"]["allowedPattern"]
    # Long presigned URLs occur with AWS Roles Anywhere sessions.
    value = base64.b64encode(b"A" * 1708).decode("ascii")
    assert len(value) == 2280
    assert re.fullmatch(pattern, value)
    assert re.fullmatch(pattern, "bad-signed-url_contains-underscore") is None
    # In AWS SSM's RE2 validator, {n,m} with counts above 1000 fails.
    counts = re.findall(r"\{(\d+)(?:,(\d+))?\}", pattern)
    assert all(int(n) <= 1000 and (not m or int(m) <= 1000) for n, m in counts)


def test_url_length_is_enforced_separately_before_decode() -> None:
    doc = json.loads(DOCUMENT.read_text())
    commands = doc["mainSteps"][0]["inputs"]["runCommand"]
    length_check = next(i for i, command in enumerate(commands) if "url_len=${#SSM_artifactUrlB64}" in command)
    decoder = next(i for i, command in enumerate(commands) if "base64 -d" in command)
    assert length_check < decoder
    assert '"$url_len" -ge 100' in commands[length_check]
    assert '"$url_len" -le 4096' in commands[length_check]
    assert doc["parameters"]["artifactUrlB64"]["interpolationType"] == "ENV_VAR"


def test_release_routes_web_labels_to_web_only_script() -> None:
    doc = json.loads(DOCUMENT.read_text())
    commands = "\n".join(doc["mainSteps"][0]["inputs"]["runCommand"])
    assert 'deploy/ec2-release/deploy_on_ec2.sh' in commands
    script = (ROOT / "deploy/ec2-release/deploy_on_ec2.sh").read_text()
    assert "deploy_web_only_on_ec2.sh" in script
    assert "web-" in script
