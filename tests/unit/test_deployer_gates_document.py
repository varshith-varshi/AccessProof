"""The production gates SSM document must stay read-only and parameter-safe."""
from __future__ import annotations

import importlib.util
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILDER = ROOT / "deploy/deployer/build_ssm_documents.py"
DOCUMENT = ROOT / "deploy/deployer/ssm/AccessProof-Deployer-ProductionGates.json"
POLICY = ROOT / "deploy/deployer/iam-policy-production-deployer.json"


def _builder():
    spec = importlib.util.spec_from_file_location("accessproof_deployer_doc_gates", BUILDER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_generated_gates_document_matches_builder():
    assert json.loads(DOCUMENT.read_text()) == _builder().gates()
    assert json.loads(POLICY.read_text()) == _builder().role_policy()


def test_gates_parameters_are_validated_env_vars_only():
    params = _builder().gates()["parameters"]
    assert set(params) == {"organizationId", "applicationId", "evidenceGzipB64"}
    for spec in params.values():
        assert spec["interpolationType"] == "ENV_VAR" and spec["allowedPattern"].startswith("^")
    assert params["evidenceGzipB64"]["default"] == "none"
    assert not re.fullmatch(params["evidenceGzipB64"]["allowedPattern"], "$(id)")
    assert re.fullmatch(params["evidenceGzipB64"]["allowedPattern"], "none")
    assert not re.fullmatch(params["applicationId"]["allowedPattern"], "app; rm -rf /")
    assert not re.fullmatch(params["organizationId"]["allowedPattern"], "$(id)")
    commands = "\n".join(_builder().gates()["mainSteps"][0]["inputs"]["runCommand"])
    # AWS SSM parses every {{...}} token as a document parameter, including
    # Docker Go-template expressions such as {{else}}.
    assert "{{" not in commands
    assert subprocess.run(["bash", "-n"], input=commands, text=True,
                          capture_output=True, check=False).returncode == 0


def test_gates_document_is_read_only():
    commands = "\n".join(_builder().gates()["mainSteps"][0]["inputs"]["runCommand"])
    for verb in (" up ", " down", " restart", " rm ", " stop", "alembic upgrade", "DROP ", "DELETE ",
                 "UPDATE ", "INSERT ", "docker cp", " pull", "curl -X POST"):
        assert verb not in commands, verb
    assert 'test "$SELF" = "i-0c11427d4d9c1b438"' in commands      # pinned to production instance


def test_deployer_policy_allows_gates_but_still_denies_document_changes():
    policy = json.loads(POLICY.read_text())
    allow = next(s for s in policy["Statement"] if s["Effect"] == "Allow" and "ssm:SendCommand" in s["Action"])
    assert any(r.endswith("document/AccessProof-Deployer-ProductionGates") for r in allow["Resource"])
    deny = next(s for s in policy["Statement"] if s["Sid"] == "NoInteractiveAccessOrAuthorityChanges")
    assert {"ssm:CreateDocument", "ssm:UpdateDocument", "iam:*"} <= set(deny["Action"])
