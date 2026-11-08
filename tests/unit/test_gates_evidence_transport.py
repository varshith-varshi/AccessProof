"""Read-only production gate evidence transport cannot forge current certification."""
from __future__ import annotations

import base64
import gzip
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from deploy.deployer import build_ssm_documents as b
from scripts import gates_evidence_transport as transport

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / "docs/evidence/certificate-renewals/20261104T153209Z/source-certification-evidence.json"
PILOT = ROOT / "docs/evidence/pilot-and-automation-2026-11-05/pilot-source-certificate-evidence/source-certification-evidence.json"
REF_ORG = "48ee8c86-d4d8-4cde-b00b-bc779f965f4f"
PILOT_ORG = "0fb98b25-bd7d-445e-a192-4ff8ee730760"


def _decode_host_code(encoded: str, *, org: str) -> subprocess.CompletedProcess:
    # Exercise the EXACT Python code embedded into the AWS SSM gates document.
    cmd = b.gates_bundle_command("docker compose -f docker-compose.ec2.yml")
    code = cmd.split("<<'PYGATES'\n", 1)[1].rsplit("PYGATES\n)", 1)[0]
    states = ["healthy", "running", "healthy", "healthy", "healthy", "head", "head", "1"]
    env = {**os.environ, "SSM_evidenceGzipB64": encoded, "SSM_organizationId": org}
    return subprocess.run([sys.executable, "-", *states], input=code, text=True,
                          env=env, capture_output=True, check=False, timeout=10)


@pytest.mark.parametrize("path,org", [(REFERENCE, REF_ORG), (PILOT, PILOT_ORG)])
def test_real_previously_issued_evidence_round_trips(path: Path, org: str):
    encoded = transport.encode(path, organization_id=org)
    assert len(encoded) <= transport.MAX_ENCODED
    payload = json.loads(gzip.decompress(base64.b64decode(encoded)))
    assert payload["organization_id"] == org
    assert len(payload["checks"]) == 14
    done = _decode_host_code(encoded, org=org)
    assert done.returncode == 0, done.stderr
    bundle = json.loads(done.stdout)
    assert bundle["evidence"] == payload
    assert bundle["host_facts"]["migration_at_head"] is True
    assert bundle["host_facts"]["rollback_available"] is True


def test_missing_evidence_remains_blocked():
    done = _decode_host_code("none", org=REF_ORG)
    assert done.returncode == 0
    assert json.loads(done.stdout)["evidence"] is None


def test_cross_organization_and_untrusted_locations_are_rejected(tmp_path: Path):
    with pytest.raises(transport.EvidenceRejected, match="ORGANIZATION_MISMATCH"):
        transport.encode(REFERENCE, organization_id=PILOT_ORG)
    outside = tmp_path / "source-certification-evidence.json"
    outside.write_text(REFERENCE.read_text())
    with pytest.raises(transport.EvidenceRejected, match="OUTSIDE_APPROVED"):
        transport.encode(outside, organization_id=REF_ORG)
    assert _decode_host_code(transport.encode(REFERENCE, organization_id=REF_ORG),
                             org=PILOT_ORG).returncode != 0


def test_tampered_or_unsigned_local_record_refused(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(transport, "EVIDENCE_DIR", tmp_path.resolve())
    directory = tmp_path / "canary"
    directory.mkdir()
    evidence = directory / "source-certification-evidence.json"
    record = directory / "source-certificate-record.json"
    evidence.write_text(REFERENCE.read_text())
    record.write_text((REFERENCE.parent / record.name).read_text())
    assert transport.encode(evidence, organization_id=REF_ORG)
    payload = json.loads(evidence.read_text())
    payload["checks"][0]["status"] = "FAIL"
    evidence.write_text(json.dumps(payload))
    with pytest.raises(transport.EvidenceRejected, match="DIGEST_MISMATCH"):
        transport.encode(evidence, organization_id=REF_ORG)
    evidence.write_text(REFERENCE.read_text())
    current = json.loads(record.read_text())
    current["signature"] = "unsigned"
    record.write_text(json.dumps(current))
    with pytest.raises(transport.EvidenceRejected, match="SIGNED_CERTIFICATE_RECORD_REQUIRED"):
        transport.encode(evidence, organization_id=REF_ORG)


def test_decoder_rejects_invalid_base64_and_decompression_bomb():
    for invalid in ("A" * 100, base64.b64encode(gzip.compress(b"X" * 20000)).decode()):
        done = _decode_host_code(invalid, org=REF_ORG)
        assert done.returncode != 0
        assert not done.stdout
