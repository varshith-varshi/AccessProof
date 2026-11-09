"""Pinned operational AWS backup artifacts: live SSM v2 and independent watcher."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_live_ssm_backup_document_is_fixed_no_parameters():
    p = ROOT / "deploy/backup/AccessProof-Backup-FixedManualArchive.json"
    doc = json.loads(p.read_text())
    assert doc["schemaVersion"] == "2.2"
    assert doc["parameters"] == {}
    assert len(doc["mainSteps"]) == 1
    step = doc["mainSteps"][0]
    assert step["action"] == "aws:runShellScript"
    cmds = step["inputs"]["runCommand"]
    assert cmds[3] == "python3 - <<'AP_FIXED_BACKUP_END'"
    assert cmds[-1] == "AP_FIXED_BACKUP_END"
    script = "\n".join(cmds[4:-1]) + "\n"
    assert hashlib.sha256(script.encode()).hexdigest() == (
        "8c95b10a9d48537cf4c68d7f551d06edca676935b44bec50601cd7045ca6cfc2"
    )
    assert "i-0c11427d4d9c1b438" in script
    assert "AccessProofProductionBackupWriter" in script
    assert "accessproof-prod-db-backups-102076848988-eu-north-1" in script
    assert "S3_FULL_SHA256_MISMATCH" in script
    assert "ENCRYPTED_ARCHIVE_COMMITTED_RESTORE_UNVERIFIED" in script
    assert "aws_access_key_id" in script
    assert "ssh " not in script
    assert "pg_dump" in script
    assert "--no-owner" in script
    assert "--no-privileges" in script
    assert "PGPASSWORD" not in script
    assert "put_object(" in script and "s3.upload_fileobj(" in script


def test_independent_monitor_has_only_s3_metadata_permission():
    p = ROOT / "deploy/backup/independent-backup-freshness-stack.json"
    template = json.loads(p.read_text())
    resources = template["Resources"]
    assert set(resources) == {
        "FreshnessRole", "FreshnessLogs", "FreshnessFunction",
        "FreshnessSchedule", "FreshnessInvokePermission", "FreshnessAlarm"
    }
    source = (ROOT / "scripts/drills/backup_freshness_monitor.py").read_text()
    assert resources["FreshnessFunction"]["Properties"]["Code"]["ZipFile"] == source

    statements = resources["FreshnessRole"]["Properties"]["Policies"][0][
        "PolicyDocument"]["Statement"]
    s3 = statements[0]
    assert s3["Action"] == "s3:ListBucket"
    assert s3["Resource"] == (
        "arn:aws:s3:::accessproof-prod-db-backups-102076848988-eu-north-1"
    )
    all_actions = [
        a for item in statements
        for a in (item["Action"] if isinstance(item["Action"], list) else [item["Action"]])
    ]
    assert "s3:GetObject" not in all_actions
    assert "kms:Decrypt" not in all_actions
    assert "s3:DeleteObject" not in all_actions
    assert "iam:PassRole" not in all_actions
    assert resources["FreshnessSchedule"]["Properties"]["ScheduleExpression"] == "rate(15 minutes)"
    assert resources["FreshnessSchedule"]["Properties"]["State"] == "ENABLED"
    alarm = resources["FreshnessAlarm"]["Properties"]
    assert alarm["Threshold"] == 3600
    assert alarm["TreatMissingData"] == "breaching"
    assert alarm["AlarmName"] == "accessproof-production-backup-stale-or-monitor-missing"
