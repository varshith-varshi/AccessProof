#!/usr/bin/env python3
"""Read-only, least-privilege production disaster-recovery inventory.

No backup creation, restoration, IAM mutation, or production DB access.
An AWS AccessDenied response is UNOBSERVABLE, never evidence of no backups.
A snapshot or backup plan alone never constitutes a restore drill.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys

REGION = "eu-north-1"
ACCOUNT = "102076848988"
INSTANCE = "i-0c11427d4d9c1b438"
STATIC = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
          "AWS_SECURITY_TOKEN", "AWS_WEB_IDENTITY_TOKEN_FILE")


def aws(*argv: str) -> tuple[bool, dict | str]:
    try:
        result = subprocess.run(
            ["aws", *argv, "--region", REGION, "--output", "json"],
            capture_output=True, text=True, timeout=25, check=False,
        )
        if result.returncode:
            message = result.stderr
            return False, ("ACCESS_DENIED" if "AccessDenied" in message
                           or "UnauthorizedOperation" in message
                           or "not authorized" in message else "AWS_CALL_FAILED")
        data = json.loads(result.stdout)
        return (True, data) if isinstance(data, dict) else (False, "AWS_INVALID_RESULT")
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return False, "AWS_CALL_FAILED"


def checked(name: str, service: str, command: str, *params: str) -> tuple[str, dict]:
    ok, data = aws(service, command, *params)
    if not ok:
        return "UNOBSERVABLE", {"operation": name, "reason": str(data)}
    return "OBSERVED", data


def audit() -> dict:
    out: dict = {
        "schema": "accessproof.production_dr_inventory/v1",
        "region": REGION,
        "instance_id": INSTANCE,
        "ready": False,
        "restore_verified": False,
        "scope": "read-only regional AWS inventory; not a restore or backup job",
    }
    profile = os.environ.get("AWS_PROFILE", "")
    if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{1,80}", profile)
            or profile in {"root", "default"}
            or any(os.environ.get(name) for name in STATIC)):
        out["blocker"] = "EXPLICIT_NONROOT_PROFILE_REQUIRED"
        return out
    identity, sts = aws("sts", "get-caller-identity")
    arn = sts.get("Arn", "") if identity and isinstance(sts, dict) else ""
    if (not isinstance(arn, str) or arn.endswith(":root")
            or not (":assumed-role/" in arn or ":user/" in arn)):
        out["blocker"] = "NONROOT_AWS_IDENTITY_NOT_VERIFIED"
        return out

    ec2_state, instances = checked("production_instance", "ec2", "describe-instances",
                                   "--instance-ids", INSTANCE)
    node = [i for r in instances.get("Reservations", []) for i in r.get("Instances", [])
            if isinstance(i, dict) and i.get("InstanceId") == INSTANCE] \
        if ec2_state == "OBSERVED" else []
    volume_ids = sorted({
        m.get("Ebs", {}).get("VolumeId") for i in node
        for m in i.get("BlockDeviceMappings", []) if m.get("Ebs", {}).get("VolumeId")
    })
    volume_state, volume_data = (
        checked("production_volumes", "ec2", "describe-volumes",
                "--volume-ids", *volume_ids) if volume_ids
        else ("UNOBSERVABLE", {"reason": "INSTANCE_VOLUMES_NOT_VERIFIED"})
    )
    volumes = volume_data.get("Volumes", []) if volume_state == "OBSERVED" else []
    exact_volumes = (
        len(node) == 1 and len(volume_ids) > 0
        and len(volumes) == len(volume_ids)
        and {v.get("VolumeId") for v in volumes} == set(volume_ids)
    )
    unencrypted = sorted(v["VolumeId"] for v in volumes if v.get("Encrypted") is not True)
    out["storage"] = {
        "state": "OBSERVED" if exact_volumes else "UNOBSERVABLE",
        "volume_count": len(volume_ids) if exact_volumes else None,
        "all_volumes_encrypted": exact_volumes and not unencrypted,
        "unencrypted_volume_ids": unencrypted if exact_volumes else [],
    }

    plans_state, plans = checked("backup_plans", "backup", "list-backup-plans")
    out["backup_plans"] = {
        "state": ("UNOBSERVABLE" if plans_state != "OBSERVED"
                  else "NONE" if not plans.get("BackupPlansList")
                  else "PRESENT_SCOPE_NOT_VERIFIED"),
        "count": len(plans.get("BackupPlansList", [])) if plans_state == "OBSERVED" else None,
    }
    vault_state, vaults = checked("backup_vaults", "backup", "list-backup-vaults")
    out["backup_vaults"] = {
        "state": ("UNOBSERVABLE" if vault_state != "OBSERVED"
                  else "NONE" if not vaults.get("BackupVaultList") else "PRESENT"),
        "count": len(vaults.get("BackupVaultList", [])) if vault_state == "OBSERVED" else None,
    }
    arn_base = f"arn:aws:ec2:{REGION}:{ACCOUNT}:"
    resources = [arn_base + "instance/" + INSTANCE]
    resources += [arn_base + "volume/" + vol for vol in volume_ids]
    observed_points: list[dict] = []
    for resource in resources:
        state, points = checked("recovery_points", "backup",
                                "list-recovery-points-by-resource", "--resource-arn", resource)
        observed_points.append({
            "resource_type": "instance" if ":instance/" in resource else "volume",
            "state": ("UNOBSERVABLE" if state != "OBSERVED"
                      else "NONE" if not points.get("RecoveryPoints") else "PRESENT"),
            "count": len(points.get("RecoveryPoints", [])) if state == "OBSERVED" else None,
        })
    out["aws_backup_recovery_points"] = observed_points
    out["restore_status"] = "PRODUCTION_DATA_ISOLATED_RESTORE_NOT_VERIFIED"
    out["blocker"] = "RECOVERY_COMPLIANCE_NOT_VERIFIED"
    return out


if __name__ == "__main__":
    result = audit()
    print(json.dumps(result, sort_keys=True))
    sys.exit(0 if result["ready"] else 2)
