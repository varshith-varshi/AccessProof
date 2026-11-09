"""Independent AWS Lambda monitor for AccessProof encrypted DB backup freshness.

Observes only S3 object names, sizes, and timestamps. Does NOT read customer
database archives, decrypt backups, trust unverified backup content, or claim
restore certification. A missing/erroring monitor is alarmed by CloudWatch.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any

BUCKET = "accessproof-prod-db-backups-102076848988-eu-north-1"
PREFIX = "database/"
ASSOCIATION_ID = "9f6b4342-356e-4a4d-bf22-1bf316ff659f"
METRIC_NAMESPACE = "AccessProof/ProductionBackup"
METRIC_NAME = "LatestArchivePairAgeSeconds"
ARCHIVE = re.compile(r"^database/(\d{8}T\d{6}Z-[a-f0-9]{32})\.dump$")
MANIFEST = re.compile(r"^database/(\d{8}T\d{6}Z-[a-f0-9]{32})\.manifest\.json$")
NO_BACKUP_AGE_SECONDS = 86_400


def most_recent_pair_age(objects: list[dict[str, Any]], now: datetime) -> float:
    """Metadata availability check, NOT a dump-integrity or restore check."""
    archives: dict[str, dict[str, Any]] = {}
    manifests: dict[str, dict[str, Any]] = {}
    for item in objects:
        key = item.get("Key")
        size = item.get("Size")
        last_modified = item.get("LastModified")
        if not isinstance(key, str) or not isinstance(size, int):
            continue
        if not isinstance(last_modified, datetime):
            continue
        if last_modified.tzinfo is None:
            continue
        match = ARCHIVE.fullmatch(key)
        if match and size >= 5:
            archives[match.group(1)] = item
        match = MANIFEST.fullmatch(key)
        if match and size >= 100:
            manifests[match.group(1)] = item
    stamps: list[datetime] = []
    for stem in archives.keys() & manifests.keys():
        a, m = archives[stem], manifests[stem]
        stamps.append(min(a["LastModified"], m["LastModified"]))
    if not stamps:
        return float(NO_BACKUP_AGE_SECONDS)
    return max(0.0, (now - max(stamps)).total_seconds())


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    import boto3

    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(hours=4)).strftime("%Y%m%dT%H%M%SZ")
    s3 = boto3.client("s3")
    objects: list[dict[str, Any]] = []
    pages = s3.get_paginator("list_objects_v2").paginate(
        Bucket=BUCKET, Prefix=PREFIX, StartAfter=f"{PREFIX}{cutoff}"
    )
    for page in pages:
        objects.extend(page.get("Contents", []))
        # Abnormally high listing volume is a visibility failure, not a
        # reason to silently declare the latest backup healthy.
        if len(objects) > 2000:
            raise RuntimeError("ABNORMAL_BACKUP_OBJECT_COUNT")
    age = most_recent_pair_age(objects, now)
    cw = boto3.client("cloudwatch")
    cw.put_metric_data(
        Namespace=METRIC_NAMESPACE,
        MetricData=[{
            "MetricName": METRIC_NAME,
            "Dimensions": [{"Name": "AssociationId", "Value": ASSOCIATION_ID}],
            "Unit": "Seconds",
            "Value": age,
            "Timestamp": now,
        }],
    )
    # No customer content or backup object keys in CloudWatch logs.
    return {"status": "FRESHNESS_METADATA_REPORTED", "age_seconds": round(age),
            "independent_of_production_ec2": True, "restore_verified": False}
