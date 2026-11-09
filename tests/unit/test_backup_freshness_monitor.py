"""Backup S3 metadata monitor: independent freshness and fail-visible behavior."""
from __future__ import annotations

import sys
import types
from datetime import datetime, timedelta, timezone

import pytest

from scripts.drills import backup_freshness_monitor as mon


NOW = datetime(2026, 11, 9, 4, 30, tzinfo=timezone.utc)
STEM = "20261109T042000Z-" + "a" * 32


def obj(name, size=500, age_minutes=10):
    return {"Key": "database/" + name, "Size": size,
            "LastModified": NOW - timedelta(minutes=age_minutes)}


def test_fresh_complete_pair():
    rows = [obj(STEM + ".dump", size=3400000),
            obj(STEM + ".manifest.json", size=534)]
    assert mon.most_recent_pair_age(rows, NOW) == 600


def test_only_archive_or_only_manifest_is_stale():
    for file in (".dump", ".manifest.json"):
        assert mon.most_recent_pair_age(
            [obj(STEM + file)], NOW
        ) == mon.NO_BACKUP_AGE_SECONDS


def test_untrusted_malformed_metadata_cannot_hide_staleness():
    bad = [
        obj(STEM + ".dump", size=3),
        obj(STEM + ".manifest.json", size=534),
        obj("garbage.dump", size=30000),
        {"Key": "database/" + STEM + ".dump", "Size": 999,
         "LastModified": datetime(2026, 11, 9, 4, 20)},  # naive timestamp
    ]
    assert mon.most_recent_pair_age(bad, NOW) == mon.NO_BACKUP_AGE_SECONDS


def test_pair_time_uses_older_part_to_avoid_false_freshness():
    rows = [obj(STEM + ".dump", size=50000, age_minutes=70),
            obj(STEM + ".manifest.json", size=500, age_minutes=1)]
    assert mon.most_recent_pair_age(rows, NOW) == 70 * 60


def test_lambda_emits_metric_without_reading_database_objects(monkeypatch):
    class Paginator:
        def paginate(self, **kwargs):
            assert kwargs["Bucket"] == mon.BUCKET
            assert kwargs["Prefix"] == mon.PREFIX
            assert kwargs["StartAfter"].startswith(mon.PREFIX)
            return [{"Contents": [obj(STEM + ".dump", size=30000),
                                   obj(STEM + ".manifest.json")]}]

    class S3:
        def get_paginator(self, name):
            assert name == "list_objects_v2"
            return Paginator()

    class CloudWatch:
        def __init__(self):
            self.calls = []

        def put_metric_data(self, **kwargs):
            self.calls.append(kwargs)

    cw = CloudWatch()
    fake = types.ModuleType("boto3")
    fake.client = lambda kind: {"s3": S3(), "cloudwatch": cw}[kind]
    monkeypatch.setitem(sys.modules, "boto3", fake)
    result = mon.lambda_handler({}, None)
    assert result["status"] == "FRESHNESS_METADATA_REPORTED"
    assert result["restore_verified"] is False
    assert len(cw.calls) == 1
    sent = cw.calls[0]
    assert sent["Namespace"] == mon.METRIC_NAMESPACE
    assert sent["MetricData"][0]["MetricName"] == mon.METRIC_NAME
    assert sent["MetricData"][0]["Dimensions"] == [
        {"Name": "AssociationId", "Value": mon.ASSOCIATION_ID}
    ]


def test_s3_pagination_failure_must_not_publish_false_success(monkeypatch):
    class FailedS3:
        def get_paginator(self, name):
            raise RuntimeError("S3_LIST_DENIED")

    fake = types.ModuleType("boto3")
    fake.client = lambda kind: FailedS3()
    monkeypatch.setitem(sys.modules, "boto3", fake)
    with pytest.raises(RuntimeError, match="S3_LIST_DENIED"):
        mon.lambda_handler({}, None)
