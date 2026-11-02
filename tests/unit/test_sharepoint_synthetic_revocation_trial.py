"""Regression tests for explicitly authorized real SharePoint synthetic revoke/restore."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

from scripts import sharepoint_synthetic_revocation_trial as trial


def test_revocation_cannot_start_without_explicit_synthetic_ack(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["trial", "--execute"])
    with pytest.raises(trial.RevocationError, match="ACKNOWLEDGMENT_REQUIRED"):
        asyncio.run(trial.main())


def test_cannot_mix_execute_with_restore_mode(monkeypatch):
    monkeypatch.setattr(
        sys, "argv", ["trial", "--execute", "--restore-only", "--acknowledge-synthetic"],
    )
    with pytest.raises(trial.RevocationError, match="ACKNOWLEDGMENT_REQUIRED"):
        asyncio.run(trial.main())


def test_revocation_targets_only_one_fixed_synthetic_site_and_item():
    assert trial.SITE == "https://neuralmatrix093.sharepoint.com/sites/AccessProof-Validation-20261027"
    assert trial.LIST == "8200ffae-ba10-42c5-bfa9-8f7ac155c5c4"
    assert trial.ITEM == 2
    assert "/items(2)" in trial.ITEM_ROOT
    assert trial.RECOVERY.parent == trial.PRIVATE
    assert "synthetic" in trial.EVIDENCE.name
    assert Path(trial.RECOVERY).suffix == ".json"
