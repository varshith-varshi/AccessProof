#!/usr/bin/env python3
"""Evaluate SharePoint Production Protect gates A–J (read-only).

Run INSIDE the API container so gate I measures the real runtime role:

  python scripts/production_security_gates.py --organization-id ORG \\
      --application-id APP [--host-facts facts.json] [--evidence evidence.json]

Exit 0 only for TECHNICAL_GATES_PASSED_PENDING_REVIEWER_APPROVAL. Never
writes to the database; prints no secrets or document content.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from apps.api.accessproof_api.db import SessionLocal  # noqa: E402
from apps.api.accessproof_api.production_gates import evaluate  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--organization-id", required=True)
    parser.add_argument("--application-id", required=True)
    parser.add_argument("--host-facts", type=Path)
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    facts = json.loads(args.host_facts.read_text()) if args.host_facts else None
    with SessionLocal() as db:
        try:
            report = evaluate(db, organization_id=args.organization_id, application_id=args.application_id,
                              host_facts=facts, evidence_path=args.evidence)
        finally:
            db.rollback()
    print(json.dumps(report, indent=2))
    return 0 if report["verdict"].startswith("TECHNICAL_GATES_PASSED") else 1


if __name__ == "__main__":
    raise SystemExit(main())
