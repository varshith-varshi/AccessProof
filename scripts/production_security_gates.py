#!/usr/bin/env python3
"""Evaluate SharePoint Production Protect gates A–J (read-only).

Run INSIDE the API container so gate I measures the real runtime role:

  python scripts/production_security_gates.py --organization-id ORG \\
      --application-id APP [--host-facts facts.json] [--evidence evidence.json]

or, when the container filesystem is read-only, stream both over stdin:

  ... --stdin-bundle  < bundle.json   # {"host_facts": {...}, "evidence": {...} | null}

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
    parser.add_argument("--stdin-bundle", action="store_true",
                        help="read {host_facts, evidence} JSON from stdin (read-only container)")
    args = parser.parse_args()
    facts = json.loads(args.host_facts.read_text()) if args.host_facts else None
    evidence = None
    if args.stdin_bundle:
        bundle = json.loads(sys.stdin.read())
        if not isinstance(bundle, dict):
            parser.error("stdin bundle must be a JSON object")
        facts, evidence = bundle.get("host_facts"), bundle.get("evidence")
    with SessionLocal() as db:
        try:
            report = evaluate(db, organization_id=args.organization_id, application_id=args.application_id,
                              host_facts=facts, evidence_path=args.evidence, evidence=evidence)
        finally:
            db.rollback()
    print(json.dumps(report, indent=2))
    return 0 if report["verdict"].startswith("TECHNICAL_GATES_PASSED") else 1


if __name__ == "__main__":
    raise SystemExit(main())
