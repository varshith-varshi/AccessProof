#!/usr/bin/env python3
"""Independent, operator-run SharePoint/OneDrive source certifier (defect D-01).

This tool is deliberately NOT part of the API image. It holds the Ed25519
private key; the API only ever receives the public key.

  keygen  --private-key PATH            create a 0600 key, print public-key JSON
  issue   --private-key PATH --evidence EVIDENCE.json --organization-id ...
          --source-id ... --profile ... --scope-digest ... [--days 7]
                                        refuse unless every required live check
                                        PASSED; print a signed record
  scope   --organization-id ... --source-id ...
                                        print only the non-secret profile and
                                        scope digest to certify (DATABASE_URL)
  import  --record RECORD.json          verify with the API's pinned public
                                        keys and the source's CURRENT scope,
                                        then upsert (DATABASE_URL); rolls back
                                        if the API would not accept it

It never fabricates evidence: issuance requires an evidence file whose checks
were observed against the real tenant and the real protected route.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from datetime import datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from packages.crypto.source_certificate import (  # noqa: E402
    REQUIRED_CHECKS, CertificateError, issue_certificate, public_key_b64,
)


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise SystemExit(f"refusing key with permissive mode {oct(mode)}; chmod 600 {path}")
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit("certifier key must be Ed25519")
    return key


def cmd_keygen(args: argparse.Namespace) -> int:
    if args.private_key.exists():
        raise SystemExit("refusing to overwrite an existing certifier key")
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    fd = os.open(args.private_key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(pem)
    print(json.dumps({args.key_id: public_key_b64(key)}))
    print("Set ACCESSPROOF_SOURCE_CERTIFICATION_PUBLIC_KEYS_JSON on the API to the line above.",
          file=sys.stderr)
    return 0


def cmd_issue(args: argparse.Namespace) -> int:
    key = _load_private_key(args.private_key)
    evidence = json.loads(args.evidence.read_text())
    try:
        record = issue_certificate(
            evidence, organization_id=args.organization_id, source_id=args.source_id,
            profile=args.profile, scope_digest=args.scope_digest, private_key=key,
            key_id=args.key_id, validity=timedelta(days=args.days),
        )
    except CertificateError as exc:
        print(f"NOT ISSUED: {exc}", file=sys.stderr)
        print("Required checks: " + ", ".join(REQUIRED_CHECKS), file=sys.stderr)
        return 2
    print(json.dumps(record, indent=2))
    return 0


def cmd_import(args: argparse.Namespace) -> int:
    from sqlalchemy import select

    from apps.api.accessproof_api.db import (
        SessionLocal, SourceConnection, SourceEffectiveCertification, set_tenant_context,
    )
    from apps.api.accessproof_api.app import _secret_box
    from apps.api.accessproof_api.source_certification import effective_source_certified

    record = json.loads(args.record.read_text())
    with SessionLocal() as db:
        set_tenant_context(db, record["organization_id"])
        source = db.scalar(select(SourceConnection).where(
            SourceConnection.id == record["source_id"],
            SourceConnection.organization_id == record["organization_id"],
        ))
        if source is None:
            print("NOT IMPORTED: source not found in that organization", file=sys.stderr)
            return 2
        cert = db.scalar(select(SourceEffectiveCertification).where(
            SourceEffectiveCertification.organization_id == source.organization_id,
            SourceEffectiveCertification.source_id == source.id,
        )) or SourceEffectiveCertification(organization_id=source.organization_id, source_id=source.id)
        cert.provider_profile = record["provider_profile"]
        cert.scope_digest = record["scope_digest"]
        cert.evidence_digest = record["evidence_digest"]
        cert.verifier_version = record["verifier_version"]
        cert.certified_at = datetime.fromisoformat(record["certified_at"])
        cert.expires_at = datetime.fromisoformat(record["expires_at"])
        cert.signature = record["signature"]
        cert.status = "verified"
        db.add(cert)
        db.flush()
        credentials = json.loads(_secret_box.decrypt(source.encrypted_credentials or ""))
        if not effective_source_certified(db, source, credentials):
            db.rollback()
            print("NOT IMPORTED: the API would reject this certificate "
                  "(signature, key pin, scope, or expiry)", file=sys.stderr)
            return 2
        db.commit()
    print("Imported. This satisfies only the Microsoft certificate gate; all other "
          "activation checks still apply.")
    return 0


def cmd_scope(args: argparse.Namespace) -> int:
    """Print ONLY the source's certification profile and scope digest (both
    non-secret; the digest is a SHA-256 over stable identifiers). Run where the
    API runs (DATABASE_URL + secret key); prints no identifiers or secrets."""
    from sqlalchemy import select

    from apps.api.accessproof_api.app import _secret_box
    from apps.api.accessproof_api.db import SessionLocal, SourceConnection, set_tenant_context
    from apps.api.accessproof_api.source_certification import _source_scope

    with SessionLocal() as db:
        set_tenant_context(db, args.organization_id)
        source = db.scalar(select(SourceConnection).where(
            SourceConnection.id == args.source_id, SourceConnection.organization_id == args.organization_id))
        if source is None:
            print("source not found in that organization", file=sys.stderr)
            return 2
        scope = _source_scope(source, json.loads(_secret_box.decrypt(source.encrypted_credentials or "")))
        db.rollback()
    if scope is None:
        print("SCOPE_NOT_CERTIFIABLE (provider/profile identifiers incomplete)", file=sys.stderr)
        return 2
    print(json.dumps({"profile": scope[0], "scope_digest": scope[1]}))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    keygen = sub.add_parser("keygen")
    keygen.add_argument("--private-key", type=Path, required=True)
    keygen.add_argument("--key-id", default="certifier-1")
    issue = sub.add_parser("issue")
    issue.add_argument("--private-key", type=Path, required=True)
    issue.add_argument("--key-id", default="certifier-1")
    issue.add_argument("--evidence", type=Path, required=True)
    issue.add_argument("--organization-id", required=True)
    issue.add_argument("--source-id", required=True)
    issue.add_argument("--profile", required=True)
    issue.add_argument("--scope-digest", required=True)
    issue.add_argument("--days", type=int, default=30)
    scope = sub.add_parser("scope")
    scope.add_argument("--organization-id", required=True)
    scope.add_argument("--source-id", required=True)
    imp = sub.add_parser("import")
    imp.add_argument("--record", type=Path, required=True)
    args = parser.parse_args(argv)
    return {"keygen": cmd_keygen, "issue": cmd_issue, "scope": cmd_scope, "import": cmd_import}[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
