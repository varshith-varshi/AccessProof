#!/usr/bin/env python3
"""Independent source-scoped SharePoint certification automation.

For each *registered* customer test boundary, require exact source scope,
real identity bindings, explicitly approved synthetic canaries, and the
complete 14-check live evidence suite before signing/importing. Runs ONLY
on a restricted independent certifier host, never in the SaaS API process.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import socket
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
CERTIFIER = Path(__file__).resolve().parent
ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
HEX = re.compile(r"^[a-f0-9]{64}$")
# Synthetic canary ACLs must include BOTH positive and negative controls;
# customer profiles may vary the tenant, scope and marker text, not the
# expected permission outcome to manufacture a passing matrix.
CANARY_RIGHTS = {
    "alice": {"finance_alice.txt": True, "engineering_bob.txt": False,
              "shared_control.txt": True, "group_finance_alice.txt": True,
              "inherited_finance_alice.txt": True},
    "bob": {"finance_alice.txt": False, "engineering_bob.txt": True,
            "shared_control.txt": True, "group_finance_alice.txt": False,
            "inherited_finance_alice.txt": False},
}
PROFILE_FIELDS = {
    "renew_source_certificate": ("ORG", "SOURCE", "APP", "GUARD_CONTAINER", "SOCKS"),
    "employee_identity": ("TENANT", "ISSUER", "UPN_DOMAIN", "SITE", "FOLDER", "APP_ONLY_CONFIG"),
    "sharepoint_effective_matrix": ("ORG", "SOURCE", "SITE", "EXPECTED", "PEOPLE_FILE",
                                    "SHAREPOINT_CERT_DIR", "GRAPH_REGISTRATION", "FIXTURE_STATE"),
    "sharepoint_fixtures": ("STATE", "GROUP", "SUBFOLDER"),
    "layer1_matrix": ("ORG", "SRC", "APP", "GUARD", "GUARD_CONTAINER",
                      "RAG_CONTAINER", "FIXTURE_STATE", "EXPECT"),
    "rag_e2e": ("ORG", "SOURCE", "APP", "RAG", "GUARD", "RAG_ROUTE", "WITNESS", "CANARY"),
    "route_revocation": ("MODEL", "HOLD", "QUESTION_FOR"),
    "revocation_trial": ("ORG", "SOURCE", "APP", "GUARD_ID", "GUARD_URL",
                         "GUARD_CONTAINER", "RAG_CONTAINER", "RECOVERY"),
}


class RegistrationError(ValueError):
    pass


def _uuid(value: object) -> str:
    try:
        uid = str(UUID(str(value)))
    except (TypeError, ValueError, AttributeError) as exc:
        raise RegistrationError("INVALID_SOURCE_OR_TENANT_ID") from exc
    if uid == "00000000-0000-0000-0000-000000000000":
        raise RegistrationError("EMPTY_SOURCE_OR_TENANT_ID")
    return uid


def _private_json(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise RegistrationError("PRIVATE_CONFIGURATION_MISSING")
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise RegistrationError("PRIVATE_CONFIGURATION_PERMISSIONS")
    result = json.loads(path.read_text())
    if not isinstance(result, dict):
        raise RegistrationError("PRIVATE_CONFIGURATION_NOT_OBJECT")
    return result


def validate_registration(path: Path) -> tuple[dict, dict]:
    """Never infer customer approval or use reference fixture defaults."""
    reg = _private_json(path)
    if reg.get("schema") != "accessproof.source_certification_registration/v1":
        raise RegistrationError("REGISTRATION_SCHEMA_UNSUPPORTED")
    for field in ("organization_id", "source_id", "tenant_id"):
        reg[field] = _uuid(reg.get(field))
    app = reg.get("application_id")
    if not isinstance(app, str) or not ID.fullmatch(app):
        raise RegistrationError("INVALID_APPLICATION_ID")
    digest = reg.get("scope_digest")
    if not isinstance(digest, str) or not HEX.fullmatch(digest):
        raise RegistrationError("CURRENT_SOURCE_SCOPE_REQUIRED")
    canary = reg.get("canary")
    if not isinstance(canary, dict) or canary.get("mutation_authorized") is not True:
        raise RegistrationError("CUSTOMER_TEST_CANARY_APPROVAL_REQUIRED")
    site = canary.get("site_url")
    if not isinstance(site, str):
        raise RegistrationError("CUSTOMER_TEST_SITE_REQUIRED")
    parsed = urlsplit(site)
    if (parsed.scheme != "https" or not parsed.hostname or
            not parsed.hostname.endswith((".sharepoint.com", ".sharepointonline.com"))
            or parsed.username or parsed.password or parsed.port is not None
            or not parsed.path.startswith("/sites/")
            or parsed.query or parsed.fragment or ".." in parsed.path):
        raise RegistrationError("CANARY_MUST_BE_AN_APPROVED_SHAREPOINT_SITE")
    employees = canary.get("employee_object_ids")
    if not isinstance(employees, dict) or set(employees) != {"alice", "bob"}:
        raise RegistrationError("TWO_CUSTOMER_TEST_EMPLOYEES_REQUIRED")
    employees = {k: _uuid(v) for k, v in employees.items()}
    if employees["alice"] == employees["bob"]:
        raise RegistrationError("TEST_EMPLOYEES_NOT_DISTINCT")
    reg["employee_object_ids"] = employees
    gateway = reg.get("gateway_service")
    if not isinstance(gateway, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", gateway):
        raise RegistrationError("SOURCE_GATEWAY_SERVICE_REQUIRED")
    profile_path = Path(reg.get("profile_file") or "")
    if not profile_path.is_absolute():
        raise RegistrationError("ABSOLUTE_SOURCE_PROFILE_REQUIRED")
    profile = _private_json(profile_path)
    for module, keys in PROFILE_FIELDS.items():
        values = profile.get(module)
        if not isinstance(values, dict) or any(k not in values for k in keys):
            raise RegistrationError(f"CUSTOMER_FIXTURE_PROFILE_INCOMPLETE:{module}")
    matches = {
        ("renew_source_certificate", "ORG"): reg["organization_id"],
        ("renew_source_certificate", "SOURCE"): reg["source_id"],
        ("renew_source_certificate", "APP"): app,
        ("employee_identity", "TENANT"): reg["tenant_id"],
        ("employee_identity", "SITE"): site,
        ("sharepoint_effective_matrix", "ORG"): reg["organization_id"],
        ("sharepoint_effective_matrix", "SOURCE"): reg["source_id"],
        ("sharepoint_effective_matrix", "SITE"): site,
        ("layer1_matrix", "ORG"): reg["organization_id"],
        ("layer1_matrix", "SRC"): reg["source_id"],
        ("layer1_matrix", "APP"): app,
        ("rag_e2e", "ORG"): reg["organization_id"],
        ("rag_e2e", "SOURCE"): reg["source_id"],
        ("rag_e2e", "APP"): app,
        ("revocation_trial", "ORG"): reg["organization_id"],
        ("revocation_trial", "SOURCE"): reg["source_id"],
        ("revocation_trial", "APP"): app,
    }
    for (module, key), expected in matches.items():
        if profile[module][key] != expected:
            raise RegistrationError(f"PROFILE_CROSS_SOURCE_REUSE:{module}.{key}")
    if profile["sharepoint_effective_matrix"]["EXPECTED"] != CANARY_RIGHTS:
        raise RegistrationError("SOURCE_CANARY_EXPECTED_PROVIDER_MATRIX_CHANGED")
    guard_matrix = {
        actor: {doc: "ALLOW" if allowed else "DENY" for doc, allowed in rights.items()}
        for actor, rights in CANARY_RIGHTS.items()
    }
    if profile["layer1_matrix"]["EXPECT"] != guard_matrix:
        raise RegistrationError("SOURCE_CANARY_EXPECTED_GUARD_MATRIX_CHANGED")
    if profile["employee_identity"].get("ISSUER") != (
        f"https://login.microsoftonline.com/{reg['tenant_id']}/v2.0"
    ):
        raise RegistrationError("SOURCE_TEST_ENTRA_ISSUER_MISMATCH")
    reg["profile_file"] = str(profile_path)
    return reg, profile


def _employee_claims(path: Path) -> dict:
    """Read verified OIDC claim SUMMARY from the owner-only Unix socket.

    Never request or persist an ID/access/refresh token.
    """
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(4)
        client.connect(str(path))
        client.sendall(b"claims\n")
        chunks = []
        size = 0
        while size < 8192:
            data = client.recv(4096)
            if not data:
                break
            chunks.append(data)
            size += len(data)
            if b"\n" in data:
                break
        if size > 8192:
            raise RegistrationError("EMPLOYEE_CLAIMS_TOO_LARGE")
        return json.loads(b"".join(chunks).split(b"\n", 1)[0])


def source_preflight(reg: dict, profile: dict, readonly) -> list[str]:
    """Read-only production checks under the certifier's least-privilege SSM role."""
    errors: list[str] = []
    try:
        raw_scope = readonly("source_scope", organizationId=reg["organization_id"],
                             sourceId=reg["source_id"])
        scope = json.loads(raw_scope.strip().splitlines()[-1])
        if scope.get("profile") != "sharepoint_list_item_effective":
            errors.append("PROVIDER_EFFECTIVE_SCOPE_NOT_SUPPORTED")
        if scope.get("scope_digest") != reg["scope_digest"]:
            errors.append("SOURCE_SCOPE_CHANGED")
        cursors = readonly("sync_cursors", organizationId=reg["organization_id"],
                           sourceId=reg["source_id"])
        if not {"acl:connected", "directory:connected"} <= set(cursors.strip().split(",")):
            errors.append("SHAREPOINT_ACL_DIRECTORY_SYNC_NOT_READY")
        rows = json.loads(readonly("identity_bindings",
                                   organizationId=reg["organization_id"]).strip().splitlines()[0])
        if not isinstance(rows, list) or len(rows) != 2:
            errors.append("TWO_VERIFIED_EMPLOYEE_MAPPINGS_REQUIRED")
        else:
            by_oid = {r.get("oidc_subject_oid"): r for r in rows}
            if set(by_oid) != set(reg["employee_object_ids"].values()):
                errors.append("CUSTOMER_EMPLOYEE_OIDS_MISMATCH")
            elif not all(r.get("status") == "VERIFIED" and
                         r.get("oid_equals_source_principal") is True and
                         r.get("method") == "directory_verified" for r in rows):
                errors.append("CUSTOMER_EMPLOYEE_SOURCE_BINDING_NOT_VERIFIED")
    except (ValueError, KeyError, IndexError, RuntimeError, subprocess.SubprocessError):
        errors.append("INDEPENDENT_PRODUCTION_SCOPE_CHECK_FAILED")
    for actor in ("alice", "bob"):
        sockets = profile["renew_source_certificate"].get("SOCKS", {})
        socket = Path(sockets.get(actor) or Path.home() / f".ap-id/{actor}.sock")
        try:
            if not stat.S_ISSOCK(socket.stat().st_mode):
                errors.append(f"EMPLOYEE_IDENTITY_SESSION_NOT_SOCKET:{actor}")
                continue
            claims = _employee_claims(socket)
            identity = claims.get("id_token_claims") or {}
            if (identity.get("oid") != reg["employee_object_ids"][actor]
                    or identity.get("tid") != reg["tenant_id"]
                    or claims.get("graph_me_oid_match") is not True):
                errors.append(f"EMPLOYEE_IDENTITY_TOKEN_OID_OR_TENANT_MISMATCH:{actor}")
        except (OSError, ValueError, KeyError):
            errors.append(f"EMPLOYEE_IDENTITY_SESSION_UNAVAILABLE:{actor}")
    # A reference RAG or a RAG bypassing Gateway cannot certify this source.
    # This synthetic adapter's own immutable deployment binding is checked
    # before running any canary revocation or issuing a certificate.
    rag_container = profile["rag_e2e"]["RAG"]
    try:
        if not isinstance(rag_container, str) or not rag_container:
            raise ValueError("RAG_CONTAINER_REQUIRED")
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{json .Config.Env}}", rag_container],
            capture_output=True, text=True, timeout=12, check=True,
        )
        env = dict(x.split("=", 1) for x in json.loads(result.stdout) if "=" in x)
        if (env.get("LAB_APPLICATION_ID") != reg["application_id"] or
                env.get("LAB_SOURCE_ID") != reg["source_id"]):
            errors.append("RAG_CONNECTED_TO_DIFFERENT_SOURCE_OR_APPLICATION")
        if env.get("LAB_GATEWAY_URL") != f"http://{reg['gateway_service']}:8090/v1/chat/completions":
            errors.append("RAG_ROUTE_BYPASSES_CERTIFIED_GATEWAY")
    except (OSError, ValueError, subprocess.SubprocessError):
        errors.append("RAG_DEPLOYMENT_BINDING_UNVERIFIED")
    if os.environ.get("AWS_PROFILE") != "accessproof-certifier":
        errors.append("RESTRICTED_INDEPENDENT_CERTIFIER_ROLE_REQUIRED")
    if any(os.environ.get(k) for k in
           ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")):
        errors.append("STATIC_OR_ROOT_AWS_CREDENTIALS_NOT_ALLOWED")
    return errors


def handle_registration(path: Path, *, execute: bool, readonly) -> dict:
    report: dict = {"registration": path.name, "state": "BLOCKED",
                    "blocking_codes": [], "certificate_issued": False}
    try:
        reg, profile = validate_registration(path)
        report["organization_id"] = reg["organization_id"]
        report["source_id"] = reg["source_id"]
        report["application_id"] = reg["application_id"]
        errors = source_preflight(reg, profile, readonly)
        if errors:
            report["blocking_codes"] = sorted(set(errors))
            return report
        if not execute:
            report["state"] = "PREREQUISITES_READY_NOT_CERTIFIED"
            return report
        # The private key is only available on this independent host; the
        # customer API always verifies signed records against public keys.
        env = {**os.environ, "AP_PROFILE_FILE": reg["profile_file"],
               "AP_SOURCE_BOUND_EVIDENCE": "1",
               "AP_EXPECTED_EMPLOYEE_OIDS_JSON":
                   json.dumps(reg["employee_object_ids"], sort_keys=True),
               "AP_CERTIFIER_EVIDENCE_HOME": str(Path.home() / ".config/accessproof/certifier/evidence"),
               "AP_EXPECTED_SOURCE_TENANT_ID": reg["tenant_id"],
               "AP_EXPECTED_CANARY_SITE_URL": reg["canary"]["site_url"]}
        result = subprocess.run([sys.executable, "-u", str(CERTIFIER / "renew_source_certificate.py"),
                                 "--renew-days", "10", "--days", "30"],
                                cwd=ROOT, env=env, capture_output=True, text=True, timeout=9000)
        if result.returncode:
            report["blocking_codes"] = ["LIVE_SOURCE_CERTIFICATION_FAILED"]
            # Error codes from the live certifier are diagnostic and should
            # not include document content or employee access tokens.
            report["failure_type"] = "LIVE_CHECK_FAILED"
            return report
        if "NOT_DUE" in result.stdout:
            report["state"] = "CERTIFICATE_CURRENT_NOT_DUE"
        elif "RENEWED certified_at=" in result.stdout:
            report["state"] = "ISSUED_AFTER_LIVE_EVIDENCE"
            report["certificate_issued"] = True
        else:
            report["blocking_codes"] = ["CERTIFIER_RESULT_NOT_VERIFIABLE"]
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        report["blocking_codes"] = [str(exc)[:180]]
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registrations", type=Path, required=True)
    parser.add_argument("--execute", action="store_true",
                        help="Perform source-scoped, customer-approved canary trials and sign only after 14 PASS checks")
    args = parser.parse_args()
    folder = args.registrations
    if folder.is_symlink() or not folder.is_dir() or stat.S_IMODE(folder.stat().st_mode) & 0o077:
        parser.error("CERTIFIER_REGISTRATION_DIRECTORY_MUST_BE_PRIVATE_0700")
    sys.path.insert(0, str(CERTIFIER))
    import ssm_ops  # noqa: PLC0415

    # Prevent a timer and an interactive invocation from mutating the same
    # synthetic test ACL simultaneously. A stale lock is released by the OS.
    lock_fd = os.open(folder / ".certification.lock", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise SystemExit("CERTIFICATION_JOB_ALREADY_RUNNING")
    reports = [handle_registration(path, execute=args.execute, readonly=ssm_ops.read_only)
               for path in sorted(folder.glob("*.json"))]
    result = {"schema": "accessproof.independent_certification_batch/v1",
              "checked_at": datetime.now(timezone.utc).isoformat(), "sources": reports}
    print(json.dumps(result, indent=2))
    if not reports:
        return 0  # No registrations yet; do not issue or fabricate a certificate.
    return 0 if all(r["state"] in {"PREREQUISITES_READY_NOT_CERTIFIED",
                                   "ISSUED_AFTER_LIVE_EVIDENCE",
                                   "CERTIFICATE_CURRENT_NOT_DUE"} for r in reports) else 2


if __name__ == "__main__":
    raise SystemExit(main())
