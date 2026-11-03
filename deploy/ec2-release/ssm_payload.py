#!/usr/bin/env python3
"""Build the AWS-RunShellScript parameters for an AccessProof EC2 release.

Kept separate from ship_via_ssm.sh so the generated wrapper can be tested.

AWS-RunShellScript joins ``commands`` into one script and runs it with
``/bin/sh`` (dash on Ubuntu), NOT bash. The wrapper must therefore be POSIX:
``set -o pipefail`` aborts dash immediately (the r22 first-attempt failure,
SSM command a10ad326-…). Bash-only logic lives in deploy_on_ec2.sh, which the
wrapper invokes explicitly with ``bash``.

Every value interpolated into the wrapper is validated here, and presigned
URLs are single-quoted, so nothing is word-split or shell-evaluated.

    python3 ssm_payload.py [--rehearsal-no-public-checks] <release-id> <artifact-sha256> <expected-db-rev> \
        <url-artifact> <url-deploy> <url-rollback> <url-lp> <url-patch> <url-gates>
"""
from __future__ import annotations

import json
import re
import sys

RELEASES = "/home/ubuntu/accessproof-releases"
RELEASE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{5,80}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
# Alembic revision ids in this repo are 12 lowercase alphanumerics.
DB_REVISION_RE = re.compile(r"^[0-9a-z]{12}$")
URL_RE = re.compile(r"^https://[A-Za-z0-9.-]+\.amazonaws\.com/[^'\s]*$")

STAGED_FILES = (
    "deploy_on_ec2.sh",
    "rollback_on_ec2.sh",
    # Staged for a separately approved run; never executed by this command.
    "enable_least_privilege_db.sh",
    "patch_compose_db_roles.py",
    "run_security_gates.sh",
)


def build(
    release_id: str,
    artifact_sha256: str,
    expected_db_revision: str,
    artifact_url: str,
    file_urls: dict[str, str],
    public_checks: bool = True,
) -> dict:
    if not RELEASE_ID_RE.fullmatch(release_id):
        raise ValueError("bad release id")
    if not SHA256_RE.fullmatch(artifact_sha256):
        raise ValueError("bad artifact sha256")
    if not DB_REVISION_RE.fullmatch(expected_db_revision):
        raise ValueError("bad expected DB revision")
    if set(file_urls) != set(STAGED_FILES):
        raise ValueError("staged file set mismatch")
    for url in (artifact_url, *file_urls.values()):
        if not URL_RE.fullmatch(url):
            raise ValueError("presigned URL is not a plain https amazonaws.com URL")

    d = f"{RELEASES}/{release_id}"
    commands = [
        "set -eu",
        f"install -d -m 700 {RELEASES}",
        # A release id is never reused: its rollback/ state and backup would be
        # overwritten, and image tags would silently point at a different build.
        f"if [ -e {d} ]; then echo 'release directory {release_id} already exists; refusing to reuse it' >&2; exit 2; fi",
        f"install -d -m 700 {d}",
        f"curl -fsS -o {d}/artifact.tar '{artifact_url}'",
    ]
    commands += [f"curl -fsS -o {d}/{name} '{file_urls[name]}'" for name in STAGED_FILES]
    commands += [
        f"echo '{artifact_sha256}  {d}/artifact.tar' | sha256sum -c -",
        # Passed as an env prefix on the remote command itself; a workstation
        # env var would never reach the instance.
        # PUBLIC_CHECKS=0 only for a staging rehearsal, whose public URLs would
        # otherwise probe production and pass misleadingly.
        f"EXPECTED_DB_REVISION={expected_db_revision} PUBLIC_CHECKS={1 if public_checks else 0} "
        f"bash {d}/deploy_on_ec2.sh "
        f"{release_id} {d}/artifact.tar {artifact_sha256}",
    ]
    return {"executionTimeout": ["3600"], "commands": commands}


def main(argv: list[str]) -> int:
    public_checks = True
    if argv and argv[0] == "--rehearsal-no-public-checks":
        public_checks, argv = False, argv[1:]
    if len(argv) != 9:
        print(__doc__, file=sys.stderr)
        return 2
    rid, sha, rev, art, *urls = argv
    try:
        payload = build(rid, sha, rev, art, dict(zip(STAGED_FILES, urls)), public_checks)
    except ValueError as exc:
        print(f"ssm_payload: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(payload))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
