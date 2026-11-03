#!/usr/bin/env python3
"""Minimal, verified edit of the SERVER's docker-compose.ec2.yml (P0-01).

The server Compose file differs from the repository and is never replaced
wholesale. This changes ONLY the DATABASE_URL line of the `api` and `worker`
services (and adds ACCESSPROOF_METRICS_DATABASE_URL to `api`) so they read the
restricted role credentials from .env. `migrate` keeps the owner. Refuses
(exit 2) unless each target line is found exactly once in its service block.

  python3 patch_compose_db_roles.py docker-compose.ec2.yml
"""
import re
import sys
from pathlib import Path

OWNER_URL = "postgresql+psycopg://accessproof:${POSTGRES_PASSWORD}@db:5432/accessproof"
NEW = {
    "api": "postgresql+psycopg://${ACCESSPROOF_APP_DB_USER:-accessproof}:"
           "${ACCESSPROOF_APP_DB_PASSWORD:-${POSTGRES_PASSWORD}}@db:5432/accessproof",
    "worker": "postgresql+psycopg://${ACCESSPROOF_WORKER_DB_USER:-accessproof}:"
              "${ACCESSPROOF_WORKER_DB_PASSWORD:-${POSTGRES_PASSWORD}}@db:5432/accessproof",
}


def service_blocks(lines: list[str]) -> dict[str, tuple[int, int]]:
    blocks, current, start = {}, None, 0
    for i, line in enumerate(lines):
        m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if m or (line and not line.startswith(" ") and i > 0):
            if current is not None:
                blocks[current] = (start, i)
            current, start = (m.group(1), i) if m else (None, i)
    if current is not None:
        blocks[current] = (start, len(lines))
    return blocks


def main() -> int:
    path = Path(sys.argv[1])
    lines = path.read_text().split("\n")
    if any("ACCESSPROOF_APP_DB_USER" in line for line in lines):
        print("already patched")
        return 0
    blocks = service_blocks(lines)
    edits = {}
    for service, url in NEW.items():
        if service not in blocks:
            print(f"service {service} not found")
            return 2
        lo, hi = blocks[service]
        hits = [i for i in range(lo, hi) if lines[i].strip() == f"DATABASE_URL: {OWNER_URL}"]
        if len(hits) != 1:
            print(f"{service}: expected exactly one owner DATABASE_URL line, found {len(hits)}")
            return 2
        edits[service] = hits[0]
    for service, i in edits.items():
        indent = lines[i][:len(lines[i]) - len(lines[i].lstrip())]
        lines[i] = f"{indent}DATABASE_URL: {NEW[service]}"
        if service == "api":
            lines[i] += f"\n{indent}ACCESSPROOF_METRICS_DATABASE_URL: ${{ACCESSPROOF_METRICS_DATABASE_URL:-}}"
    path.write_text("\n".join(lines))
    print("patched api and worker DATABASE_URL")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
