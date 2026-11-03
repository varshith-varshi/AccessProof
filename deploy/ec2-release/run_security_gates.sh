#!/usr/bin/env bash
# Read-only production certification gate run — ON the EC2 host.
#   sudo bash run_security_gates.sh <organization-id> <application-id> [evidence.json]
# Collects host facts, then evaluates gates A–J inside the API container so the
# database gate measures the real runtime role. Changes nothing.
set -Eeuo pipefail
umask 077
ORG="${1:?organization id}"; APP="${2:?application id}"; EVIDENCE="${3:-}"
APP_DIR=/home/ubuntu/accessproof
compose() { docker compose --project-directory "$APP_DIR" -f "$APP_DIR/docker-compose.ec2.yml" "$@"; }
state() { local c; c=$(compose ps -q "$1" 2>/dev/null || true); [[ -n "$c" ]] && docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$c" || echo missing; }
OUT=$(mktemp -d); trap 'rm -rf "$OUT"' EXIT
head_rev=$(compose exec -T api alembic heads 2>/dev/null | awk '/\(head\)/{print $1}')
db_rev=$(compose exec -T db psql -U accessproof -d accessproof -tAc "select version_num from alembic_version" | tr -d '[:space:]')
rollbacks=$(ls -d /home/ubuntu/accessproof-releases/*/rollback 2>/dev/null | wc -l)
# The API container's root filesystem is read-only: facts and evidence are
# streamed over stdin, never copied into the container.
python3 - "$(state api)" "$(state worker)" "$(state db)" "$(state redis)" "$(state web)" \
  "$head_rev" "$db_rev" "$rollbacks" "$EVIDENCE" > "$OUT/bundle.json" <<'PY'
import json, sys
api, worker, db, redis, web, head, rev, rollbacks, evidence = sys.argv[1:]
facts = {"api_healthy": api == "healthy", "worker_running": worker in {"running", "healthy"},
         "db_healthy": db == "healthy", "redis_healthy": redis == "healthy", "web_healthy": web == "healthy",
         "migration_at_head": bool(head) and head == rev, "rollback_available": int(rollbacks) > 0}
json.dump({"host_facts": facts, "evidence": json.load(open(evidence)) if evidence else None}, sys.stdout)
PY
compose exec -T api python scripts/production_security_gates.py --organization-id "$ORG" \
  --application-id "$APP" --stdin-bundle < "$OUT/bundle.json"
