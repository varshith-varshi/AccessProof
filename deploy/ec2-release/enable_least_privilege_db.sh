#!/usr/bin/env bash
# P0-01 production switch to least-privilege database roles — runs ON EC2.
#
#   sudo bash enable_least_privilege_db.sh <release-id> --approve-database-role-change
#   (RECOVERY=1 when the API is down after a credential divergence)
#
# Requires a release deployed with migration t4d5e6f7a8b9 or later.
# 1. Generates three random passwords (never printed; 0600 files + .env).
# 2. Provisions accessproof_app / accessproof_rls_admin / accessproof_metrics
#    as the table owner and verifies, AS EACH ROLE, that it is non-superuser,
#    NOBYPASSRLS, owns nothing, cannot disable RLS (metrics: cannot write).
# 3. Switches the API and worker to those roles and recreates ONLY api+worker.
# 4. Proves the running API is restricted. Any failure restores the previous
#    .env and recreates api+worker on the owner credentials.
set -Eeuo pipefail
umask 077
RELEASE_ID="${1:?release id}"
[[ "${2:-}" == "--approve-database-role-change" ]] || { echo "explicit --approve-database-role-change required"; exit 2; }
APP_DIR=/home/ubuntu/accessproof
COMPOSE_FILE="$APP_DIR/docker-compose.ec2.yml"
REL="/home/ubuntu/accessproof-releases/$RELEASE_ID"
ROLES="$REL/db-roles"
compose() { docker compose --project-directory "$APP_DIR" -f "$COMPOSE_FILE" "$@"; }
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$REL/deployment-logs/db-roles.log"; }
healthy() {  # <service> <seconds>
  local deadline=$((SECONDS + $2)) cid st
  while (( SECONDS < deadline )); do
    cid=$(compose ps -q "$1" || true)
    if [[ -n "$cid" ]]; then
      st=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid")
      [[ "$st" == healthy || ( "$1" == worker && "$st" == running ) ]] && return 0
    fi
    sleep 3
  done
  return 1
}

mkdir -p "$REL/deployment-logs" "$ROLES"
chmod 700 "$ROLES"
# Require the P0-01 policies themselves (migration t4d5e6f7a8b9 or later),
# not a hard-coded revision list that every later migration would break.
policies=$(compose exec -T db psql -U accessproof -d accessproof -tAc \
  "select count(*) from pg_policies where policyname = 'accessproof_tenant_isolation'" | tr -d '[:space:]')
[[ "$policies" =~ ^[0-9]+$ ]] && (( policies >= 58 )) \
  || { log "tenant RLS policies missing ($policies); deploy a release with migration t4d5e6f7a8b9 or later first"; exit 2; }
# RECOVERY=1: allowed when the API is down because the role passwords in the
# database and .env diverged; re-running re-syncs them from .env (idempotent).
if ! healthy api 10; then
  [[ "${RECOVERY:-0}" == 1 ]] || { log "API not healthy; refusing (set RECOVERY=1 to re-sync role passwords from .env)"; exit 2; }
  log "RECOVERY: API unhealthy at start; re-syncing role passwords from .env"
fi

cp -p "$APP_DIR/.env" "$ROLES/env.before"; chmod 600 "$ROLES/env.before"
cp -p "$COMPOSE_FILE" "$ROLES/compose.before"; chmod 600 "$ROLES/compose.before"
restore() {
  log "RESTORE: reverting to previous database credentials"
  cp "$ROLES/env.before" "$APP_DIR/.env"
  cp "$ROLES/compose.before" "$COMPOSE_FILE"
  compose up -d --no-deps --force-recreate api >>"$REL/deployment-logs/db-roles.log" 2>&1
  if ! healthy api 240; then
    log "RESTORE FAILED: API not healthy after reverting .env/compose — ESCALATE (see api logs)"; exit 4
  fi
  compose up -d --no-deps --force-recreate worker >>"$REL/deployment-logs/db-roles.log" 2>&1
  healthy worker 120 || { log "RESTORE FAILED: worker not running — ESCALATE"; exit 4; }
  log "RESTORE complete: api/worker healthy on the pre-run credentials"; exit 1
}
trap 'log "failure at line $LINENO"; restore' ERR

# Password files live in their own directory, owned by the API image's uid
# (10001), and only that directory is mounted: the container user must be
# able to traverse it, and env.before/compose.before never enter a container.
SECRETS="$ROLES/secrets"
mkdir -p "$SECRETS"
# Idempotent: if this host already runs on the restricted roles, REUSE the
# passwords in .env. Rotating here would leave the restored .env (on any later
# failure) out of step with the database and lock the API out. New passwords
# are generated only for roles that have none yet.
existing() {  # <role> -> current password from .env, or empty
  case "$1" in
    app)     grep -E '^ACCESSPROOF_APP_DB_PASSWORD=' "$APP_DIR/.env" | tail -1 | cut -d= -f2- ;;
    worker)  grep -E '^ACCESSPROOF_WORKER_DB_PASSWORD=' "$APP_DIR/.env" | tail -1 | cut -d= -f2- ;;
    metrics) grep -E '^ACCESSPROOF_METRICS_DATABASE_URL=' "$APP_DIR/.env" | tail -1 \
               | sed -nE 's#^[^=]+=postgresql\+psycopg://accessproof_metrics:([^@]+)@.*#\1#p' ;;
  esac
}
for role in app worker metrics; do
  rm -f "$SECRETS/$role.pw"
  current=$(existing "$role")
  if [[ -n "$current" ]]; then printf '%s\n' "$current" > "$SECRETS/$role.pw"; log "$role: reusing existing password"
  else openssl rand -hex 32 > "$SECRETS/$role.pw"; log "$role: generated new password"; fi
done
chown 10001:10001 "$SECRETS" "$SECRETS"/*.pw; chmod 500 "$SECRETS"; chmod 400 "$SECRETS"/*.pw
# Read ONLY the owner password (never source .env: exported values would
# override .env during later compose interpolation). Passed via the
# environment (-e NAME), never in argv.
POSTGRES_PASSWORD=$(grep -E '^POSTGRES_PASSWORD=' "$APP_DIR/.env" | tail -1 | cut -d= -f2- | sed -E "s/^['\"]//; s/['\"]$//")
[[ -n "$POSTGRES_PASSWORD" ]] || { log "POSTGRES_PASSWORD missing from .env"; false; }
export DATABASE_URL="postgresql+psycopg://accessproof:${POSTGRES_PASSWORD}@db:5432/accessproof"
compose run --rm --no-deps -T -v "$SECRETS:/run/db-roles:ro" -e DATABASE_URL api \
  python scripts/provision_database_roles.py \
    --app-password-file /run/db-roles/app.pw \
    --worker-password-file /run/db-roles/worker.pw \
    --metrics-password-file /run/db-roles/metrics.pw > "$REL/deployment-logs/db-roles-verification.json"
unset DATABASE_URL
log "roles provisioned and verified"

# The server Compose file hard-codes the owner URL; switch only api/worker.
python3 "$(dirname "$0")/patch_compose_db_roles.py" "$COMPOSE_FILE" | tee -a "$REL/deployment-logs/db-roles.log"
compose config --quiet

tmp="$APP_DIR/.env.db-roles"
grep -vE '^(ACCESSPROOF_APP_DB_USER|ACCESSPROOF_APP_DB_PASSWORD|ACCESSPROOF_WORKER_DB_USER|ACCESSPROOF_WORKER_DB_PASSWORD|ACCESSPROOF_METRICS_DATABASE_URL)=' "$APP_DIR/.env" > "$tmp"
{
  echo "ACCESSPROOF_APP_DB_USER=accessproof_app"
  echo "ACCESSPROOF_APP_DB_PASSWORD=$(cat "$SECRETS/app.pw")"
  echo "ACCESSPROOF_WORKER_DB_USER=accessproof_rls_admin"
  echo "ACCESSPROOF_WORKER_DB_PASSWORD=$(cat "$SECRETS/worker.pw")"
  echo "ACCESSPROOF_METRICS_DATABASE_URL=postgresql+psycopg://accessproof_metrics:$(cat "$SECRETS/metrics.pw")@db:5432/accessproof"
} >> "$tmp"
chmod 600 "$tmp"; mv "$tmp" "$APP_DIR/.env"

compose up -d --no-deps --force-recreate api >>"$REL/deployment-logs/db-roles.log" 2>&1
healthy api 240
compose up -d --no-deps --force-recreate worker >>"$REL/deployment-logs/db-roles.log" 2>&1
healthy worker 120
# The RUNNING API must now be the restricted role.
compose exec -T api python scripts/provision_database_roles.py --audit > "$REL/deployment-logs/db-runtime-audit.json"
python3 - "$REL/deployment-logs/db-runtime-audit.json" <<'PY'
import json, sys
facts = json.load(open(sys.argv[1]))
ok = (facts["current_user"] == "accessproof_app" and not facts["superuser"] and not facts["bypassrls"]
      and not facts["owns_tables"] and not facts["tables_missing_policy"] and not facts["settable_bypass_policies"])
sys.exit(0 if ok else 1)
PY
if [[ "${PUBLIC_CHECKS:-1}" == 1 ]]; then curl -fsS --max-time 15 https://api.accessproof.in/health/ready > /dev/null; fi
trap - ERR
log "LEAST-PRIVILEGE DATABASE ROLES ACTIVE: api=accessproof_app worker=accessproof_rls_admin metrics=accessproof_metrics"
