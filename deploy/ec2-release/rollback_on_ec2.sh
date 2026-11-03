#!/usr/bin/env bash
# Manual rollback of an AccessProof release — runs ON the EC2 host.
#
#   sudo bash rollback_on_ec2.sh <release-id>
#
# Restores the pre-release .env (image references), downgrades ONLY this
# release's migrations (back to previous_db_revision) (refuses if Ed25519 source certificates
# exist, since the downgrade would delete them), and recreates api/worker/web.
# Never touches db/redis/nginx volumes and never restores a database dump.
set -Eeuo pipefail
umask 077
RELEASE_ID="${1:?release id}"
# One release operation at a time on this host (deploy, rollback, DB-role
# switch), whoever starts it: operator, SSM, or an agent.
install -d -m 700 /home/ubuntu/accessproof-releases
exec 9>>/home/ubuntu/accessproof-releases/.release.lock
flock -n 9 || { echo "another release operation holds the host release lock: $(cat /home/ubuntu/accessproof-releases/.release.lock.holder 2>/dev/null)" >&2; exit 75; }
printf '%s pid=%s %s %s\n' "$(date -u +%FT%TZ)" "$$" "$(basename "$0")" "$RELEASE_ID" > /home/ubuntu/accessproof-releases/.release.lock.holder
APP_DIR=/home/ubuntu/accessproof
COMPOSE_FILE="$APP_DIR/docker-compose.ec2.yml"
REL="/home/ubuntu/accessproof-releases/$RELEASE_ID"
compose() { docker compose --project-directory "$APP_DIR" -f "$COMPOSE_FILE" "$@"; }
# Migrations need DDL, so they always run as the table OWNER — never via the
# api service's runtime DATABASE_URL, which after the P0-01 switch is the
# restricted accessproof_app role. The password travels in the environment
# (compose run -e NAME), never in argv, so it never appears in `ps`.
owner_alembic() {  # <api-image> <alembic args...>
  local image="$1"; shift
  local pw; pw=$(grep -E '^POSTGRES_PASSWORD=' "$APP_DIR/.env" | tail -1 | cut -d= -f2- | sed -E "s/^['\"]//; s/['\"]$//")
  [[ -n "$pw" ]] || { echo "POSTGRES_PASSWORD missing from .env" >&2; return 1; }
  DATABASE_URL="postgresql+psycopg://accessproof:${pw}@db:5432/accessproof" ACCESSPROOF_API_IMAGE="$image" \
    compose run --rm --no-deps -T -e DATABASE_URL api alembic "$@"
}
psqlv() { compose exec -T db psql -U accessproof -d accessproof -tAc "$1" | tr -d '[:space:]'; }

[[ -f "$REL/rollback/.env" ]] || { echo "no rollback state for $RELEASE_ID"; exit 2; }
PREVIOUS_REV=$(grep -E '^previous_db_revision=' "$REL/rollback/previous-state.txt" | cut -d= -f2)
[[ "$PREVIOUS_REV" =~ ^[0-9a-z]{12}$ ]] || { echo "previous revision unknown"; exit 2; }
rev=$(psqlv "select version_num from alembic_version")
if [[ "$rev" != "$PREVIOUS_REV" ]]; then
  [[ "$(psqlv "select count(*) from source_effective_certifications where length(signature) > 64")" == 0 ]] \
    || { echo "Ed25519 certificates exist; downgrade would delete them. Decide manually."; exit 3; }
  owner_alembic "accessproof/api:$RELEASE_ID" downgrade "$PREVIOUS_REV"
fi
# Restore ONLY the image references (D-15). Copying the whole pre-release
# .env would also revert any later least-privilege switch, silently putting
# api/worker back on the superuser owner credentials.
tmp="$APP_DIR/.env.rollback-$RELEASE_ID"
cp -p "$APP_DIR/.env" "$tmp"
for k in API WORKER WEB; do
  v=$(grep -E "^ACCESSPROOF_${k}_IMAGE=" "$REL/rollback/.env" | tail -1 | cut -d= -f2-) || v=""
  [[ "$v" =~ ^[a-z0-9./_-]+:[A-Za-z0-9._-]+$ ]] || { rm -f "$tmp"; echo "rollback: no valid previous ACCESSPROOF_${k}_IMAGE"; exit 2; }
  sed -i -E "s#^ACCESSPROOF_${k}_IMAGE=.*#ACCESSPROOF_${k}_IMAGE=$v#" "$tmp"
  grep -qx "ACCESSPROOF_${k}_IMAGE=$v" "$tmp" || { rm -f "$tmp"; echo "rollback: could not set ACCESSPROOF_${k}_IMAGE"; exit 2; }
done
chmod 600 "$tmp"; mv "$tmp" "$APP_DIR/.env"
compose up -d --no-deps --force-recreate api
api_ok=0
for i in $(seq 1 80); do
  [[ "$(docker inspect -f '{{.State.Health.Status}}' "$(compose ps -q api)")" == healthy ]] && { api_ok=1; break; }; sleep 3
done
(( api_ok )) || { echo "ROLLBACK: previous API not healthy after 240s; escalate" >&2; exit 4; }
compose up -d --no-deps --force-recreate worker web
[[ "${PUBLIC_CHECKS:-1}" == 1 ]] && curl -fsS --max-time 15 https://api.accessproof.in/health/ready
[[ "${PUBLIC_CHECKS:-1}" == 1 ]] && curl -fsS --max-time 15 -o /dev/null https://app.accessproof.in/login && echo "web ok"
compose ps --format '{{.Service}} {{.Image}} {{.Status}}'
echo "Rolled back to: $(grep -E '^previous_(api|web|worker)_image=' "$REL/rollback/previous-state.txt" | tr '\n' ' ')"
