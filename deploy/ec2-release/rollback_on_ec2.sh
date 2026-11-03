#!/usr/bin/env bash
# Manual rollback of an AccessProof release — runs ON the EC2 host.
#
#   sudo bash rollback_on_ec2.sh <release-id>
#
# Restores the pre-release .env (image references), downgrades ONLY this
# release's two additive migrations (refuses if Ed25519 source certificates
# exist, since the downgrade would delete them), and recreates api/worker/web.
# Never touches db/redis/nginx volumes and never restores a database dump.
set -Eeuo pipefail
umask 077
RELEASE_ID="${1:?release id}"
APP_DIR=/home/ubuntu/accessproof
COMPOSE_FILE="$APP_DIR/docker-compose.ec2.yml"
REL="/home/ubuntu/accessproof-releases/$RELEASE_ID"
compose() { docker compose --project-directory "$APP_DIR" -f "$COMPOSE_FILE" "$@"; }
psqlv() { compose exec -T db psql -U accessproof -d accessproof -tAc "$1" | tr -d '[:space:]'; }

[[ -f "$REL/rollback/.env" ]] || { echo "no rollback state for $RELEASE_ID"; exit 2; }
PREVIOUS_REV=$(grep -E '^previous_db_revision=' "$REL/rollback/previous-state.txt" | cut -d= -f2)
[[ "$PREVIOUS_REV" =~ ^[0-9a-z]{12}$ ]] || { echo "previous revision unknown"; exit 2; }
rev=$(psqlv "select version_num from alembic_version")
if [[ "$rev" != "$PREVIOUS_REV" ]]; then
  [[ "$(psqlv "select count(*) from source_effective_certifications where length(signature) > 64")" == 0 ]] \
    || { echo "Ed25519 certificates exist; downgrade would delete them. Decide manually."; exit 3; }
  ACCESSPROOF_API_IMAGE="accessproof/api:$RELEASE_ID" compose run --rm --no-deps -T api \
    alembic downgrade "$PREVIOUS_REV"
fi
cp "$REL/rollback/.env" "$APP_DIR/.env"
compose up -d --no-deps --force-recreate api
for i in $(seq 1 80); do
  [[ "$(docker inspect -f '{{.State.Health.Status}}' "$(compose ps -q api)")" == healthy ]] && break; sleep 3
done
compose up -d --no-deps --force-recreate worker web
[[ "${PUBLIC_CHECKS:-1}" == 1 ]] && curl -fsS --max-time 15 https://api.accessproof.in/health/ready
[[ "${PUBLIC_CHECKS:-1}" == 1 ]] && curl -fsS --max-time 15 -o /dev/null https://app.accessproof.in/login && echo "web ok"
compose ps --format '{{.Service}} {{.Image}} {{.Status}}'
echo "Rolled back to: $(grep -E '^previous_(api|web|worker)_image=' "$REL/rollback/previous-state.txt" | tr '\n' ' ')"
