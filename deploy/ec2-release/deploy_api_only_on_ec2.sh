#!/usr/bin/env bash
# Isolated, checksum-bound API + worker release; images built OFF the 2GB host.
# Do not inherit ERR traps into functions/command substitutions: a transient
# curl failure otherwise invokes rollback twice in competing shells.
set -euo pipefail
umask 077
RID="${1:?release id}"; ARCHIVE="${2:?artifact}"; SHA="${3:?sha256}"
EXPECTED_DB_REVISION="${EXPECTED_DB_REVISION:?expected production database revision}"
[[ "${PUBLIC_CHECKS:-1}" == 1 ]] || { echo "Production checks required" >&2; exit 2; }
[[ "$RID" =~ ^api-[a-z0-9-]{6,65}-[0-9a-f]{12}$ && "$SHA" =~ ^[0-9a-f]{64}$ ]] || exit 2
APP=/home/ubuntu/accessproof
COMPOSE="$APP/docker-compose.ec2.yml"
REL="/home/ubuntu/accessproof-releases/$RID"
API_IMAGE="accessproof/api:$RID"
WORKER_IMAGE="accessproof/worker:$RID"
INSTALLER_SHA="9db1c5a90e52e22097183c84c670a6dc71046d530a4c7627787d1344ba98ffc6"
log(){ printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
compose(){ docker compose --project-directory "$APP" -f "$COMPOSE" "$@"; }
health(){
  local svc="$1" deadline=$((SECONDS + $2)) cid state
  while (( SECONDS < deadline )); do
    cid="$(compose ps -q "$svc" || true)"
    if [[ -n "$cid" ]]; then
      state="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid")"
      [[ "$state" == healthy || ( "$svc" == worker && "$state" == running ) ]] && return 0
    fi
    sleep 3
  done
  return 1
}
db_revision(){ compose exec -T db psql -U accessproof -d accessproof -tAc 'select version_num from alembic_version' | tr -d '[:space:]'; }
reload_nginx(){ compose exec -T nginx nginx -t && compose exec -T nginx nginx -s reload; }
public_health(){
  local http_code attempt
  # API container health can become READY before the public Nginx/TLS socket
  # finishes reloading. A single curl (55) must not abort a safe release.
  # Keep a bounded deadline and require an actual HTTP 200 (never skip it).
  for attempt in {1..12}; do
    if http_code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 8       https://api.accessproof.in/health/ready 2>/dev/null)" && [[ "$http_code" == 200 ]]; then
      return 0
    fi
    sleep 2
  done
  echo 'PUBLIC_API_HEALTH_NOT_200_WITHIN_RETRY_WINDOW' >&2
  return 1
}
rollback(){
  local rc=$?
  trap - ERR
  log "API RELEASE FAILED at line $1 (exit $rc). Restoring previous API/worker images."
  if [[ -f "$REL/rollback/.env" ]]; then
    cp -p "$REL/rollback/.env" "$APP/.env"
    if compose up -d --no-deps --force-recreate api worker >>"$REL/logs/rollback.log" 2>&1 \
        && health api 240 && health worker 120 && reload_nginx >>"$REL/logs/rollback.log" 2>&1 \
        && public_health; then
      log 'API/WORKER ROLLBACK VERIFIED; web, db and redis untouched'
    else
      log 'CRITICAL: ROLLBACK NOT VERIFIED; operator intervention required' >&2
    fi
  fi
  exit "$rc"
}
install -d -m 700 /home/ubuntu/accessproof-releases
exec 9>>/home/ubuntu/accessproof-releases/.release.lock
flock -n 9 || { log 'Concurrent production release refused'; exit 75; }
[[ "$(sha256sum "$ARCHIVE" | awk '{print $1}')" == "$SHA" ]] || { log 'Artifact hash mismatch'; exit 2; }
commit="$(tar -xOf "$ARCHIVE" RELEASE_COMMIT)"
[[ "$RID" == *-"$(printf '%s' "$commit" | cut -c1-12)" ]] || { log 'Commit mismatch'; exit 2; }
[[ ! -e "$REL/rollback/.env" ]] || { log 'Release ID already used'; exit 2; }
(( $(df -BG --output=avail / | tail -1 | tr -dc 0-9) >= 8 )) || { log 'Insufficient disk'; exit 2; }
for svc in db redis api web; do health "$svc" 12 || { log "Unhealthy $svc"; exit 2; }; done
health worker 12 || { log 'Worker stopped'; exit 2; }
public_health || { log 'Production API not ready'; exit 2; }
[[ "$(db_revision)" == "$EXPECTED_DB_REVISION" ]] || { log 'DB revision changed'; exit 2; }
install -d -m 700 "$REL" "$REL/src" "$REL/rollback" "$REL/logs" "$REL/backup"
log "Isolated API/worker release $RID starting (no EC2 Docker builds)"
cp -p "$APP/.env" "$REL/rollback/.env"
chmod 600 "$REL/rollback/.env"
cp -p "$COMPOSE" "$REL/rollback/docker-compose.ec2.yml"
for svc in db redis nginx web; do echo "$svc=$(compose ps -q "$svc")"; done > "$REL/rollback/unchanged-ids.txt"
for svc in api worker; do
  img="$(docker inspect -f '{{.Config.Image}}' "$(compose ps -q "$svc")")"
  docker image inspect "$img" >/dev/null 2>&1 || { log "Missing prior $svc image"; exit 2; }
  printf '%s=%s\n' "$svc" "$img" >> "$REL/rollback/previous-images.txt"
done
tar -xf "$ARCHIVE" -C "$REL/src"
for svc in api worker; do
  if [[ "$svc" == api ]]; then image="$API_IMAGE"; else image="$WORKER_IMAGE"; fi
  [[ -f "$REL/src/$svc-image.tar.gz" && -f "$REL/src/$svc-image.digests" ]] || { log "$svc image bundle missing"; exit 2; }
  if docker image inspect "$image" >/dev/null 2>&1; then log "$image already exists; refusing reuse"; exit 2; fi
  timeout --signal=TERM --kill-after=30s 10m nice -n 10 ionice -c2 -n7 \
    gzip -dc "$REL/src/$svc-image.tar.gz" | docker load > "$REL/logs/$svc-load.log" 2>&1 \
      || { log "Could not load $svc image"; exit 2; }
  actual="$(docker image inspect -f '{{.Id}}' "$image")"
  grep -Fxq "$actual" "$REL/src/$svc-image.digests" || { log "$svc image digest mismatch"; exit 2; }
  [[ "$(docker image inspect -f '{{.Architecture}}' "$image")" == amd64 ]] || exit 2
  docker run --rm --entrypoint test "$image" -f /app/apps/api/accessproof_api/gateway_presence.py
  log "$svc image verified $actual"
done
target="$(docker run --rm --entrypoint alembic "$API_IMAGE" heads 2>/dev/null | awk '/\(head\)/{print $1}')"
[[ "$target" == "$EXPECTED_DB_REVISION" ]] || { log "Schema migration required ($EXPECTED_DB_REVISION to $target); API-only release refused"; exit 2; }
compose exec -T db pg_dump -U accessproof -d accessproof -Fc > "$REL/backup/pre-$RID.dump"
entries="$(compose exec -T db pg_restore --list < "$REL/backup/pre-$RID.dump" | grep -c ' TABLE DATA ' || true)"
(( entries > 10 )) || { log 'DB backup verification failed'; exit 2; }
sha256sum "$REL/backup/pre-$RID.dump" > "$REL/backup/checksum.txt"
log "DB backup verified ($entries table entries), schema unchanged"
trap 'rollback $LINENO' ERR
tmp="$APP/.env.api-release-$RID"
cp -p "$APP/.env" "$tmp"
sed -i -E "s#^ACCESSPROOF_API_IMAGE=.*#ACCESSPROOF_API_IMAGE=$API_IMAGE#; s#^ACCESSPROOF_WORKER_IMAGE=.*#ACCESSPROOF_WORKER_IMAGE=$WORKER_IMAGE#" "$tmp"
[[ "$(grep -c '^ACCESSPROOF_API_IMAGE=' "$tmp")" == 1 ]]
[[ "$(grep -c '^ACCESSPROOF_WORKER_IMAGE=' "$tmp")" == 1 ]]
mv "$tmp" "$APP/.env"
compose up -d --no-deps --force-recreate api >> "$REL/logs/deploy.log" 2>&1
health api 240
compose up -d --no-deps --force-recreate worker >> "$REL/logs/deploy.log" 2>&1
health worker 120
reload_nginx >> "$REL/logs/deploy.log" 2>&1
public_health
[[ "$(db_revision)" == "$EXPECTED_DB_REVISION" ]]
for svc in api worker; do
  cid="$(compose ps -q "$svc")"
  [[ "$(docker inspect -f '{{.Config.Image}}' "$cid")" == *":$RID" ]]
done
for svc in db redis nginx web; do
  prev="$(grep "^$svc=" "$REL/rollback/unchanged-ids.txt" | cut -d= -f2)"
  [[ "$(compose ps -q "$svc")" == "$prev" ]] || { log "Unexpected $svc recreation"; false; }
done
[[ "$(compose exec -T web sha256sum /app/public/downloads/accessproof-gateway-connector.zip | cut -d' ' -f1)" == "$INSTALLER_SHA" ]] || false
[[ "$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 https://app.accessproof.in/login)" == 200 ]]
[[ "$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 -X POST -H 'Content-Type: application/json' -d '{}' https://api.accessproof.in/api/v1/gateway-installations/heartbeat)" == 422 ]]
[[ "$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 https://api.accessproof.in/api/v1/guards)" == 401 ]]
status="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 -H 'Cookie: accessproof_session=synthetic-invalid-no-real-session' https://app.accessproof.in/downloads/accessproof-gateway-connector.zip)"
[[ "$status" =~ ^(302|303|307|308|401|403)$ ]]
trap - ERR
log "API/WORKER RELEASE VERIFIED $RID: web, db, redis, nginx untouched"
