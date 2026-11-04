#!/bin/sh
# Enable Microsoft Graph change notifications on the production WORKER (r35+).
#   sudo sh enable_microsoft_notifications.sh <release-id>
# Backs up compose + .env (0600), adds the passthrough to the worker service,
# recreates ONLY the worker, verifies it is running; restores on any failure.
set -eu
REL_ID="${1:?release id}"
APP=/home/ubuntu/accessproof; BK=/home/ubuntu/accessproof-releases/$REL_ID/notifications-rollback
URL=https://api.accessproof.in/api/v1/provider-events/microsoft
exec 9>>/home/ubuntu/accessproof-releases/.release.lock; flock -n 9 || { echo "release lock held"; exit 75; }
umask 077; install -d -m 700 "$BK"; cp -p "$APP/docker-compose.ec2.yml" "$APP/.env" "$BK/"
compose() { docker compose --project-directory "$APP" -f "$APP/docker-compose.ec2.yml" "$@"; }
restore() { echo "RESTORING"; cp -p "$BK/docker-compose.ec2.yml" "$BK/.env" "$APP/"; compose up -d --no-deps worker; exit 1; }
python3 - "$APP/docker-compose.ec2.yml" <<'PY'
import re, sys
p = sys.argv[1]; lines = open(p).read().split("\n"); out = []; svc = None; done = False
KEY = "      ACCESSPROOF_MICROSOFT_NOTIFICATION_URL: ${ACCESSPROOF_MICROSOFT_NOTIFICATION_URL:-}"
if any("ACCESSPROOF_MICROSOFT_NOTIFICATION_URL" in l for l in lines): sys.exit(0)
for l in lines:
    m = re.match(r"^  ([a-z0-9_-]+):\s*$", l)
    if m: svc = m.group(1)
    out.append(l)
    if svc == "worker" and l == "    environment:" and not done:
        out.append(KEY); done = True
if not done: sys.exit("worker environment block not found")
open(p, "w").write("\n".join(out))
PY
grep -q '^ACCESSPROOF_MICROSOFT_NOTIFICATION_URL=' "$APP/.env" || printf 'ACCESSPROOF_MICROSOFT_NOTIFICATION_URL=%s\n' "$URL" >> "$APP/.env"
compose config -q || restore
compose up -d --no-deps worker || restore
sleep 20
[ "$(docker inspect -f '{{.State.Running}}' accessproof-worker-1)" = true ] || restore
docker exec accessproof-worker-1 printenv ACCESSPROOF_MICROSOFT_NOTIFICATION_URL
sleep 30
docker logs --since 1m accessproof-worker-1 2>&1 | grep -E "graph_subscription|microsoft_subscription|graph_security" | tail -10
echo "NOTIFICATIONS ENABLED (backup: $BK)"
