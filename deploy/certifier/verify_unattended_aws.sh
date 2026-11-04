#!/usr/bin/env bash
# Verify unattended operation WITHOUT the interactive AWS login session.
#   bash deploy/certifier/verify_unattended_aws.sh
# The `aws login` cache (~/.aws/login) is moved aside for the duration (restored by
# trap), so any service that still depended on it would fail here.
set -uo pipefail
LOGIN="$HOME/.aws/login"; HIDDEN="$HOME/.aws/login.hidden-for-verification"
PASS=0; FAIL=0
ok()   { echo "PASS  $*"; PASS=$((PASS+1)); }
bad()  { echo "FAIL  $*"; FAIL=$((FAIL+1)); }
restore() { [ -d "$HIDDEN" ] && mv "$HIDDEN" "$LOGIN"; }
trap restore EXIT
[ -d "$LOGIN" ] && mv "$LOGIN" "$HIDDEN"
env -u AWS_PROFILE aws sts get-caller-identity >/dev/null 2>&1 && bad "interactive/default credentials still usable (test invalid)" || ok "interactive login session unavailable during this test"

for p in accessproof-staging-tunnel accessproof-certifier; do
  arn=$(AWS_PROFILE=$p aws sts get-caller-identity --query Arn --output text 2>/dev/null) && ok "$p authenticates: $arn" || bad "$p cannot authenticate"
  exp=$(AWS_PROFILE=$p aws configure export-credentials --format process 2>/dev/null | python3 -c 'import json,sys;print(json.load(sys.stdin).get("Expiration",""))')
  [ -n "$exp" ] && ok "$p short-lived credentials expire $exp (auto-refreshed by credential_process)" || bad "$p no expiring credentials"
done
AWS_PROFILE=accessproof-certifier aws ssm send-command --region eu-north-1 --instance-ids i-0c11427d4d9c1b438 \
  --document-name AWS-RunShellScript --parameters commands=id >/dev/null 2>&1 && bad "certifier ran AWS-RunShellScript" || ok "certifier denied AWS-RunShellScript on production"
AWS_PROFILE=accessproof-staging-tunnel aws ssm send-command --region eu-north-1 --instance-ids i-0c11427d4d9c1b438 \
  --document-name AccessProof-Certifier-ProductionReadOnly --parameters operation=certificate_status >/dev/null 2>&1 \
  && bad "tunnel identity reached production" || ok "tunnel identity denied on production"
AWS_PROFILE=accessproof-certifier aws iam list-roles --max-items 1 >/dev/null 2>&1 && bad "certifier can read IAM" || ok "certifier denied IAM"

U=accessproof-remote-rag-tunnel.service
pid=$(systemctl --user show $U -p MainPID --value); systemctl --user kill -s SIGKILL $U 2>/dev/null
for _ in $(seq 1 60); do
  sleep 5
  new=$(systemctl --user show $U -p MainPID --value)
  if [ "$new" != "$pid" ] && [ "$new" != 0 ] && curl -s -m 5 -o /dev/null -w '%{http_code}' 127.0.0.1:28187/health/evidence | grep -q 200; then break; fi
done
curl -s -m 5 -o /dev/null -w '%{http_code}' 127.0.0.1:28188/health/evidence | grep -q 200 \
  && ok "tunnel reconnected after SIGKILL using its role; both remote routes reachable" || bad "tunnel did not recover"

systemctl --user start accessproof-route-attestation.service
[ "$(systemctl --user show accessproof-route-attestation.service -p Result --value)" = success ] \
  && ok "scheduled route verification succeeded (restricted documents)" || bad "route verification failed"
journalctl --user -u accessproof-route-attestation.service -n 6 --no-pager -o cat | grep '"route"' | tail -3

for u in accessproof-cert-renewal.service accessproof-cert-renewal-pilot.service; do
  systemctl --user start $u
  [ "$(systemctl --user show $u -p Result --value)" = success ] && ok "$u ran with the certifier role" || bad "$u failed"
  journalctl --user -u $u -n 3 --no-pager -o cat | tail -2
done

for u in accessproof-ingestion-refresher-reference accessproof-ingestion-refresher-pilot; do
  systemctl --user is-active --quiet $u && ok "$u active" || bad "$u not active"; done
for g in 8080 8081; do curl -s 127.0.0.1:$g/health | grep -q '"ready":true' && ok "guard :$g ready" || bad "guard :$g not ready"; done
echo; echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
