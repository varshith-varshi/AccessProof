#!/usr/bin/env bash
# OWNER-RUN, ONCE: unattended AWS authentication for the AccessProof certifier host.
#
# Mechanism: IAM Roles Anywhere. The host proves its identity with an X.509
# certificate (~/.ap-id/rolesanywhere/host.pem + host.key, 0600, generated on this
# host by Claude; the CA is the trust anchor). AWS issues 1-hour credentials,
# refreshed automatically by aws_signing_helper via `credential_process`. No IAM
# user and no access keys are created, and the root account is never used by the
# services. Run this while you are signed in (`aws login`); the services stop
# using that session afterwards.
#
#   bash deploy/certifier/setup_unattended_aws_identity.sh
set -euo pipefail
REGION=eu-north-1
ACCOUNT=102076848988
ROLE=accessproof-certifier
D="$HOME/.ap-id/rolesanywhere"
HERE="$(cd "$(dirname "$0")" && pwd)"
HELPER="$HOME/.local/bin/aws_signing_helper"

[ -r "$D/ca.pem" ] && [ -r "$D/host.pem" ] && [ -r "$D/host.key" ] || { echo "missing $D/{ca,host}.pem or host.key"; exit 1; }
[ "$(stat -c %a "$D/host.key")" = "600" ] || { echo "host.key must be 0600"; exit 1; }
[ -x "$HELPER" ] || { echo "missing $HELPER"; exit 1; }
aws sts get-caller-identity --query Arn --output text >/dev/null

# 1. Trust anchor = the certifier host CA (reuse if it exists).
TA=$(aws rolesanywhere list-trust-anchors --region $REGION \
      --query "trustAnchors[?name=='accessproof-certifier-host-ca'].trustAnchorArn | [0]" --output text)
if [ "$TA" = "None" ] || [ -z "$TA" ]; then
  TA=$(aws rolesanywhere create-trust-anchor --region $REGION --name accessproof-certifier-host-ca --enabled \
        --source "{\"sourceType\":\"CERTIFICATE_BUNDLE\",\"sourceData\":{\"x509CertificateData\":$(python3 -c 'import json,sys;print(json.dumps(open(sys.argv[1]).read()))' "$D/ca.pem")}}" \
        --query trustAnchor.trustAnchorArn --output text)
fi
echo "trust anchor: $TA"

# 2. Role: assumable ONLY via Roles Anywhere, ONLY from this trust anchor, ONLY by the certifier host certificate.
TRUST=$(python3 - "$TA" <<'PY'
import json, sys
print(json.dumps({"Version": "2012-10-17", "Statement": [{
    "Effect": "Allow", "Principal": {"Service": "rolesanywhere.amazonaws.com"},
    "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"],
    "Condition": {"ArnEquals": {"aws:SourceArn": sys.argv[1]},
                  "StringEquals": {"aws:PrincipalTag/x509Subject/CN": "accessproof-certifier-host",
                                   "aws:PrincipalTag/x509Subject/OU": "certifier"}}}]}))
PY
)
if aws iam get-role --role-name $ROLE >/dev/null 2>&1; then
  aws iam update-assume-role-policy --role-name $ROLE --policy-document "$TRUST"
else
  aws iam create-role --role-name $ROLE --max-session-duration 3600 --assume-role-policy-document "$TRUST" \
      --description "AccessProof certifier host: staging tunnel, remote route verification, source certificate renewal" >/dev/null
fi
aws iam put-role-policy --role-name $ROLE --policy-name accessproof-certifier-least-privilege \
    --policy-document "file://$HERE/certifier-unattended-iam-policy.json"
ROLE_ARN="arn:aws:iam::$ACCOUNT:role/$ROLE"
echo "role: $ROLE_ARN"

# 3. Profile: 1-hour sessions for that role only.
PROFILE=$(aws rolesanywhere list-profiles --region $REGION \
           --query "profiles[?name=='accessproof-certifier'].profileArn | [0]" --output text)
if [ "$PROFILE" = "None" ] || [ -z "$PROFILE" ]; then
  PROFILE=$(aws rolesanywhere create-profile --region $REGION --name accessproof-certifier --enabled \
             --role-arns "$ROLE_ARN" --duration-seconds 3600 --query profile.profileArn --output text)
fi
echo "profile: $PROFILE"

# 4. CLI profile (credential_process: short-lived, auto-refreshed; no stored secret).
mkdir -p "$HOME/.aws"
python3 - "$HOME/.aws/config" "$TA" "$PROFILE" "$ROLE_ARN" "$D" "$HELPER" <<'PY'
import configparser, sys
path, ta, prof, role, d, helper = sys.argv[1:]
c = configparser.RawConfigParser()
c.read(path)
section = "profile accessproof-certifier"
if not c.has_section(section):
    c.add_section(section)
c.set(section, "region", "eu-north-1")
c.set(section, "credential_process",
      f"{helper} credential-process --certificate {d}/host.pem --private-key {d}/host.key "
      f"--trust-anchor-arn {ta} --profile-arn {prof} --role-arn {role} --role-session-name accessproof-certifier")
with open(path, "w") as fh:
    c.write(fh)
PY
echo "identity via role:"; AWS_PROFILE=accessproof-certifier aws sts get-caller-identity --query Arn --output text

# 5. Point the three services at the role (systemd drop-ins); reload.
for u in accessproof-remote-rag-tunnel.service accessproof-route-attestation.service \
         accessproof-cert-renewal.service accessproof-cert-renewal-pilot.service; do
  mkdir -p "$HOME/.config/systemd/user/$u.d"
  printf '[Service]\nEnvironment=AWS_PROFILE=accessproof-certifier\nEnvironment=AWS_SDK_LOAD_CONFIG=1\n' > "$HOME/.config/systemd/user/$u.d/aws-identity.conf"
done
systemctl --user daemon-reload
systemctl --user restart accessproof-remote-rag-tunnel.service
echo "DONE. Tell Claude to verify the services without the interactive session."
