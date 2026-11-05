#!/usr/bin/env bash
# OWNER-RUN: hardened unattended AWS authentication for the AccessProof certifier host.
#
# What it creates (idempotent; safe to rerun):
#   SSM documents  AccessProof-Certifier-ProductionReadOnly / -ProductionImport / -RagHostProbe
#                  (rendered in deploy/certifier/ssm, hashes in MANIFEST.json; no AWS-RunShellScript)
#   Roles Anywhere trust anchor  accessproof-certifier-host-ca  (the local CA certificate)
#   Role accessproof-staging-tunnel  + profile  (staging SSH-over-SSM only; denied all command execution)
#   Role accessproof-certifier       + profile  (the three named documents only; denied IAM/documents/shell/sessions)
#   CLI profiles accessproof-staging-tunnel / accessproof-certifier  (credential_process; 1-hour credentials,
#                  refreshed automatically by aws_signing_helper; NO access keys anywhere)
#
# Then it VALIDATES allowed and denied operations for each role, and only if every
# check passes switches the services (systemd drop-ins; backup kept). Finally it
# encrypts the CA private key with a passphrase you choose and removes the plaintext.
#
# Run while signed in (aws login) as an administrator, from the repository root:
#   bash deploy/certifier/setup_unattended_aws_identity.sh
# Recovery (restores the previous service configuration):
#   bash deploy/certifier/setup_unattended_aws_identity.sh --rollback
set -euo pipefail
REGION=eu-north-1
ACCOUNT=102076848988
PROD=i-0c11427d4d9c1b438
STG=i-0e6d2256a1e5a6f67
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
RA="$HOME/.ap-id/rolesanywhere"
HELPER="$HOME/.local/bin/aws_signing_helper"
UNITS="$HOME/.config/systemd/user"
BACKUP_LINK="$HOME/.ap-id/aws-setup-backup-latest"
SERVICES_CERTIFIER="accessproof-route-attestation.service accessproof-cert-renewal.service accessproof-cert-renewal-pilot.service"
SERVICE_TUNNEL="accessproof-remote-rag-tunnel.service"
log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*"; }
die() { log "FAILED: $*"; log "Nothing was switched. Services keep their previous configuration."; exit 1; }

if [ "${1:-}" = "--encrypt-ca-key" ]; then
  [ -f "$RA/ca.key" ] || { log "no plaintext CA key (already encrypted?)"; exit 0; }
  mkdir -p "$HOME/.ap-id/rolesanywhere-ca"; chmod 700 "$HOME/.ap-id/rolesanywhere-ca"
  openssl pkey -in "$RA/ca.key" -aes-256-cbc -out "$HOME/.ap-id/rolesanywhere-ca/ca.key.enc"
  chmod 600 "$HOME/.ap-id/rolesanywhere-ca/ca.key.enc"; shred -u "$RA/ca.key"; log "CA key encrypted; plaintext removed"; exit 0
fi
if [ "${1:-}" = "--rollback" ]; then
  [ -d "$BACKUP_LINK" ] || die "no backup at $BACKUP_LINK"
  for u in $SERVICE_TUNNEL $SERVICES_CERTIFIER; do rm -f "$UNITS/$u.d/aws-identity.conf"
    [ -f "$BACKUP_LINK/$u.aws-identity.conf" ] && cp "$BACKUP_LINK/$u.aws-identity.conf" "$UNITS/$u.d/aws-identity.conf"; done
  systemctl --user daemon-reload; systemctl --user restart $SERVICE_TUNNEL
  log "rolled back to the configuration saved in $BACKUP_LINK"; exit 0
fi

# ---------------------------------------------------------------- preconditions
for f in "$RA/ca.pem" "$RA/tunnel/host.pem" "$RA/tunnel/host.key" "$RA/certifier/host.pem" "$RA/certifier/host.key"; do
  [ -r "$f" ] || die "missing $f"; done
for k in "$RA/tunnel/host.key" "$RA/certifier/host.key"; do [ "$(stat -c %a "$k")" = "600" ] || die "$k must be 0600"; done
[ -x "$HELPER" ] || die "missing $HELPER"
aws sts get-caller-identity --query Arn --output text >/dev/null || die "sign in first: aws login"
python3 - "$HERE/ssm" <<'PY' || die "SSM document files do not match MANIFEST.json (regenerate and review)"
import hashlib, json, sys, pathlib
d = pathlib.Path(sys.argv[1]); m = json.loads((d / "MANIFEST.json").read_text())
assert all(hashlib.sha256((d / f"{n}.json").read_bytes()).hexdigest() == v["sha256"] for n, v in m.items())
PY

# ---------------------------------------------------------------- 1. SSM documents (exact reviewed content)
for f in "$HERE"/ssm/AccessProof-*.json; do
  name=$(basename "$f" .json)
  if aws ssm describe-document --region $REGION --name "$name" >/dev/null 2>&1; then
    ver=$(aws ssm update-document --region $REGION --name "$name" --content "file://$f" --document-format JSON \
          --document-version '$LATEST' --query DocumentDescription.DocumentVersion --output text 2>/dev/null || true)
    if [ -n "$ver" ] && [ "$ver" != "None" ]; then
      aws ssm update-document-default-version --region $REGION --name "$name" --document-version "$ver" >/dev/null
      log "document $name updated to version $ver"
    else log "document $name unchanged"; fi
  else
    aws ssm create-document --region $REGION --name "$name" --document-type Command --document-format JSON \
        --content "file://$f" >/dev/null; log "document $name created"
  fi
done

# ---------------------------------------------------------------- 2. trust anchor
TA=$(aws rolesanywhere list-trust-anchors --region $REGION \
      --query "trustAnchors[?name=='accessproof-certifier-host-ca'].trustAnchorArn | [0]" --output text)
if [ "$TA" = "None" ] || [ -z "$TA" ]; then
  TA=$(aws rolesanywhere create-trust-anchor --region $REGION --name accessproof-certifier-host-ca --enabled \
        --source "$(python3 -c 'import json,sys;print(json.dumps({"sourceType":"CERTIFICATE_BUNDLE","sourceData":{"x509CertificateData":open(sys.argv[1]).read()}}))' "$RA/ca.pem")" \
        --query trustAnchor.trustAnchorArn --output text)
fi
log "trust anchor $TA"

# ---------------------------------------------------------------- 3. roles, policies, profiles
role() {  # name ou cn policyfile -> prints profile arn
  local NAME=$1 OU=$2 CN=$3 POLICY=$4 TRUST
  TRUST=$(python3 - "$TA" "$OU" "$CN" <<'PY'
import json, sys
ta, ou, cn = sys.argv[1:]
print(json.dumps({"Version": "2012-10-17", "Statement": [{
  "Effect": "Allow", "Principal": {"Service": "rolesanywhere.amazonaws.com"},
  "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"],
  "Condition": {"ArnEquals": {"aws:SourceArn": ta},
                "StringEquals": {"aws:PrincipalTag/x509Subject/CN": cn, "aws:PrincipalTag/x509Subject/OU": ou,
                                 "aws:PrincipalTag/x509Subject/O": "NeuralMatrix AccessProof",
                                 "aws:PrincipalTag/x509Issuer/CN": "AccessProof Certifier Host CA"}}}]}))
PY
)
  if aws iam get-role --role-name "$NAME" >/dev/null 2>&1; then
    aws iam update-assume-role-policy --role-name "$NAME" --policy-document "$TRUST"
  else
    aws iam create-role --role-name "$NAME" --max-session-duration 3600 --assume-role-policy-document "$TRUST" >/dev/null
  fi
  for old in $(aws iam list-role-policies --role-name "$NAME" --query PolicyNames --output text); do
    [ "$old" = "$NAME-least-privilege" ] || aws iam delete-role-policy --role-name "$NAME" --policy-name "$old"; done
  aws iam put-role-policy --role-name "$NAME" --policy-name "$NAME-least-privilege" --policy-document "file://$POLICY"
  [ -z "$(aws iam list-attached-role-policies --role-name "$NAME" --query AttachedPolicies --output text)" ] \
      || die "$NAME has attached managed policies; remove them"
  local P
  P=$(aws rolesanywhere list-profiles --region $REGION --query "profiles[?name=='$NAME'].profileArn | [0]" --output text)
  if [ "$P" = "None" ] || [ -z "$P" ]; then
    P=$(aws rolesanywhere create-profile --region $REGION --name "$NAME" --enabled --duration-seconds 3600 \
         --accept-role-session-name --role-arns "arn:aws:iam::$ACCOUNT:role/$NAME" --query profile.profileArn --output text)
  fi
  # Fixed session names are what the "own sessions only" permission relies on.
  aws rolesanywhere update-profile --region $REGION --profile-id "${P##*/}" --accept-role-session-name \
      --role-arns "arn:aws:iam::$ACCOUNT:role/$NAME" --duration-seconds 3600 >/dev/null
  echo "$P"
}
P_TUNNEL=$(role accessproof-staging-tunnel staging-tunnel accessproof-tunnel-host "$HERE/iam-policy-staging-tunnel.json")
P_CERT=$(role accessproof-certifier certifier accessproof-certifier-host "$HERE/iam-policy-certifier.json")
log "profiles: tunnel=$P_TUNNEL certifier=$P_CERT"
log "waiting 15 s for IAM propagation"; sleep 15

# ---------------------------------------------------------------- 4. CLI profiles (no secrets stored)
python3 - "$HOME/.aws/config" "$TA" "$HELPER" "$RA" "$ACCOUNT" "$P_TUNNEL" "$P_CERT" <<'PY'
import configparser, sys
path, ta, helper, ra, acct, p_tunnel, p_cert = sys.argv[1:]
c = configparser.RawConfigParser(); c.read(path)
for name, sub, prof in (("accessproof-staging-tunnel", "tunnel", p_tunnel), ("accessproof-certifier", "certifier", p_cert)):
    sec = f"profile {name}"
    if not c.has_section(sec):
        c.add_section(sec)
    c.set(sec, "region", "eu-north-1")
    c.set(sec, "credential_process",
          f"{helper} credential-process --certificate {ra}/{sub}/host.pem --private-key {ra}/{sub}/host.key "
          f"--trust-anchor-arn {ta} --profile-arn {prof} --role-arn arn:aws:iam::{acct}:role/{name} --role-session-name {name}")
if c.has_section("profile accessproof-certifier") and c.has_option("profile accessproof-certifier", "credential_process"):
    pass
with open(path, "w") as fh:
    c.write(fh)
PY

# ---------------------------------------------------------------- 5. validate BEFORE switching
as() { local P=$1; shift; env -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN AWS_PROFILE="$P" "$@"; }
expect_denied() { local what=$1; shift; if out=$("$@" 2>&1); then die "NOT DENIED: $what"; fi
  echo "$out" | grep -qE "AccessDenied|not authorized|UnauthorizedOperation" || die "unexpected error for $what: ${out: -200}"
  log "denied as expected: $what"; }
[ "$(as accessproof-staging-tunnel aws sts get-caller-identity --query Arn --output text)" = "arn:aws:sts::$ACCOUNT:assumed-role/accessproof-staging-tunnel/accessproof-staging-tunnel" ] || die "tunnel identity"
[ "$(as accessproof-certifier aws sts get-caller-identity --query Arn --output text)" = "arn:aws:sts::$ACCOUNT:assumed-role/accessproof-certifier/accessproof-certifier" ] || die "certifier identity"
log "both roles authenticate with 1-hour credentials"
expect_denied "tunnel -> command on production"   as accessproof-staging-tunnel aws ssm send-command --region $REGION --instance-ids $PROD --document-name AccessProof-Certifier-ProductionReadOnly --parameters operation=certificate_status
expect_denied "tunnel -> IAM"                      as accessproof-staging-tunnel aws iam list-roles --max-items 1
expect_denied "certifier -> AWS-RunShellScript"    as accessproof-certifier aws ssm send-command --region $REGION --instance-ids $PROD --document-name AWS-RunShellScript --parameters commands=id
expect_denied "certifier -> interactive session"   as accessproof-certifier aws ssm start-session --region $REGION --target $PROD
expect_denied "certifier -> SSH key push"          as accessproof-certifier aws ec2-instance-connect send-ssh-public-key --region $REGION --instance-id $STG --instance-os-user ubuntu --ssh-public-key "file://$HOME/.ap-id/remote-gw/ssh_ed25519.pub"
expect_denied "certifier -> change a document"     as accessproof-certifier aws ssm update-document --region $REGION --name AccessProof-Certifier-ProductionImport --content "file://$HERE/ssm/AccessProof-Certifier-ProductionImport.json" --document-version '$LATEST'
expect_denied "certifier -> IAM"                   as accessproof-certifier aws iam list-roles --max-items 1
out=$(cd "$REPO" && as accessproof-certifier python3 -c 'import sys; sys.path.insert(0,"scripts/certifier"); import ssm_ops; print(ssm_ops.read_only("certificate_status", organizationId="48ee8c86-d4d8-4cde-b00b-bc779f965f4f", sourceId="2fa9562b-b765-4098-bebf-222ea53ec667"))') \
    || die "certifier cannot run the read-only document"
echo "$out" | grep -q '|verified$' || die "unexpected read-only result"
log "certifier: read-only document works"
as accessproof-staging-tunnel aws ec2-instance-connect send-ssh-public-key --region $REGION --instance-id $STG \
    --instance-os-user ubuntu --ssh-public-key "file://$HOME/.ap-id/remote-gw/ssh_ed25519.pub" --query Success --output text | grep -q True \
    || die "tunnel cannot push its key to staging"
log "tunnel: staging key push works"

# ---------------------------------------------------------------- 6. switch services (backup first)
B="$HOME/.ap-id/aws-setup-backup-$(date -u +%Y%m%dT%H%M%SZ)"; mkdir -p "$B"; chmod 700 "$B"
for u in $SERVICE_TUNNEL $SERVICES_CERTIFIER; do
  [ -f "$UNITS/$u.d/aws-identity.conf" ] && cp "$UNITS/$u.d/aws-identity.conf" "$B/$u.aws-identity.conf"; done
ln -sfn "$B" "$BACKUP_LINK"
mkdir -p "$UNITS/$SERVICE_TUNNEL.d"
printf '[Service]\nEnvironment=AWS_PROFILE=accessproof-staging-tunnel\n' > "$UNITS/$SERVICE_TUNNEL.d/aws-identity.conf"
for u in $SERVICES_CERTIFIER; do
  mkdir -p "$UNITS/$u.d"
  printf '[Service]\nEnvironment=AWS_PROFILE=accessproof-certifier\nWorkingDirectory=%%h/Projects/AccessProof-universal\n' > "$UNITS/$u.d/aws-identity.conf"
done
systemctl --user daemon-reload
systemctl --user restart $SERVICE_TUNNEL
log "services switched (backup: $B). Protect, Guards, Gateways and refreshers were not touched."

# ---------------------------------------------------------------- 7. protect the CA private key
if [ -f "$RA/ca.key" ] && [ ! -t 0 ]; then
  log "CA key NOT encrypted (no terminal for the passphrase). Run interactively later:"
  log "  bash deploy/certifier/setup_unattended_aws_identity.sh --encrypt-ca-key"
elif [ -f "$RA/ca.key" ]; then
  mkdir -p "$HOME/.ap-id/rolesanywhere-ca"; chmod 700 "$HOME/.ap-id/rolesanywhere-ca"
  log "Choose a passphrase for the CA private key (needed only to issue/revoke host certificates):"
  openssl pkey -in "$RA/ca.key" -aes-256-cbc -out "$HOME/.ap-id/rolesanywhere-ca/ca.key.enc"
  chmod 600 "$HOME/.ap-id/rolesanywhere-ca/ca.key.enc"
  shred -u "$RA/ca.key" && log "CA key encrypted to ~/.ap-id/rolesanywhere-ca/ca.key.enc; plaintext removed (move it offline if possible)"
fi
log "DONE. Ask Claude to run the unattended verification."
