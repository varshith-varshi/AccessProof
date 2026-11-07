#!/usr/bin/env bash
# Install preflight-only service on a *new*, approved, dedicated certifier EC2.
# Deliberately no certificate signer, employee session, raw key, import access,
# or production cutover. Requires instance already provisioned by admin stack.
set -euo pipefail
umask 027

if [[ "${EUID}" -ne 0 || "${#}" -ne 3 ]]; then
  echo "Usage: sudo bash bootstrap_readonly_host.sh EXPECTED_INSTANCE_ID EXECUTION_ROLE_ARN ED25519_KMS_KEY_ARN" >&2
  exit 2
fi
INSTANCE_ID="$1"
EXEC_ROLE="$2"
KMS_ARN="$3"
REGION=eu-north-1
if [[ ! "$INSTANCE_ID" =~ ^i-[0-9a-f]{17}$ ]] ||
   [[ ! "$EXEC_ROLE" =~ ^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9_+=,.@-]{1,64}$ ]] ||
   [[ ! "$KMS_ARN" =~ ^arn:aws:kms:eu-north-1:[0-9]{12}:key/[0-9a-fA-F-]{36}$ ]] ||
   [[ "${EXEC_ROLE:13:12}" != "${KMS_ARN:23:12}" ]] ||
   [[ "$INSTANCE_ID" == "i-0c11427d4d9c1b438" || "$INSTANCE_ID" == "i-0e6d2256a1e5a6f67" ]]; then
  echo "REFUSED: identity must refer to a separate, approved eu-north-1 certifier instance and role." >&2
  exit 2
fi
# The host must prove its own instance ID using IMDSv2, not a caller's assertion.
TOKEN="$(curl -fsS --connect-timeout 2 --max-time 4 -X PUT \
  -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' \
  http://169.254.169.254/latest/api/token)"
HOST_ID="$(curl -fsS --connect-timeout 2 --max-time 4 \
  -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/instance-id)"
unset TOKEN
if [[ "$HOST_ID" != "$INSTANCE_ID" ]]; then
  echo "REFUSED: instance identity mismatch." >&2
  exit 2
fi
if [[ ! -f scripts/certifier/independent_host_preflight.py ]]; then
  echo "REFUSED: run from the reviewed AccessProof source tree." >&2
  exit 2
fi
if ! command -v aws >/dev/null || ! command -v python3 >/dev/null; then
  echo "REFUSED: AWS CLI and Python 3 are prerequisites. No service activated." >&2
  exit 2
fi

install -d -o root -g root -m 0755 /opt/accessproof-independent-certifier
install -d -o root -g root -m 0755 /etc/accessproof-independent-certifier
install -o root -g root -m 0644 scripts/certifier/independent_host_preflight.py \
  /opt/accessproof-independent-certifier/independent_host_preflight.py

# This configuration contains ROLE ARNs ONLY. No static AWS access key and no
# employee OAuth token ever belong here. AWS SDK assumes the restricted role
# using IMDS instance credentials; KMS Sign remains denied in this phase.
cat > /etc/accessproof-independent-certifier/aws-config <<EOF
[profile accessproof-certifier]
region = $REGION
role_arn = $EXEC_ROLE
credential_source = Ec2InstanceMetadata
EOF
chmod 0644 /etc/accessproof-independent-certifier/aws-config

cat > /etc/systemd/system/accessproof-independent-certifier-preflight.service <<EOF
[Unit]
Description=AccessProof isolated certifier host identity and public key preflight
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
DynamicUser=yes
Environment=AWS_PROFILE=accessproof-certifier
Environment=AWS_CONFIG_FILE=/etc/accessproof-independent-certifier/aws-config
Environment=AWS_SHARED_CREDENTIALS_FILE=/dev/null
Environment=AWS_EC2_METADATA_DISABLED=false
ExecStart=/usr/bin/python3 /opt/accessproof-independent-certifier/independent_host_preflight.py --expected-instance-id $INSTANCE_ID --expected-role-arn $EXEC_ROLE --kms-key-arn $KMS_ARN
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
CapabilityBoundingSet=
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
MemoryMax=128M
TimeoutStartSec=75s
StandardOutput=journal
StandardError=journal
EOF
cat > /etc/systemd/system/accessproof-independent-certifier-preflight.timer <<'EOF'
[Unit]
Description=Periodically verify AccessProof independent certifier host prerequisites
[Timer]
OnBootSec=2min
OnUnitInactiveSec=12h
RandomizedDelaySec=90s
Persistent=true
Unit=accessproof-independent-certifier-preflight.service
[Install]
WantedBy=timers.target
EOF
chmod 0644 /etc/systemd/system/accessproof-independent-certifier-preflight.*
systemctl daemon-reload
systemctl enable --now accessproof-independent-certifier-preflight.timer
echo "READ_ONLY_PREFLIGHT_INSTALLED: no signing, no certificate renewal, no imports, no cutover."
