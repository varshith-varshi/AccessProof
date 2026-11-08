#!/usr/bin/env bash
# Installer for independent certifier's production READ-ONLY status watcher.
# NOT a source-certification writer: no private keys, human tokens or imports.
set -euo pipefail
umask 027

if [[ $EUID -ne 0 || $# -ne 3 ]]; then
  echo "Usage: sudo bash install_status_watcher.sh CERTIFIER_INSTANCE_ID EXEC_ROLE_ARN KMS_KEY_ARN" >&2
  exit 2
fi
INSTANCE_ID="$1"; EXEC_ROLE="$2"; KMS_ARN="$3"
[[ "$INSTANCE_ID" =~ ^i-[0-9a-f]{17}$ ]] || { echo 'INVALID_INSTANCE'; exit 2; }
[[ "$EXEC_ROLE" == 'arn:aws:iam::102076848988:role/AccessProofIndependentCertifierExec2026' ]] || { echo 'INVALID_ROLE'; exit 2; }
[[ "$KMS_ARN" == 'arn:aws:kms:eu-north-1:102076848988:key/0f040c1c-afc8-4227-9f9f-18aa014c5f10' ]] || { echo 'INVALID_KMS'; exit 2; }
[[ -f ./scripts/certifier/independent_status_watcher.py ]] || { echo 'REVIEWED_SOURCE_REQUIRED'; exit 2; }
[[ -f /opt/accessproof-independent-certifier/independent_host_preflight.py ]] || { echo 'BASE_PREFLIGHT_REQUIRED'; exit 2; }

# Always prove this is the separate certifier EC2; do not install on production.
TOKEN="$(curl -fsS --connect-timeout 2 --max-time 4 -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' http://169.254.169.254/latest/api/token)"
SELF="$(curl -fsS --connect-timeout 2 --max-time 4 -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)"
unset TOKEN
[[ "$SELF" == "$INSTANCE_ID" && "$SELF" == 'i-0af8a03948e7ba058' ]] || { echo 'WRONG_HOST'; exit 2; }

install -o root -g root -m 0644 scripts/certifier/independent_status_watcher.py /opt/accessproof-independent-certifier/independent_status_watcher.py

cat > /etc/systemd/system/accessproof-independent-certificate-status.service <<EOF
[Unit]
Description=AccessProof read-only production certificate expiry watcher (NO renewal)
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
DynamicUser=yes
Environment=AWS_PROFILE=accessproof-certifier
Environment=AWS_CONFIG_FILE=/etc/accessproof-independent-certifier/aws-config
Environment=AWS_SHARED_CREDENTIALS_FILE=/dev/null
Environment=AWS_EC2_METADATA_DISABLED=false
Environment=HOME=/run/accessproof-independent-certifier
RuntimeDirectory=accessproof-independent-certifier
RuntimeDirectoryMode=0700
ExecStart=/usr/bin/python3 /opt/accessproof-independent-certifier/independent_status_watcher.py --expected-instance-id $INSTANCE_ID --expected-role-arn $EXEC_ROLE --kms-key-arn $KMS_ARN
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
MemoryMax=256M
TimeoutStartSec=160s
StandardOutput=journal
StandardError=journal
EOF
cat > /etc/systemd/system/accessproof-independent-certificate-status.timer <<'EOF'
[Unit]
Description=Hourly independent observation of source and route certificate status
[Timer]
OnBootSec=4min
OnUnitInactiveSec=1h
RandomizedDelaySec=2min
Persistent=true
Unit=accessproof-independent-certificate-status.service
[Install]
WantedBy=timers.target
EOF
chmod 0644 /etc/systemd/system/accessproof-independent-certificate-status.*
systemctl daemon-reload
systemctl enable --now accessproof-independent-certificate-status.timer
echo "READ_ONLY_STATUS_WATCHER_INSTALLED, CERTIFICATE_SIGNING_AND_IMPORT_STILL_DISABLED"
