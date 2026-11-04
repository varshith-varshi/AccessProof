#!/usr/bin/env bash
# OWNER-RUN: revoke a certifier/tunnel host certificate in IAM Roles Anywhere.
#   bash deploy/certifier/rolesanywhere_revoke_host_cert.sh ~/.ap-id/rolesanywhere/tunnel/host.pem
# Builds a CRL signed by the (passphrase-protected) CA key listing the certificate's
# serial (plus any serials already in ~/.ap-id/rolesanywhere-ca/revoked.txt) and
# imports/updates it on the trust anchor. A revoked or expired certificate can no
# longer obtain AWS credentials. Immediate kill switch for everything:
#   aws rolesanywhere disable-trust-anchor --region eu-north-1 --trust-anchor-id <id>
set -euo pipefail
CERT=${1:?certificate to revoke}
CA_DIR="$HOME/.ap-id/rolesanywhere-ca"; RA="$HOME/.ap-id/rolesanywhere"
SERIAL=$(openssl x509 -in "$CERT" -noout -serial | cut -d= -f2)
touch "$CA_DIR/revoked.txt"; grep -qx "$SERIAL" "$CA_DIR/revoked.txt" || echo "$SERIAL" >> "$CA_DIR/revoked.txt"
read -r -s -p "CA key passphrase: " PASS; echo
CRL=$(mktemp); trap 'rm -f "$CRL"' EXIT
AP_CA_PASS="$PASS" python3 - "$CA_DIR/ca.key.enc" "$RA/ca.pem" "$CA_DIR/revoked.txt" "$CRL" <<'PY'
import datetime, os, sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
key = serialization.load_pem_private_key(open(sys.argv[1], "rb").read(), password=os.environ["AP_CA_PASS"].encode())
ca = x509.load_pem_x509_certificate(open(sys.argv[2], "rb").read())
now = datetime.datetime.now(datetime.timezone.utc)
b = (x509.CertificateRevocationListBuilder().issuer_name(ca.subject).last_update(now)
     .next_update(now + datetime.timedelta(days=30)))
for s in open(sys.argv[3]).read().split():
    b = b.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(int(s, 16)).revocation_date(now).build())
open(sys.argv[4], "wb").write(b.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER))
PY
unset PASS
TA=$(aws rolesanywhere list-trust-anchors --region eu-north-1 --query "trustAnchors[?name=='accessproof-certifier-host-ca'].trustAnchorArn | [0]" --output text)
CRL_ID=$(aws rolesanywhere list-crls --region eu-north-1 --query "crls[?name=='accessproof-certifier-host-crl'].crlId | [0]" --output text)
if [ "$CRL_ID" = "None" ] || [ -z "$CRL_ID" ]; then
  aws rolesanywhere import-crl --region eu-north-1 --name accessproof-certifier-host-crl --trust-anchor-arn "$TA" --crl-data "fileb://$CRL" --enabled >/dev/null
else
  aws rolesanywhere update-crl --region eu-north-1 --crl-id "$CRL_ID" --crl-data "fileb://$CRL" >/dev/null
fi
echo "revoked serial $SERIAL (CRL imported). Re-issue a replacement certificate before restarting the affected service."
