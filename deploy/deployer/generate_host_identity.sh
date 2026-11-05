#!/usr/bin/env bash
# Generate an independent Roles Anywhere deployer certificate. Never commit secrets.
# Unlike the certifier, this role has its own CA and leaf key. The CA signing
# private key is ephemeral and destroyed after certificate issuance.
set -Eeuo pipefail
umask 077
DIR="$HOME/.ap-id/rolesanywhere/production-deployer"
[[ ! -e "$DIR/host.key" && ! -e "$DIR/ca.pem" ]] || { echo 'Deployer identity already exists; do not overwrite it.' >&2; exit 2; }
install -d -m 700 "$DIR"
TEMP=$(mktemp -d "$DIR/.ca-signing.XXXXXXXX")
trap 'shred -u "$TEMP/ca.key" 2>/dev/null || true; rm -rf "$TEMP"' EXIT
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$TEMP/ca.key" >/dev/null 2>&1
openssl req -new -x509 -sha256 -days 365 -key "$TEMP/ca.key" \
  -subj '/C=IN/O=NeuralMatrix AccessProof/OU=Deployment/CN=AccessProof Production Deployer CA' \
  -addext 'basicConstraints=critical,CA:true,pathlen:0' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -out "$DIR/ca.pem" >/dev/null 2>&1
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$DIR/host.key" >/dev/null 2>&1
openssl req -new -key "$DIR/host.key" -out "$TEMP/host.csr" \
  -subj '/C=IN/O=NeuralMatrix AccessProof/OU=production-deployer/CN=accessproof-production-deployer-host' >/dev/null 2>&1
cat > "$TEMP/leaf.ext" <<'EXT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EXT
openssl x509 -req -sha256 -days 90 -in "$TEMP/host.csr" \
  -CA "$DIR/ca.pem" -CAkey "$TEMP/ca.key" -CAcreateserial -out "$DIR/host.pem" \
  -extfile "$TEMP/leaf.ext" >/dev/null 2>&1
chmod 600 "$DIR/host.key"; chmod 644 "$DIR/host.pem" "$DIR/ca.pem"
openssl verify -CAfile "$DIR/ca.pem" "$DIR/host.pem"
openssl x509 -in "$DIR/host.pem" -noout -enddate -subject
printf 'Identity ready at %s. Ephemeral CA signer will be destroyed.\n' "$DIR"
