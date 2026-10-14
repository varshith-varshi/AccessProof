#!/usr/bin/env bash
set -euo pipefail

# Produces a self-contained Ubuntu/Debian package. The resulting package bundles
# the runner virtual environment; end users do not clone this repository or run pip.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${ACCESSPROOF_RUNNER_VERSION:-0.9.0}"
ARCH="${ACCESSPROOF_RUNNER_ARCH:-amd64}"
STAGE="$(mktemp -d)"
OUT="$ROOT/dist"
trap 'rm -rf "$STAGE"' EXIT

command -v dpkg-deb >/dev/null || { echo "dpkg-deb is required" >&2; exit 1; }
mkdir -p "$OUT" "$STAGE/DEBIAN" "$STAGE/opt/accessproof-runner" "$STAGE/etc/accessproof" "$STAGE/var/lib/accessproof-runner" "$STAGE/var/log/accessproof-runner" "$STAGE/usr/share/applications" "$STAGE/lib/systemd/system"
python3 -m venv "$STAGE/opt/accessproof-runner/venv"
"$STAGE/opt/accessproof-runner/venv/bin/pip" install --no-cache-dir "$ROOT"
# Console-script shebangs point at the temporary staging virtualenv. Rewrite the
# runner entry point to its final installed location before creating the package.
sed -i "s|$STAGE/opt/accessproof-runner/venv|/opt/accessproof-runner/venv|g" \
  "$STAGE/opt/accessproof-runner/venv/bin/accessproof-runner"
install -m 0644 "$ROOT/packaging/linux/accessproof-runner.service" "$STAGE/lib/systemd/system/accessproof-runner.service"
install -m 0644 "$ROOT/packaging/linux/accessproof-runner.desktop" "$STAGE/usr/share/applications/accessproof-runner.desktop"

cat >"$STAGE/DEBIAN/control" <<EOF
Package: accessproof-runner
Version: $VERSION
Section: admin
Priority: optional
Architecture: $ARCH
Maintainer: NeuralMatrix <security@neuralmatrix.example>
Depends: python3 (>= 3.11), python3-tk
Description: AccessProof private runner
 Outbound-only authorization regression runner for enterprise AI systems.
EOF
cat >"$STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if ! getent group accessproof >/dev/null; then groupadd --system accessproof; fi
if ! getent passwd accessproof >/dev/null; then useradd --system --gid accessproof --home-dir /var/lib/accessproof-runner --shell /usr/sbin/nologin accessproof; fi
chown -R accessproof:accessproof /var/lib/accessproof-runner /var/log/accessproof-runner
chmod 700 /var/lib/accessproof-runner
chmod 750 /var/log/accessproof-runner
systemctl daemon-reload || true
EOF
chmod 0755 "$STAGE/DEBIAN/postinst"
dpkg-deb --root-owner-group --build "$STAGE" "$OUT/accessproof-runner_${VERSION}_${ARCH}.deb"
echo "Created $OUT/accessproof-runner_${VERSION}_${ARCH}.deb"
