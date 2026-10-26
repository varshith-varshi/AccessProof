#!/usr/bin/env bash
set -euo pipefail

# Build a source-free-from-git, customer-deployable Guard bundle. It contains
# only the Guard runtime and its shared libraries, never local .env files.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${ACCESSPROOF_GUARD_VERSION:-0.1.0}"
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]]; then
  echo "Invalid Guard release version; expected semantic version such as 0.1.2" >&2
  exit 1
fi
STAGE="$(mktemp -d)"
OUT="$ROOT/dist"
trap 'rm -rf "$STAGE"' EXIT

mkdir -p "$STAGE/accessproof-guard-$VERSION/apps" "$STAGE/accessproof-guard-$VERSION/packages" "$OUT"
cp "$ROOT/pyproject.toml" "$STAGE/accessproof-guard-$VERSION/"
cp -R "$ROOT/apps/guard" "$STAGE/accessproof-guard-$VERSION/apps/"
# Ship only the Guard's public RAG SDK, never unrelated server-side business
# logic, reporting, authorization backend, or development utilities.
mkdir -p "$STAGE/accessproof-guard-$VERSION/packages"
cp "$ROOT/packages/__init__.py" "$STAGE/accessproof-guard-$VERSION/packages/"
cp -R "$ROOT/packages/rag_sdk" "$STAGE/accessproof-guard-$VERSION/packages/"
find "$STAGE/accessproof-guard-$VERSION" -type d -name __pycache__ -prune -exec rm -rf {} +
find "$STAGE/accessproof-guard-$VERSION" -type f \( -name '*.pyc' -o -name '*.db' \) -delete
cp "$ROOT/packaging/guard/compose.yml" "$STAGE/accessproof-guard-$VERSION/compose.yml"
# Stamp an immutable version into this particular release: a customer may
# upgrade while retaining an older .env, so .env cannot define bundle identity.
RELEASE_COMPOSE="$STAGE/accessproof-guard-$VERSION/compose.yml"
grep -q "^      ACCESSPROOF_GUARD_CREDENTIAL_FILE:" "$RELEASE_COMPOSE"
sed -i "/^      ACCESSPROOF_GUARD_CREDENTIAL_FILE:/a\\      ACCESSPROOF_GUARD_VERSION: $VERSION" "$RELEASE_COMPOSE"
cp "$ROOT/packaging/guard/.env.example" "$STAGE/accessproof-guard-$VERSION/.env.example"
cp "$ROOT/packaging/guard/start.sh" "$STAGE/accessproof-guard-$VERSION/start.sh"
cp "$ROOT/packaging/guard/start.command" "$STAGE/accessproof-guard-$VERSION/start.command"
cp "$ROOT/packaging/guard/start.ps1" "$STAGE/accessproof-guard-$VERSION/start.ps1"
chmod 0755 "$STAGE/accessproof-guard-$VERSION/start.sh" "$STAGE/accessproof-guard-$VERSION/start.command"
cat >"$STAGE/accessproof-guard-$VERSION/README.md" <<'EOF'
# AccessProof Guard

1. Install Docker Desktop (Windows/macOS) or Docker Engine with Compose (Linux).
2. Double-click `start.command` on macOS, run `start.ps1` on Windows, or
   double-click/run `start.sh` on Linux.
3. Your browser opens the private setup page at `http://127.0.0.1:8080/setup`.
4. Create a Guard in AccessProof, paste its one-time token, enter the trusted
   OIDC issuer and audience used by your RAG, and select **Connect Guard**.

The setup page is bound to loopback and never receives remote scripts. The
one-time token is exchanged for a private machine credential in `./state`; the
credential is never returned to the browser or printed. The Guard sends only
decision metadata to the AccessProof control plane.

Advanced and automated deployments may still use the `accessproof-guard` CLI.
EOF
tar -C "$STAGE" -czf "$OUT/accessproof-guard-${VERSION}.tar.gz" "accessproof-guard-$VERSION"
(cd "$OUT" && sha256sum "accessproof-guard-${VERSION}.tar.gz" > "accessproof-guard-${VERSION}.tar.gz.sha256")
# Stage immutable-by-release-name download assets into the API Docker build
# context. The API authenticates organization admins before serving them.
mkdir -p "$ROOT/packaging/guard/releases"
cp "$OUT/accessproof-guard-${VERSION}.tar.gz" "$ROOT/packaging/guard/releases/"
cp "$OUT/accessproof-guard-${VERSION}.tar.gz.sha256" "$ROOT/packaging/guard/releases/"
echo "Created $OUT/accessproof-guard-${VERSION}.tar.gz"
