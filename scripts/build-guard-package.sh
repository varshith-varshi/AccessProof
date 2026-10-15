#!/usr/bin/env bash
set -euo pipefail

# Build a source-free-from-git, customer-deployable Guard bundle. It contains
# only the Guard runtime and its shared libraries, never local .env files.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${ACCESSPROOF_GUARD_VERSION:-0.1.0}"
STAGE="$(mktemp -d)"
OUT="$ROOT/dist"
trap 'rm -rf "$STAGE"' EXIT

mkdir -p "$STAGE/accessproof-guard-$VERSION/apps" "$STAGE/accessproof-guard-$VERSION/packages" "$OUT"
cp "$ROOT/pyproject.toml" "$STAGE/accessproof-guard-$VERSION/"
cp -R "$ROOT/apps/guard" "$STAGE/accessproof-guard-$VERSION/apps/"
cp -R "$ROOT/packages" "$STAGE/accessproof-guard-$VERSION/"
find "$STAGE/accessproof-guard-$VERSION" -type d -name __pycache__ -prune -exec rm -rf {} +
find "$STAGE/accessproof-guard-$VERSION" -type f \( -name '*.pyc' -o -name '*.db' \) -delete
cp "$ROOT/packaging/guard/compose.yml" "$STAGE/accessproof-guard-$VERSION/compose.yml"
cp "$ROOT/packaging/guard/.env.example" "$STAGE/accessproof-guard-$VERSION/.env.example"
cat >"$STAGE/accessproof-guard-$VERSION/README.md" <<'EOF'
# AccessProof Guard

1. Copy `.env.example` to `.env` and set trusted JWT verification values.
2. Start the image build with `docker compose -f compose.yml build`.
3. Use a one-time enrollment token from AccessProof:
   `docker compose -f compose.yml run --rm guard accessproof-guard enroll --server https://api.example.com`
4. Start the Guard: `docker compose -f compose.yml up -d`.

The enrollment command saves a private machine credential in `./state` and
does not print it. The Guard only sends decision metadata to the control plane.
EOF
tar -C "$STAGE" -czf "$OUT/accessproof-guard-${VERSION}.tar.gz" "accessproof-guard-$VERSION"
(cd "$OUT" && sha256sum "accessproof-guard-${VERSION}.tar.gz" > "accessproof-guard-${VERSION}.tar.gz.sha256")
echo "Created $OUT/accessproof-guard-${VERSION}.tar.gz"
