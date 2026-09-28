#!/usr/bin/env bash
# UFW OkBoy - Release Package Builder
# Creates a self-contained tar.gz: the server, the clients, the deploy scripts,
# the docs, and Python wheels for an OFFLINE install. The release workflow
# builds the published packages with this same script.
#
# Usage:
#   bash deploy/build-release.sh [version] [output_dir]
#   bash deploy/build-release.sh              # version from VERSION, output in dist/
#   bash deploy/build-release.sh v2.4.1 out
#
# REQUIRE_WHEELS=1 turns a missing wheel set into an error (the release
# workflow sets it, so a published package always installs offline).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
if [[ -n "${1:-}" ]]; then
    VERSION="$1"
elif [[ -f "$REPO_DIR/VERSION" ]]; then
    VERSION="v$(tr -d '[:space:]' < "$REPO_DIR/VERSION")"
else
    echo "Usage: bash build-release.sh <version> [output_dir]"
    exit 1
fi
OUTPUT_DIR="${2:-dist}"
PKG_NAME="ufw-okboy-${VERSION}"
PKG_DIR="$OUTPUT_DIR/$PKG_NAME"

# Target interpreters and platforms for the bundled wheels. The server needs
# Python 3.10+; pure-Python wheels are shared, compiled ones (PyYAML,
# MarkupSafe) are per interpreter and CPU.
PY_VERSIONS="3.10 3.11 3.12 3.13 3.14"
ARCHES="x86_64 aarch64"

echo "=== Building UFW OkBoy Release Package: $VERSION ==="
rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR"

# Copy repo files into the package at the same relative path. Every file named
# must exist: a missing one fails the build instead of shipping without it.
put() {
    local f
    for f in "$@"; do
        mkdir -p "$PKG_DIR/$(dirname "$f")"
        cp -p "$REPO_DIR/$f" "$PKG_DIR/$f"
    done
}

echo "[1/3] Copying files..."
put server/app.py server/ufw_ops.py server/db.py server/auth.py \
    server/requirements.txt server/config.example.yaml server/static/index.html
for f in "$REPO_DIR"/server/tests/*.py; do put "server/tests/${f##*/}"; done
put client/knock.py client/knock.sh client/knock.ps1 client/config.example.yaml
put deploy/deploy.sh deploy/quick-install.sh deploy/upgrade.sh deploy/install-server.sh \
    deploy/install-client.sh deploy/install-client.ps1 \
    deploy/ufw-okboy.service deploy/ufw-okboy-cleanup.service deploy/ufw-okboy-cleanup.timer \
    deploy/knock.service deploy/knock.timer
put nginx/ufw-okboy.conf
put README.md README.en.md GUIDE.md CHANGELOG.md SECURITY.md LICENSE docs/web-client.png
# VERSION sits next to the app so --version and /health report it.
put VERSION

# Wheels for OFFLINE install — the reliable path where PyPI is slow or blocked.
# --platform/--only-binary pin the target, so this works from any build host;
# deploy.sh/upgrade.sh install from vendor/ first and fall back to an index.
echo "[2/3] Vendoring Python wheels..."
PIPBIN="$(command -v pip3 || command -v pip || true)"
missing=()
if [[ -n "$PIPBIN" ]]; then
    mkdir -p "$PKG_DIR/vendor"
    for arch in $ARCHES; do
        for pyver in $PY_VERSIONS; do
            "$PIPBIN" download -r "$REPO_DIR/server/requirements.txt" -d "$PKG_DIR/vendor" \
                --only-binary=:all: --implementation cp --python-version "$pyver" \
                --platform "manylinux2014_$arch" --platform "manylinux_2_28_$arch" \
                --quiet >/dev/null 2>&1 || missing+=("cp$pyver-$arch")
        done
    done
else
    missing=("all (pip not found)")
fi
WHEEL_COUNT=0
if [[ -d "$PKG_DIR/vendor" ]]; then
    WHEEL_COUNT="$(find "$PKG_DIR/vendor" -name '*.whl' | wc -l | tr -d ' ')"
    [[ "$WHEEL_COUNT" -gt 0 ]] || rm -rf "$PKG_DIR/vendor"
fi
if [[ ${#missing[@]} -gt 0 ]]; then
    msg="no complete wheel set for: ${missing[*]} (installs there need a package index)"
    if [[ "${REQUIRE_WHEELS:-0}" == 1 ]]; then
        echo "[ERROR] $msg" >&2
        exit 1
    fi
    echo "    [WARN] $msg"
fi
echo "    $WHEEL_COUNT wheel(s) in vendor/"

# Installer entry point at the package root.
cat > "$PKG_DIR/install.sh" << 'INSTALLEOF'
#!/usr/bin/env bash
# UFW OkBoy - Package Installer
# Run as root: bash install.sh [deploy.sh flags...]
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$SCRIPT_DIR/deploy/deploy.sh" "$@"
INSTALLEOF
chmod +x "$PKG_DIR/install.sh"

echo "[3/3] Creating the archive..."
cd "$OUTPUT_DIR"
tar czf "${PKG_NAME}.tar.gz" "$PKG_NAME"
rm -rf "$PKG_NAME"
{ sha256sum "${PKG_NAME}.tar.gz" 2>/dev/null || shasum -a 256 "${PKG_NAME}.tar.gz"; } > "${PKG_NAME}.tar.gz.sha256"

echo ""
echo "=== Release Package Built ==="
echo "  File:     $OUTPUT_DIR/${PKG_NAME}.tar.gz"
echo "  Size:     $(du -h "${PKG_NAME}.tar.gz" | awk '{print $1}')"
echo "  SHA256:   $(awk '{print $1}' "${PKG_NAME}.tar.gz.sha256")"
echo ""
echo "  Install (as root; uses the bundled wheels, no PyPI needed):"
echo "    tar xzf ${PKG_NAME}.tar.gz && cd ${PKG_NAME}"
echo "    bash install.sh --self-signed -y"
echo ""
echo "  Upgrade an existing install from the unpacked package:"
echo "    bash deploy/upgrade.sh --repo-dir . -y"
