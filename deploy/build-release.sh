#!/usr/bin/env bash
# UFW OkBoy - Release Package Builder
# Creates a self-contained tar.gz with everything needed for offline installation
#
# Usage:
#   bash build-release.sh <version> [output_dir]
#   bash build-release.sh v2.0.0

set -euo pipefail

VERSION="${1:-}"
OUTPUT_DIR="${2:-dist}"

if [[ -z "$VERSION" ]]; then
    echo "Usage: bash build-release.sh <version> [output_dir]"
    echo "Example: bash build-release.sh v2.0.0"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PKG_NAME="ufw-okboy-${VERSION}"
PKG_DIR="$OUTPUT_DIR/$PKG_NAME"

echo "=== Building UFW OkBoy Release Package: $VERSION ==="

# Clean and create package directory
rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR"

# Copy application files
echo "[1/4] Copying server files..."
mkdir -p "$PKG_DIR/server/static" "$PKG_DIR/server/tests"
cp "$REPO_DIR/server/app.py" "$PKG_DIR/server/"
cp "$REPO_DIR/server/ufw_ops.py" "$PKG_DIR/server/"
cp "$REPO_DIR/server/db.py" "$PKG_DIR/server/"
cp "$REPO_DIR/server/auth.py" "$PKG_DIR/server/"
cp "$REPO_DIR/server/requirements.txt" "$PKG_DIR/server/"
cp "$REPO_DIR/server/config.example.yaml" "$PKG_DIR/server/"
cp "$REPO_DIR/server/static/index.html" "$PKG_DIR/server/static/" 2>/dev/null || true
cp "$REPO_DIR/server/tests/"*.py "$PKG_DIR/server/tests/" 2>/dev/null || true
cp "$REPO_DIR/server/tests/__init__.py" "$PKG_DIR/server/tests/" 2>/dev/null || true

# Copy client files
echo "[2/4] Copying client files..."
mkdir -p "$PKG_DIR/client"
cp "$REPO_DIR/client/knock.py" "$PKG_DIR/client/"
cp "$REPO_DIR/client/knock.sh" "$PKG_DIR/client/"
cp "$REPO_DIR/client/config.example.yaml" "$PKG_DIR/client/"

# Copy deploy files
echo "[3/4] Copying deploy files..."
mkdir -p "$PKG_DIR/deploy" "$PKG_DIR/nginx"
cp "$REPO_DIR/deploy/deploy.sh" "$PKG_DIR/deploy/"
cp "$REPO_DIR/deploy/quick-install.sh" "$PKG_DIR/deploy/"
cp "$REPO_DIR/deploy/install-client.sh" "$PKG_DIR/deploy/"
cp "$REPO_DIR/deploy/ufw-okboy.service" "$PKG_DIR/deploy/" 2>/dev/null || true
cp "$REPO_DIR/deploy/ufw-okboy-cleanup.service" "$PKG_DIR/deploy/" 2>/dev/null || true
cp "$REPO_DIR/deploy/ufw-okboy-cleanup.timer" "$PKG_DIR/deploy/" 2>/dev/null || true
cp "$REPO_DIR/deploy/knock.service" "$PKG_DIR/deploy/" 2>/dev/null || true
cp "$REPO_DIR/deploy/knock.timer" "$PKG_DIR/deploy/" 2>/dev/null || true
cp "$REPO_DIR/deploy/install-server.sh" "$PKG_DIR/deploy/" 2>/dev/null || true
cp "$REPO_DIR/nginx/ufw-okboy.conf" "$PKG_DIR/nginx/" 2>/dev/null || true

# Copy docs
echo "[4/4] Copying documentation..."
cp "$REPO_DIR/README.md" "$PKG_DIR/" 2>/dev/null || true
cp "$REPO_DIR/README.en.md" "$PKG_DIR/" 2>/dev/null || true
cp "$REPO_DIR/GUIDE.md" "$PKG_DIR/" 2>/dev/null || true
cp "$REPO_DIR/CLAUDE.md" "$PKG_DIR/" 2>/dev/null || true

# Create a simple install.sh wrapper in the package root
cat > "$PKG_DIR/install.sh" << 'INSTALLEOF'
#!/usr/bin/env bash
# UFW OkBoy - Package Installer
# Run as root: bash install.sh [deploy.sh flags...]
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$SCRIPT_DIR/deploy/deploy.sh" "$@"
INSTALLEOF
chmod +x "$PKG_DIR/install.sh"

# Create tarball
cd "$OUTPUT_DIR"
tar czf "${PKG_NAME}.tar.gz" "$PKG_NAME"
rm -rf "$PKG_NAME"

# Show checksum
CHECKSUM=$(sha256sum "${PKG_NAME}.tar.gz" | awk '{print $1}')
SIZE=$(du -h "${PKG_NAME}.tar.gz" | awk '{print $1}')

echo ""
echo "=== Release Package Built ==="
echo "  File:     $OUTPUT_DIR/${PKG_NAME}.tar.gz"
echo "  Size:     $SIZE"
echo "  SHA256:   $CHECKSUM"
echo ""
echo "  Install from package:"
echo "    tar xzf ${PKG_NAME}.tar.gz"
echo "    cd ${PKG_NAME}"
echo "    bash install.sh --self-signed -y"
echo ""
echo "  Or one-line install:"
echo "    curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/quick-install.sh | bash"
