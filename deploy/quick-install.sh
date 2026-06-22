#!/usr/bin/env bash
# UFW OkBoy - One-Line Installer (curl | bash)
# Downloads the latest release and runs deploy.sh
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/quick-install.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/quick-install.sh | bash -s -- --domain my.server.com
#   curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/quick-install.sh | bash -s -- --self-signed -y

set -euo pipefail

REPO_URL="https://github.com/lvusyy/UFW-OkBoy"
RAW_URL="https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master"
TMP_DIR=$(mktemp -d)

cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

echo "=== UFW OkBoy Quick Installer ==="
echo ""

# Download the full repository (shallow clone)
if command -v git &>/dev/null; then
    echo "[INFO] Downloading via git clone..."
    git clone --depth 1 "$REPO_URL" "$TMP_DIR/ufw-okboy" 2>/dev/null
    REPO_DIR="$TMP_DIR/ufw-okboy"
elif command -v curl &>/dev/null; then
    echo "[INFO] Downloading via tarball..."
    curl -fsSL "$REPO_URL/archive/refs/heads/master.tar.gz" -o "$TMP_DIR/repo.tar.gz"
    tar xzf "$TMP_DIR/repo.tar.gz" -C "$TMP_DIR"
    REPO_DIR="$TMP_DIR/UFW-OkBoy-master"
else
    echo "[ERROR] Need git or curl to download."
    exit 1
fi

if [[ ! -d "$REPO_DIR" ]]; then
    echo "[ERROR] Download failed."
    exit 1
fi

cd "$REPO_DIR"

# Run the deployment script with all forwarded args
exec bash deploy/deploy.sh "$@"
