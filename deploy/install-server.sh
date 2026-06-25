#!/usr/bin/env bash
# UFW OkBoy - Server Installation Script (lightweight standalone entry)
#
# For full deployment (SSL/nginx/systemd) use deploy/deploy.sh instead.
# This script installs the app + Python deps + systemd services only.
#
# Run as root on the server:
#   bash install-server.sh

set -euo pipefail

APP_DIR="/opt/ufw-okboy"
DATA_DIR="/var/lib/ufw-okboy"
LOG_DIR="/var/log/ufw-okboy"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VENDOR_DIR="$REPO_DIR/vendor"   # bundled wheels (offline install) if present
PIP_MIRROR=""                   # --mirror <url>; else auto CN fallback if PyPI down
OFFLINE=false                   # --offline forces bundled-wheels-only install

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mirror)  PIP_MIRROR="$2"; shift 2 ;;
        --offline) OFFLINE=true; shift ;;
        --app-dir) APP_DIR="$2"; shift 2 ;;
        -h|--help) head -8 "$0"; exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# pip install with offline-vendor / mirror fallback (survives slow/blocked PyPI).
pip_install() {
    local pip="$APP_DIR/venv/bin/pip"
    if [[ -d "$VENDOR_DIR" ]]; then
        echo "[INFO] Installing Python deps OFFLINE from $VENDOR_DIR"
        if "$pip" install --no-index --find-links "$VENDOR_DIR" "$@"; then return 0; fi
        [[ "$OFFLINE" == true ]] && { echo "[ERROR] Offline install failed and --offline forbids network."; return 1; }
        echo "[WARN] Offline install incomplete; falling back to an online index."
    elif [[ "$OFFLINE" == true ]]; then
        echo "[ERROR] --offline set but no bundled wheels at $VENDOR_DIR."; return 1
    fi
    local index="$PIP_MIRROR"
    if [[ -z "$index" ]]; then
        if ! curl -fsS --max-time 4 -o /dev/null https://pypi.org/simple/ 2>/dev/null; then
            index="https://pypi.tuna.tsinghua.edu.cn/simple"
            echo "[WARN] pypi.org unreachable — using mirror: $index"
        fi
    fi
    if [[ -n "$index" ]]; then
        local host; host="$(echo "$index" | awk -F/ '{print $3}')"
        "$pip" install -i "$index" --trusted-host "$host" "$@"
    else
        "$pip" install "$@"
    fi
}

echo "=== UFW OkBoy Server Installation ==="

# Check prerequisites
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root."
    exit 1
fi

command -v ufw     >/dev/null 2>&1 || { echo "Error: ufw is not installed."; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "Error: python3 is not installed."; exit 1; }

# Detect distribution (RHEL-family needs EPEL for ufw)
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    DISTRO_ID="$ID"
else
    echo "Error: Cannot detect distribution (/etc/os-release missing)."
    exit 1
fi
echo "[INFO] Detected distribution: $DISTRO_ID"

# Ensure ufw is available (RHEL-family: ufw lives in EPEL)
case "$DISTRO_ID" in
    ubuntu|debian|linuxmint|raspbian)
        : # ufw is in the default repos
        ;;
    centos|rhel|rocky|almalinux|amzn)
        if ! rpm -q ufw >/dev/null 2>&1 && ! command -v ufw >/dev/null 2>&1; then
            echo "[INFO] Installing EPEL (provides ufw on RHEL-family)..."
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y epel-release
            else
                yum install -y epel-release
            fi
            # ufw check at top already failed if still missing; re-check below
            command -v ufw >/dev/null 2>&1 || dnf install -y ufw 2>/dev/null || yum install -y ufw
        fi
        ;;
    fedora)
        : # ufw in default repos
        ;;
    *)
        echo "Warning: Unsupported distribution '$DISTRO_ID'. Proceeding anyway."
        ;;
esac

# Create directories
echo "[1/5] Creating directories..."
mkdir -p "$APP_DIR/server" "$DATA_DIR" "$LOG_DIR"

# Copy application files (ALL server modules — v2.0 split db.py/auth.py MUST be included)
echo "[2/5] Copying application files..."
cp "$REPO_DIR/server/app.py" \
   "$REPO_DIR/server/ufw_ops.py" \
   "$REPO_DIR/server/db.py" \
   "$REPO_DIR/server/auth.py" \
   "$REPO_DIR/server/requirements.txt" \
   "$REPO_DIR/server/config.example.yaml" \
   "$APP_DIR/server/" 2>/dev/null || true
# Copy static + tests
[[ -d "$REPO_DIR/server/static" ]] && cp -r "$REPO_DIR/server/static" "$APP_DIR/server/"
[[ -d "$REPO_DIR/server/tests" ]]  && { mkdir -p "$APP_DIR/server/tests"; cp -r "$REPO_DIR/server/tests/"* "$APP_DIR/server/tests/" 2>/dev/null || true; }
# Copy VERSION so the installed app can report its version (for upgrade checks)
[[ -f "$REPO_DIR/VERSION" ]] && cp "$REPO_DIR/VERSION" "$APP_DIR/"

# Create virtual environment and install dependencies
echo "[3/5] Setting up Python virtual environment..."
python3 -m venv "$APP_DIR/venv"
pip_install --upgrade pip || echo "[WARN] pip self-upgrade skipped (non-fatal)."
pip_install -r "$APP_DIR/server/requirements.txt"

# Config file
echo "[4/5] Setting up configuration..."
if [[ ! -f "$APP_DIR/server/config.yaml" ]]; then
    cp "$APP_DIR/server/config.example.yaml" "$APP_DIR/server/config.yaml" 2>/dev/null || true
    echo "  -> config.yaml created at $APP_DIR/server/config.yaml"
    echo "  -> IMPORTANT: Edit it and set real user secrets!"
    echo "  -> Generate secrets with: $APP_DIR/venv/bin/python $APP_DIR/server/app.py gen-secret <username>"
else
    echo "  -> config.yaml already exists, skipping."
fi

# Install systemd services
echo "[5/5] Installing systemd services..."
cp "$REPO_DIR/deploy/ufw-okboy.service" /etc/systemd/system/ 2>/dev/null || true
cp "$REPO_DIR/deploy/ufw-okboy-cleanup.service" /etc/systemd/system/ 2>/dev/null || true
cp "$REPO_DIR/deploy/ufw-okboy-cleanup.timer" /etc/systemd/system/ 2>/dev/null || true
systemctl daemon-reload

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Next steps:"
echo "  1. Edit config:    nano $APP_DIR/server/config.yaml"
echo "  2. Generate secrets: $APP_DIR/venv/bin/python $APP_DIR/server/app.py gen-secret alice"
echo "  3. Create admin:     $APP_DIR/venv/bin/python $APP_DIR/server/app.py -c $APP_DIR/server/config.yaml user-add <admin> --admin"
echo "  4. Configure Nginx:  cp nginx/ufw-okboy.conf /etc/nginx/sites-available/  (or use deploy.sh for full SSL setup)"
echo "  5. Start server:     systemctl enable --now ufw-okboy"
echo "  6. Enable cleanup:   systemctl enable --now ufw-okboy-cleanup.timer"
echo "  7. Check status:     systemctl status ufw-okboy"
echo "  8. Version:          $APP_DIR/venv/bin/python $APP_DIR/server/app.py --version"
