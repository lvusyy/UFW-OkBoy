#!/usr/bin/env bash
# UFW OkBoy - Server Installation Script (lightweight standalone entry)
#
# For full deployment (SSL/nginx/systemd) use deploy/deploy.sh instead.
# This script installs the app + Python deps + systemd services only.
#
# Run as root on the server, from a checkout or an unpacked release package:
#   bash deploy/install-server.sh [--mirror <pypi-index>] [--offline] [--app-dir <dir>]
#
#   --mirror <url>   PyPI index to use (default: pypi.org, a CN mirror if unreachable)
#   --offline        Install Python deps only from the bundled vendor/ wheels
#   --app-dir <dir>  Install directory (default: /opt/ufw-okboy)

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
        -h|--help) awk 'NR > 1 && !/^#/ {exit} NR > 1 {sub(/^# ?/, ""); print}' "$0"; exit 0 ;;
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
        # --trusted-host also switches certificate checks off for an https
        # index (a man in the middle could then serve packages that run as
        # root): pass it only for a plain-http index chosen with --mirror.
        local trust=()
        [[ "$index" == http://* ]] && trust=(--trusted-host "$(echo "$index" | awk -F/ '{print $3}')")
        "$pip" install -i "$index" ${trust[@]+"${trust[@]}"} "$@"
    else
        "$pip" install "$@"
    fi
}

echo "=== UFW OkBoy Server Installation ==="

# The unit files get --app-dir verbatim: keep it to a plain absolute path.
[[ "$APP_DIR" =~ ^/[A-Za-z0-9._/-]+$ ]] || { echo "Error: --app-dir must be an absolute path of letters, digits, '.', '_', '-' and '/'."; exit 1; }

# Check prerequisites
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root."
    exit 1
fi

# The server needs Python 3.10+ able to create a venv with pip: the distro's
# python3 when it qualifies, else a newer one installed next to it
# (python3.11/3.12 on RHEL-family 8/9; Debian/Ubuntu also need python3.X-venv).
PYTHON=""
for c in python3 python3.14 python3.13 python3.12 python3.11 python3.10; do
    command -v "$c" >/dev/null 2>&1 || continue
    if "$c" -c 'import sys, ensurepip; sys.exit(sys.version_info < (3, 10))' 2>/dev/null; then
        PYTHON="$(command -v "$c")"
        break
    fi
done
[[ -n "$PYTHON" ]] || {
    echo "Error: Python 3.10 or newer with venv support is required (found: $(python3 --version 2>&1 || echo none))."
    echo "       Install it first (Debian/Ubuntu: python3-venv; RHEL-family 8/9: dnf install python3.12 python3.12-pip)."
    exit 1
}
echo "[INFO] Using $("$PYTHON" --version 2>&1) ($PYTHON)"

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
            # RHEL itself has no epel-release package in its repositories.
            EPEL_PKG="epel-release"
            [[ "$DISTRO_ID" == "rhel" ]] && EPEL_PKG="https://dl.fedoraproject.org/pub/epel/epel-release-latest-${VERSION_ID%%.*}.noarch.rpm"
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y "$EPEL_PKG"
            else
                yum install -y "$EPEL_PKG"
            fi
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
command -v ufw >/dev/null 2>&1 || { echo "Error: ufw is not installed (install it first, e.g. apt install ufw)."; exit 1; }

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
# A venv made by an older interpreter keeps it: `python -m venv` does not
# replace an existing bin/python. Rebuild it then (the dependencies follow).
VENV_ARGS=()
if [[ -e "$APP_DIR/venv/bin/python" || -L "$APP_DIR/venv/bin/python" ]] \
        && ! "$APP_DIR/venv/bin/python" -c 'import sys; sys.exit(sys.version_info < (3, 10))' 2>/dev/null; then
    echo "[WARN] Rebuilding $APP_DIR/venv: its interpreter is older than 3.10 or no longer runs."
    VENV_ARGS=(--clear)
fi
"$PYTHON" -m venv ${VENV_ARGS[@]+"${VENV_ARGS[@]}"} "$APP_DIR/venv"
pip_install --upgrade pip || echo "[WARN] pip self-upgrade skipped (non-fatal)."
pip_install -r "$APP_DIR/server/requirements.txt"

# Config file
echo "[4/5] Setting up configuration..."
if [[ ! -f "$APP_DIR/server/config.yaml" ]]; then
    cp "$APP_DIR/server/config.example.yaml" "$APP_DIR/server/config.yaml" 2>/dev/null || true
    echo "  -> config.yaml created at $APP_DIR/server/config.yaml (the defaults work as they are)"
else
    echo "  -> config.yaml already exists, skipping."
fi

# Install systemd services
echo "[5/5] Installing systemd services..."
# The templates name the default /opt/ufw-okboy: point them at --app-dir.
# (--app-dir is checked above to be a plain absolute path, safe in sed and units.)
for unit in ufw-okboy.service ufw-okboy-cleanup.service ufw-okboy-cleanup.timer; do
    sed "s#/opt/ufw-okboy#$APP_DIR#g" "$REPO_DIR/deploy/$unit" > "/etc/systemd/system/$unit.tmp"
    mv "/etc/systemd/system/$unit.tmp" "/etc/systemd/system/$unit"
done
systemctl daemon-reload

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Next steps:"
echo "  1. Review config:  nano $APP_DIR/server/config.yaml"
echo "  2. Create admin:     $APP_DIR/venv/bin/python $APP_DIR/server/app.py -c $APP_DIR/server/config.yaml user-add <admin> --admin"
echo "  3. Configure Nginx:  cp nginx/ufw-okboy.conf /etc/nginx/sites-available/  (or use deploy.sh for full SSL setup)"
echo "  4. Start server:     systemctl enable --now ufw-okboy"
echo "  5. Enable cleanup:   systemctl enable --now ufw-okboy-cleanup.timer"
echo "  6. Check status:     systemctl status ufw-okboy"
echo "  7. Version:          $APP_DIR/venv/bin/python $APP_DIR/server/app.py --version"
