#!/usr/bin/env bash
# UFW OkBoy - Client Quick Install Script
# Sets up knock.py + systemd timer for auto-knocking
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/install-client.sh | bash -s -- --server https://your-server --user alice --secret YOUR_SECRET
#
# Flags:
#   --server <url>     Server URL (e.g., https://your-server.com or https://1.2.3.4:443)
#   --user <username>  Your username
#   --secret <secret>  Your HMAC secret
#   --interval <sec>   Knock interval (default: 30)
#   --no-verify-ssl    Skip SSL verification (for self-signed certs)
#   --yes              Non-interactive

set -euo pipefail

SERVER_URL=""
USERNAME=""
SECRET=""
INTERVAL=30
NO_VERIFY_SSL=false
NON_INTERACTIVE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server)      SERVER_URL="$2"; shift 2 ;;
        --user)        USERNAME="$2"; shift 2 ;;
        --secret)      SECRET="$2"; shift 2 ;;
        --interval)    INTERVAL="$2"; shift 2 ;;
        --no-verify-ssl) NO_VERIFY_SSL=true; shift ;;
        --yes)         NON_INTERACTIVE=true; shift ;;
        -h|--help)     head -15 "$0"; exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Interactive prompts for missing required fields
if [[ "$NON_INTERACTIVE" == false ]]; then
    [[ -z "$SERVER_URL" ]] && read -rp "Server URL (https://...): " SERVER_URL
    [[ -z "$USERNAME" ]]   && read -rp "Username: " USERNAME
    [[ -z "$SECRET" ]]     && read -rp "Secret: " SECRET
fi

[[ -z "$SERVER_URL" ]] && { echo "Error: --server is required"; exit 1; }
[[ -z "$USERNAME" ]]   && { echo "Error: --user is required"; exit 1; }
[[ -z "$SECRET" ]]     && { echo "Error: --secret is required"; exit 1; }

# Install python3 + pyyaml if missing
if ! command -v python3 &>/dev/null; then
    echo "[INFO] Installing python3..."
    if command -v apt-get &>/dev/null; then
        apt-get update -qq && apt-get install -y -qq python3 python3-yaml
    elif command -v dnf &>/dev/null; then
        dnf install -y python3 python3-pyyaml
    elif command -v yum &>/dev/null; then
        yum install -y python3 python3-pyyaml
    else
        echo "[ERROR] Cannot install python3. Please install manually."
        exit 1
    fi
fi

# Create config directory
CONFIG_DIR="$HOME/.config/ufw-okboy"
mkdir -p "$CONFIG_DIR"

# Write config
cat > "$CONFIG_DIR/config" << EOF
SERVER_URL=$SERVER_URL
USERNAME=$USERNAME
SECRET=$SECRET
EOF
chmod 600 "$CONFIG_DIR/config"
echo "[INFO] Config written to $CONFIG_DIR/config"

# Download knock.py
KNOCK_SCRIPT="/usr/local/bin/ufw-okboy-knock"
if [[ -f "$(dirname "$0")/knock.py" ]]; then
    cp "$(dirname "$0")/knock.py" "$KNOCK_SCRIPT"
else
    echo "[INFO] Downloading knock.py..."
    curl -fsSL "https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/client/knock.py" -o "$KNOCK_SCRIPT"
fi
chmod +x "$KNOCK_SCRIPT"

# Test knock
echo "[INFO] Testing connection..."
VERIFY_FLAG=""
[[ "$NO_VERIFY_SSL" == true ]] && VERIFY_FLAG="--no-verify-ssl"
if python3 "$KNOCK_SCRIPT" -c "$CONFIG_DIR/config" knock $VERIFY_FLAG 2>/dev/null; then
    echo "[INFO] Knock successful! Your IP is now allowlisted."
else
    echo "[WARN] Initial knock failed. Check your config and network."
    echo "       Test manually: python3 $KNOCK_SCRIPT -c $CONFIG_DIR/config knock $VERIFY_FLAG"
fi

# Set up systemd timer for auto-knock
if [[ $EUID -eq 0 ]]; then
    SERVICE_DIR="/etc/systemd/system"
else
    SERVICE_DIR="$HOME/.config/systemd/user"
    mkdir -p "$SERVICE_DIR"
fi

SERVICE_NAME="ufw-okboy-knock"
VERIFY_ARG=""
[[ "$NO_VERIFY_SSL" == true ]] && VERIFY_ARG="--no-verify-ssl"

cat > "$SERVICE_DIR/$SERVICE_NAME.service" << EOF
[Unit]
Description=UFW OkBoy Auto-Knock Client

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 $KNOCK_SCRIPT -c $CONFIG_DIR/config knock $VERIFY_ARG
EOF

cat > "$SERVICE_DIR/$SERVICE_NAME.timer" << EOF
[Unit]
Description=UFW OkBoy Auto-Knock Timer (every ${INTERVAL}s)

[Timer]
OnBootSec=10
OnUnitActiveSec=$INTERVAL
AccuracySec=5

[Install]
WantedBy=timers.target
EOF

if [[ $EUID -eq 0 ]]; then
    systemctl daemon-reload
    systemctl enable --now "$SERVICE_NAME.timer"
    echo "[INFO] System timer enabled: $SERVICE_NAME.timer (every ${INTERVAL}s)"
else
    systemctl --user daemon-reload
    systemctl --user enable --now "$SERVICE_NAME.timer"
    echo "[INFO] User timer enabled: $SERVICE_NAME.timer (every ${INTERVAL}s)"
fi

echo ""
echo "=== Client Setup Complete ==="
echo "  Config:   $CONFIG_DIR/config"
echo "  Script:   $KNOCK_SCRIPT"
echo "  Timer:    every ${INTERVAL}s"
echo ""
echo "  Manual commands:"
echo "    python3 $KNOCK_SCRIPT -c $CONFIG_DIR/config knock $VERIFY_ARG"
echo "    python3 $KNOCK_SCRIPT -c $CONFIG_DIR/config status $VERIFY_ARG"
if [[ $EUID -eq 0 ]]; then
    echo "    systemctl status $SERVICE_NAME.timer"
else
    echo "    systemctl --user status $SERVICE_NAME.timer"
fi
