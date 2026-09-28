#!/usr/bin/env bash
# UFW OkBoy - Client Quick Install Script
# Sets up knock.py + systemd timer for auto-knocking
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/install-client.sh | bash -s -- --server https://203.0.113.10:8443 --user alice --secret YOUR_SECRET --pin-sha256 SERVER_KEY_PIN
#
# Flags:
#   --server <url>     Server URL (e.g., https://your-server.com or https://203.0.113.10:8443)
#   --user <username>  Your username
#   --secret <secret>  Your HMAC secret
#   --interval <sec>   Knock interval (default: 30)
#   --pin-sha256 <pin> Trust exactly the server key with this pin (self-signed
#                      certs — common in CN; the server admin has the pin).
#                      A re-run for the same server keeps its pin; '' removes it
#   --no-verify-ssl    Skip TLS verification instead (not recommended)
#   --gh-mirror <url>  GitHub proxy prefix for downloads when GitHub is blocked
#                      (e.g. https://ghfast.top; find a current one at
#                      https://ghproxy.link/). Also via UFW_OKBOY_GH_MIRROR.
#   --yes              Non-interactive

set -euo pipefail

SERVER_URL=""
USERNAME=""
SECRET=""
INTERVAL=30
PIN_SHA256=""
PIN_GIVEN=false
NO_VERIFY_SSL=false
GH_MIRROR="${UFW_OKBOY_GH_MIRROR:-}"
NON_INTERACTIVE=false

GH_RAW="https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server)        SERVER_URL="$2"; shift 2 ;;
        --user)          USERNAME="$2"; shift 2 ;;
        --secret)        SECRET="$2"; shift 2 ;;
        --interval)      INTERVAL="$2"; shift 2 ;;
        --pin-sha256)    PIN_SHA256="$2"; PIN_GIVEN=true; shift 2 ;;
        --no-verify-ssl) NO_VERIFY_SSL=true; shift ;;
        --gh-mirror)     GH_MIRROR="$2"; shift 2 ;;
        --yes)           NON_INTERACTIVE=true; shift ;;
        -h|--help)       head -20 "$0"; exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Fetch a file from the repo, honoring a GitHub mirror prefix when set. ghproxy
# style: <mirror>/<full-raw-url>. Falls back to a clear error pointing at the
# offline package when GitHub is unreachable and no mirror is configured.
gh_fetch() {  # $1 = path under repo, $2 = destination
    local path="$1" dest="$2" url
    if [[ -n "$GH_MIRROR" ]]; then
        url="${GH_MIRROR%/}/${GH_RAW}/${path}"
    else
        url="${GH_RAW}/${path}"
    fi
    if ! curl -fsSL "$url" -o "$dest"; then
        echo "[ERROR] Download failed: $url" >&2
        if [[ -z "$GH_MIRROR" ]]; then
            echo "        GitHub may be blocked. Retry with --gh-mirror <proxy>," >&2
            echo "        or install from the offline release package instead." >&2
        fi
        return 1
    fi
}

# Interactive prompts for missing required fields
if [[ "$NON_INTERACTIVE" == false ]]; then
    [[ -z "$SERVER_URL" ]] && read -rp "Server URL (https://...): " SERVER_URL
    [[ -z "$USERNAME" ]]   && read -rp "Username: " USERNAME
    [[ -z "$SECRET" ]]     && read -rp "Secret: " SECRET
fi

[[ -z "$SERVER_URL" ]] && { echo "Error: --server is required"; exit 1; }
[[ -z "$USERNAME" ]]   && { echo "Error: --user is required"; exit 1; }
[[ -z "$SECRET" ]]     && { echo "Error: --secret is required"; exit 1; }
if [[ -n "$PIN_SHA256" && ! "$PIN_SHA256" =~ ^[A-Za-z0-9+/]{43}=$ ]]; then
    echo "Error: --pin-sha256 must be the base64 SHA-256 of the server's public key (44 characters ending in '=')"
    exit 1
fi
if [[ -n "$PIN_SHA256" && "$SERVER_URL" != https://* ]]; then
    echo "Error: a key pin (--pin-sha256) needs an https:// --server"
    exit 1
fi

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
CONFIG_FILE="$CONFIG_DIR/config.yaml"

# A re-run keeps the key pin of the existing config unless --pin-sha256 is
# given ('' removes it). A pin that cannot be read, or whose server_url is not
# this --server, stops the install rather than being dropped silently.
# (knock.py reads the key case-sensitively; spaces may precede the colon.)
norm_url() {  # no trailing slash, no default https port
    local u="${1%/}"
    [[ "$u" =~ ^(https://[^/]+):443(/.*)?$ ]] && u="${BASH_REMATCH[1]}${BASH_REMATCH[2]}"
    printf '%s' "$u"
}
if [[ "$PIN_GIVEN" == false && -f "$CONFIG_FILE" ]] && grep -qE '^[[:space:]]*pin_sha256[[:space:]]*:' "$CONFIG_FILE"; then
    old_url="$(sed -nE "s/^[[:space:]]*server_url[[:space:]]*:[[:space:]]*[\"']?([^\"'[:space:]]*)[\"']?[[:space:]]*\$/\1/p" "$CONFIG_FILE")"
    PIN_SHA256="$(sed -nE "s/^[[:space:]]*pin_sha256[[:space:]]*:[[:space:]]*[\"']?([A-Za-z0-9+\/]{43}=)[\"']?[[:space:]]*\$/\1/p" "$CONFIG_FILE")"
    if [[ ! "$PIN_SHA256" =~ ^[A-Za-z0-9+/]{43}=$ || "$(norm_url "$old_url")" != "$(norm_url "$SERVER_URL")" ]]; then
        echo "Error: $CONFIG_FILE holds a key pin (server_url: ${old_url:-unreadable}) that cannot be carried over;"
        echo "       pass --pin-sha256 <pin> for $SERVER_URL, or --pin-sha256 '' if it needs none"
        exit 1
    fi
    echo "[INFO] Keeping the server key pin of $CONFIG_FILE (--pin-sha256 '' removes it)"
fi

# verify_ssl mirrors --no-verify-ssl; a pin_sha256 line (--pin-sha256) takes
# precedence over it in knock.py.
VERIFY_SSL=true
[[ "$NO_VERIFY_SSL" == true ]] && VERIFY_SSL=false
PIN_LINE=""
[[ -n "$PIN_SHA256" ]] && PIN_LINE="pin_sha256: \"$PIN_SHA256\""

# Write config in the YAML format knock.py expects (server_url/username/secret).
# (The previous shell-style SERVER_URL=... format was silently unparseable by the
# Python client, so the auto-knock never worked.)
cat > "$CONFIG_FILE" << EOF
server_url: "$SERVER_URL"
username: "$USERNAME"
secret: "$SECRET"
verify_ssl: $VERIFY_SSL
$PIN_LINE
EOF
chmod 600 "$CONFIG_FILE"
echo "[INFO] Config written to $CONFIG_FILE"

# Install knock.py (prefer the local copy from a repo/offline package).
KNOCK_SCRIPT="/usr/local/bin/ufw-okboy-knock"
if [[ -f "$(dirname "$0")/../client/knock.py" ]]; then
    cp "$(dirname "$0")/../client/knock.py" "$KNOCK_SCRIPT"
elif [[ -f "$(dirname "$0")/knock.py" ]]; then
    cp "$(dirname "$0")/knock.py" "$KNOCK_SCRIPT"
else
    echo "[INFO] Downloading knock.py..."
    gh_fetch "client/knock.py" "$KNOCK_SCRIPT"
fi
chmod +x "$KNOCK_SCRIPT"

# Test knock (verify_ssl is read from the config now).
echo "[INFO] Testing connection..."
if python3 "$KNOCK_SCRIPT" -c "$CONFIG_FILE" knock 2>/dev/null; then
    echo "[INFO] Knock successful! Your IP is now allowlisted."
else
    echo "[WARN] Initial knock failed. Check your config and network."
    echo "       Test manually: python3 $KNOCK_SCRIPT -c $CONFIG_FILE knock"
fi

# Set up systemd timer for auto-knock
if [[ $EUID -eq 0 ]]; then
    SERVICE_DIR="/etc/systemd/system"
else
    SERVICE_DIR="$HOME/.config/systemd/user"
    mkdir -p "$SERVICE_DIR"
fi

SERVICE_NAME="ufw-okboy-knock"

cat > "$SERVICE_DIR/$SERVICE_NAME.service" << EOF
[Unit]
Description=UFW OkBoy Auto-Knock Client

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 $KNOCK_SCRIPT -c $CONFIG_FILE knock
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
echo "  Config:   $CONFIG_FILE"
echo "  Script:   $KNOCK_SCRIPT"
echo "  Timer:    every ${INTERVAL}s"
if [[ -n "$PIN_SHA256" ]]; then
    echo "  TLS:      pinned server key $PIN_SHA256"
else
    echo "  TLS:      verify_ssl=$VERIFY_SSL"
fi
echo ""
echo "  Manual commands:"
echo "    python3 $KNOCK_SCRIPT -c $CONFIG_FILE knock"
echo "    python3 $KNOCK_SCRIPT -c $CONFIG_FILE status"
if [[ $EUID -eq 0 ]]; then
    echo "    systemctl status $SERVICE_NAME.timer"
else
    echo "    systemctl --user status $SERVICE_NAME.timer"
fi
