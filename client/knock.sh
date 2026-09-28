#!/usr/bin/env bash
# UFW OkBoy - Shell Client (zero dependencies beyond curl + openssl)
#
# Usage:
#   ./knock.sh                        # Knock once
#   ./knock.sh status                 # Check registration status
#   KNOCK_CONFIG=/path/cfg ./knock.sh # Custom config path
#
# Config file format (default: ~/.config/ufw-okboy/config):
#   SERVER_URL=https://your-server.com
#   USERNAME=alice
#   SECRET=your-secret-here
#   PIN_SHA256=<base64>   # optional: trust exactly this server key (self-signed certs)
#   INSECURE=1            # optional: skip TLS verification altogether
#
# Self-signed certificates are the norm for IP-based / high-port deployments
# (common in mainland China where filed domains + Let's Encrypt are impractical).
# For those, set PIN_SHA256 to the server's public-key pin (the admin prints it
# on the server; see GUIDE.md): curl then accepts only that key, CA or not, and
# INSECURE / --insecure no longer matter. INSECURE=1 (in the config or the
# environment) or --insecure skips verification instead: the HMAC secret is
# never transmitted, but a man in the middle can capture a request and replay
# it while its signature is valid. PIN_SHA256 needs an https:// SERVER_URL and
# curl 7.49 or later (older ones ignored the pin on some TLS backends, so they
# are refused); a curl whose TLS backend cannot check sha256 pins stops with an
# error and sends nothing (see curl's CURLOPT_PINNEDPUBLICKEY).

set -euo pipefail

# ---- Configuration ---- #

CONFIG_FILE="${KNOCK_CONFIG:-$HOME/.config/ufw-okboy/config}"

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Error: Config file not found: $CONFIG_FILE"
    echo ""
    echo "Create it with:"
    echo "  mkdir -p ~/.config/ufw-okboy"
    echo "  cat > ~/.config/ufw-okboy/config << 'EOF'"
    echo "  SERVER_URL=https://your-server.com"
    echo "  USERNAME=alice"
    echo "  SECRET=your-secret-here"
    echo "  EOF"
    echo "  chmod 600 ~/.config/ufw-okboy/config"
    exit 1
fi

# shellcheck source=/dev/null
source "$CONFIG_FILE"

: "${SERVER_URL:?SERVER_URL is required in config}"
: "${USERNAME:?USERNAME is required in config}"
: "${SECRET:?SECRET is required in config}"

# ---- HMAC-SHA256 Auth ---- #

build_auth() {
    local timestamp
    timestamp=$(date +%s)
    local message="${USERNAME}:${timestamp}"
    local signature
    signature=$(printf '%s' "$message" | openssl dgst -sha256 -hmac "$SECRET" -hex 2>/dev/null | awk '{print $NF}')
    echo "HMAC-SHA256 ${USERNAME}:${timestamp}:${signature}"
}

# ---- Actions ---- #

do_knock() {
    local auth
    auth=$(build_auth)
    curl ${CURL_PRE[@]+"${CURL_PRE[@]}"} -sS -X POST \
        "${SERVER_URL}/api/knock" \
        -H "Authorization: ${auth}" \
        -H "Content-Type: application/json" \
        --connect-timeout 10 \
        --max-time 30 \
        ${CURL_TLS[@]+"${CURL_TLS[@]}"}
    echo ""
}

do_status() {
    local auth
    auth=$(build_auth)
    curl ${CURL_PRE[@]+"${CURL_PRE[@]}"} -sS -X GET \
        "${SERVER_URL}/api/status" \
        -H "Authorization: ${auth}" \
        --connect-timeout 10 \
        --max-time 30 \
        ${CURL_TLS[@]+"${CURL_TLS[@]}"}
    echo ""
}

# ---- Main ---- #

# Parse the action and an optional --insecure / -k flag (in any order).
ACTION="knock"
for arg in "$@"; do
    case "$arg" in
        -k|--insecure) INSECURE=1 ;;
        knock|status)  ACTION="$arg" ;;
        *) echo "Usage: $0 [knock|status] [--insecure]"; exit 1 ;;
    esac
done

# Resolve TLS verification: PIN_SHA256 > --insecure flag > INSECURE from config/env.
INSECURE="${INSECURE:-0}"
PIN_SHA256="${PIN_SHA256:-}"
CURL_PRE=()
CURL_TLS=()
if [[ -n "$PIN_SHA256" ]]; then
    if [[ ! "$PIN_SHA256" =~ ^[A-Za-z0-9+/]{43}=$ ]]; then
        echo "Error: PIN_SHA256 must be the base64 SHA-256 of the server's public key (44 characters ending in '=')"
        exit 1
    fi
    if [[ "$SERVER_URL" != https://* ]]; then
        echo "Error: PIN_SHA256 needs an https:// SERVER_URL"
        exit 1
    fi
    # Before 7.49, curl accepted --pinnedpubkey on TLS backends that never
    # checked it; since then such a backend is an error.
    curl_version="$(curl --version 2>/dev/null | awk 'NR == 1 {print $2}')"
    IFS=. read -r curl_major curl_minor _ <<< "$curl_version"
    if [[ ! "$curl_major" =~ ^[0-9]+$ || ! "${curl_minor%%[!0-9]*}" =~ ^[0-9]+$ ]] ||
            (( curl_major < 7 || (curl_major == 7 && ${curl_minor%%[!0-9]*} < 49) )); then
        echo "Error: PIN_SHA256 needs curl 7.49 or later (found: ${curl_version:-none})"
        exit 1
    fi
    # -q (must come first): no ~/.curlrc, whose options (HTTP/3, say) could
    # weaken the check. -k: no CA or host-name check (a self-signed server); the
    # pin is checked right after the handshake and curl sends nothing when it
    # does not match. --proto: https and nothing else.
    CURL_PRE=(-q)
    CURL_TLS=(-k --pinnedpubkey "sha256//$PIN_SHA256" --proto "=https")
elif [[ "$INSECURE" == "1" || "$INSECURE" == "true" ]]; then
    CURL_TLS=(-k)
fi

case "$ACTION" in
    knock)
        do_knock
        ;;
    status)
        do_status
        ;;
esac
