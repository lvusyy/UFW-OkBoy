#!/usr/bin/env bash
# UFW OkBoy - One-Line Installer (curl | bash)
# Downloads the latest source and runs deploy.sh
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/quick-install.sh | bash
#   curl -fsSL .../quick-install.sh | bash -s -- --self-signed -y
#   # Behind the GFW (GitHub blocked), use a proxy prefix:
#   curl -fsSL .../quick-install.sh | bash -s -- --gh-mirror https://ghproxy.com --self-signed -y
#
# --gh-mirror <url>   GitHub proxy prefix (ghproxy-style); also UFW_OKBOY_GH_MIRROR.
#                     All other flags are forwarded to deploy.sh (--port, --ip,
#                     --mirror, --offline, --self-signed, -y, ...).
#
# NOTE: For unreliable networks (mainland China), the OFFLINE release package is
# more robust than this online installer — it bundles Python wheels so the only
# download is the single tarball. See build-release.sh / the GitHub Releases page.

set -euo pipefail

REPO_URL="https://github.com/lvusyy/UFW-OkBoy"
GH_MIRROR="${UFW_OKBOY_GH_MIRROR:-}"
TMP_DIR=$(mktemp -d)

cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

# Separate --gh-mirror (consumed here) from the flags forwarded to deploy.sh.
PASS_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --gh-mirror) GH_MIRROR="$2"; shift 2 ;;
        *) PASS_ARGS+=("$1"); shift ;;
    esac
done

# Prefix a GitHub URL with the mirror when set (ghproxy form: <mirror>/<url>).
gh_url() { if [[ -n "$GH_MIRROR" ]]; then echo "${GH_MIRROR%/}/$1"; else echo "$1"; fi; }

echo "=== UFW OkBoy Quick Installer ==="
[[ -n "$GH_MIRROR" ]] && echo "[INFO] Using GitHub mirror: $GH_MIRROR"
echo ""

REPO_DIR=""
# Prefer git clone (shallow); fall back to a tarball; both honor the mirror.
if command -v git &>/dev/null; then
    echo "[INFO] Downloading via git clone..."
    if git clone --depth 1 "$(gh_url "$REPO_URL")" "$TMP_DIR/ufw-okboy" 2>/dev/null; then
        REPO_DIR="$TMP_DIR/ufw-okboy"
    else
        echo "[WARN] git clone failed; trying tarball..."
    fi
fi
if [[ -z "$REPO_DIR" ]] && command -v curl &>/dev/null; then
    echo "[INFO] Downloading via tarball..."
    if curl -fsSL "$(gh_url "$REPO_URL/archive/refs/heads/master.tar.gz")" -o "$TMP_DIR/repo.tar.gz"; then
        tar xzf "$TMP_DIR/repo.tar.gz" -C "$TMP_DIR"
        REPO_DIR="$TMP_DIR/UFW-OkBoy-master"
    fi
fi

if [[ -z "$REPO_DIR" || ! -d "$REPO_DIR" ]]; then
    echo "[ERROR] Download failed." >&2
    if [[ -z "$GH_MIRROR" ]]; then
        echo "        GitHub may be blocked on this network." >&2
        echo "        Retry with a proxy:  ... | bash -s -- --gh-mirror https://ghproxy.com" >&2
        echo "        Or use the OFFLINE release package (bundles all deps)." >&2
    fi
    exit 1
fi

cd "$REPO_DIR"

# Run the deployment script with the forwarded args.
exec bash deploy/deploy.sh "${PASS_ARGS[@]+"${PASS_ARGS[@]}"}"
