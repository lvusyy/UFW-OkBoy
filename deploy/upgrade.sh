#!/usr/bin/env bash
#
# UFW OkBoy - One-click upgrade
#
#   curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/upgrade.sh | bash
#   curl -fsSL .../upgrade.sh | bash -s -- --app-dir /opt/ufw-okboy -y
#
# Updates the code of an EXISTING install, restarts the service (DB schema
# migrations run automatically on startup), and health-checks. PRESERVES your
# config.yaml, nginx config, SSL certs and the database. The DB is backed up
# first and the old code is snapshotted, so a failed upgrade can be rolled back.
#
# This is the fix for "re-running the installer doesn't restart the old service".

set -euo pipefail

APP_DIR="/opt/ufw-okboy"
SERVICE="ufw-okboy"
REPO_URL="https://github.com/lvusyy/UFW-OkBoy"
BRANCH="master"
REPO_DIR=""          # use a local checkout instead of cloning (optional)
ASSUME_YES=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --app-dir)  APP_DIR="$2"; shift 2 ;;
        --service)  SERVICE="$2"; shift 2 ;;
        --branch)   BRANCH="$2"; shift 2 ;;
        --repo-dir) REPO_DIR="$2"; shift 2 ;;
        -y|--yes)   ASSUME_YES=1; shift ;;
        -h|--help)  grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

info() { echo "[INFO] $*"; }
warn() { echo "[WARN] $*" >&2; }
err()  { echo "[ERROR] $*" >&2; }

[[ $EUID -eq 0 ]] || { err "Please run as root (sudo)."; exit 1; }
[[ -f "$APP_DIR/server/app.py" ]] || {
    err "No install found at $APP_DIR. Run the installer first, or pass --app-dir."
    exit 1
}

PY="$APP_DIR/venv/bin/python"
CONF="$APP_DIR/server/config.yaml"

cur_version() { "$PY" "$APP_DIR/server/app.py" --version 2>/dev/null | awk '{print $NF}'; }
OLD_VER="$(cur_version || echo unknown)"
info "Current version: ${OLD_VER:-unknown}   dir: $APP_DIR   service: $SERVICE"

# 1) Back up the database first (safety net). Capture the path so the rollback
#    hint can name the exact file to restore.
DB_BAK=""
if [[ -f "$CONF" ]]; then
    info "Backing up the database..."
    DB_BAK="$("$PY" "$APP_DIR/server/app.py" -c "$CONF" backup 2>/dev/null \
        | awk '/Backup written:/{print $NF}')" \
        || warn "DB backup step skipped/failed; make sure you have a backup."
    [[ -n "$DB_BAK" ]] && info "DB backup: $DB_BAK"
fi

# 2) Fetch the latest code (unless a local --repo-dir was given).
TMP_DIR=""
if [[ -z "$REPO_DIR" ]]; then
    TMP_DIR="$(mktemp -d)"
    trap '[[ -n "$TMP_DIR" ]] && rm -rf "$TMP_DIR"' EXIT
    info "Fetching latest code ($BRANCH)..."
    fetched=0
    if command -v git >/dev/null 2>&1; then
        if git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$TMP_DIR/src" 2>"$TMP_DIR/git.err"; then
            fetched=1
        else
            warn "git clone failed ($(tail -n1 "$TMP_DIR/git.err" 2>/dev/null)); falling back to tarball."
        fi
    fi
    if [[ "$fetched" -eq 0 ]]; then
        curl -fsSL "$REPO_URL/archive/refs/heads/$BRANCH.tar.gz" -o "$TMP_DIR/src.tgz"
        mkdir -p "$TMP_DIR/src"
        tar xzf "$TMP_DIR/src.tgz" -C "$TMP_DIR/src" --strip-components=1
    fi
    REPO_DIR="$TMP_DIR/src"
fi
[[ -f "$REPO_DIR/server/app.py" ]] || { err "Fetched source is incomplete."; exit 1; }

NEW_VER="$(tr -d '[:space:]' < "$REPO_DIR/VERSION" 2>/dev/null || echo unknown)"
info "Target version: $NEW_VER"

# 3) Snapshot current code (rollback point) and copy in the new server files.
#    config.yaml is NOT touched.
CODE_BAK="$APP_DIR/server.bak-$(date +%Y%m%d-%H%M%S)"
cp -r "$APP_DIR/server" "$CODE_BAK"
info "Code snapshot: $CODE_BAK"

cp "$REPO_DIR/server/app.py" "$REPO_DIR/server/ufw_ops.py" "$REPO_DIR/server/db.py" \
   "$REPO_DIR/server/auth.py" "$REPO_DIR/server/requirements.txt" \
   "$REPO_DIR/server/config.example.yaml" "$APP_DIR/server/"
cp -r "$REPO_DIR/server/static" "$APP_DIR/server/"
if [[ -d "$REPO_DIR/server/tests" ]]; then
    mkdir -p "$APP_DIR/server/tests"
    cp -r "$REPO_DIR/server/tests/"* "$APP_DIR/server/tests/" 2>/dev/null || true
fi
# VERSION lives next to the install root so app.py --version / /health report it.
cp "$REPO_DIR/VERSION" "$APP_DIR/" 2>/dev/null || true

# 4) Update Python deps (no --upgrade: installs anything newly required,
#    leaves satisfied pins alone).
info "Updating Python dependencies..."
"$APP_DIR/venv/bin/pip" install -r "$APP_DIR/server/requirements.txt" --quiet \
    || warn "pip step reported warnings."

# 5) Restart the service — the whole point. Migrations run on startup.
info "Restarting $SERVICE..."
systemctl daemon-reload 2>/dev/null || true
systemctl restart "$SERVICE"

# 6) Health-check (retry: gunicorn boot + on-startup DB migration can take a few
#    seconds — a single probe would false-trigger a rollback of a good upgrade).
PORT="$(awk -F'[: ]+' '/^listen_port:/{print $2}' "$CONF" 2>/dev/null | tr -d '"' || true)"
PORT="${PORT:-5000}"
healthy=0
for _ in 1 2 3 4 5 6; do
    if curl -fsS "http://127.0.0.1:$PORT/health" 2>/dev/null | grep -q '"ok"'; then
        healthy=1; break
    fi
    sleep 2
done
if [[ "$healthy" -eq 1 ]]; then
    RUN_VER="$(cur_version || echo unknown)"
    info "Health OK — service is up on version: ${RUN_VER:-unknown}"
    # Prune old code snapshots (keep the 3 most recent) so $APP_DIR doesn't grow.
    ls -dt "$APP_DIR"/server.bak-* 2>/dev/null | tail -n +4 | xargs -r rm -rf || true
    echo ""
    echo "  ✓ Upgrade complete: ${OLD_VER:-unknown} -> $NEW_VER"
    echo "    DB backup + code snapshot ($CODE_BAK) kept for safety."
    echo "    Browser users: hard-refresh (Ctrl-Shift-R) to load the new UI."
else
    err "Health check FAILED after restart — rolling back the code."
    systemctl stop "$SERVICE" 2>/dev/null || true
    # Atomic restore: move the new (failed) tree ASIDE first, copy the snapshot
    # back (CODE_BAK stays intact as the durable rollback point), and only then
    # drop the failed tree — never leave NO server dir, even if a step fails
    # (e.g. a cross-filesystem move).
    FAILED_DIR="$APP_DIR/server.failed-$(date +%Y%m%d-%H%M%S)"
    mv "$APP_DIR/server" "$FAILED_DIR" 2>/dev/null || true
    if cp -r "$CODE_BAK" "$APP_DIR/server"; then
        rm -rf "$FAILED_DIR"
    else
        err "Rollback copy failed — previous code is preserved at: $CODE_BAK"
    fi
    systemctl start "$SERVICE" 2>/dev/null || true
    err "Rolled back to the previous code. Check: journalctl -u $SERVICE -n 50 --no-pager"
    if [[ -n "$DB_BAK" ]]; then
        err "If the schema migrated, also restore the DB:"
        err "  $PY $APP_DIR/server/app.py -c $CONF restore $DB_BAK"
    fi
    exit 1
fi
