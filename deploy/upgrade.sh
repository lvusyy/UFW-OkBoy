#!/usr/bin/env bash
#
# UFW OkBoy - One-click upgrade
#
#   curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/upgrade.sh | bash
#   curl -fsSL .../upgrade.sh | bash -s -- --app-dir /opt/ufw-okboy -y
#   curl -fsSL .../upgrade.sh | bash -s -- --branch v2.4.1    # pin a release tag
#   sudo bash deploy/upgrade.sh --repo-dir . -y               # from an unpacked release package
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
GH_MIRROR="${UFW_OKBOY_GH_MIRROR:-}"   # GitHub proxy prefix when GitHub is blocked
PIP_MIRROR=""                          # --mirror <url>; else auto CN fallback
OFFLINE=false                          # install deps from bundled vendor/ wheels

while [[ $# -gt 0 ]]; do
    case "$1" in
        --app-dir)   APP_DIR="$2"; shift 2 ;;
        --service)   SERVICE="$2"; shift 2 ;;
        --branch)    BRANCH="$2"; shift 2 ;;
        --repo-dir)  REPO_DIR="$2"; shift 2 ;;
        --gh-mirror) GH_MIRROR="$2"; shift 2 ;;
        --mirror)    PIP_MIRROR="$2"; shift 2 ;;
        --offline)   OFFLINE=true; shift ;;
        -y|--yes)    shift ;;   # nothing prompts; accepted for scripted runs
        -h|--help)   awk 'NR > 1 && !/^#/ {exit} NR > 1 {sub(/^# ?/, ""); print}' "$0"; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# `--service ufw-okboy.service` names the same unit as `--service ufw-okboy`.
SERVICE="${SERVICE%.service}"

info() { echo "[INFO] $*"; }
warn() { echo "[WARN] $*" >&2; }
err()  { echo "[ERROR] $*" >&2; }

# Prefix a GitHub URL with the mirror when set (ghproxy form: <mirror>/<url>).
gh_url() { if [[ -n "$GH_MIRROR" ]]; then echo "${GH_MIRROR%/}/$1"; else echo "$1"; fi; }

# pip install with offline-vendor / mirror fallback (survives slow/blocked PyPI).
pip_install() {
    local pip="$APP_DIR/venv/bin/pip" vendor="$REPO_DIR/vendor"
    if [[ -d "$vendor" ]]; then
        info "Installing Python deps OFFLINE from $vendor"
        if "$pip" install --no-index --find-links "$vendor" "$@"; then return 0; fi
        [[ "$OFFLINE" == true ]] && { err "Offline install failed and --offline forbids network."; return 1; }
        warn "Offline install incomplete; falling back to an online index."
    elif [[ "$OFFLINE" == true ]]; then
        err "--offline set but no bundled wheels at $vendor."; return 1
    fi
    local index="$PIP_MIRROR"
    if [[ -z "$index" ]]; then
        if ! curl -fsS --max-time 4 -o /dev/null https://pypi.org/simple/ 2>/dev/null; then
            index="https://pypi.tuna.tsinghua.edu.cn/simple"
            warn "pypi.org unreachable — using mirror: $index"
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
#    The installed (old) code writes it: under umask 077, else versions before
#    2.4.0 leave it readable to every local user, secrets and all.
DB_BAK=""
if [[ -f "$CONF" ]]; then
    info "Backing up the database..."
    DB_BAK="$(umask 077; "$PY" "$APP_DIR/server/app.py" -c "$CONF" backup 2>/dev/null \
        | awk '/Backup written:/{print $NF}')" \
        || warn "DB backup step skipped/failed; make sure you have a backup."
    [[ -n "$DB_BAK" ]] && info "DB backup: $DB_BAK"
    # Earlier backups, the config (legacy seed users carry secrets) and the
    # code snapshots' copies of it: owner-only too.
    [[ -n "$DB_BAK" ]] && chmod 600 "$(dirname "$DB_BAK")"/ufw-okboy-*.db 2>/dev/null || true
    chmod 600 "$CONF" "$APP_DIR"/server.bak-*/config.yaml 2>/dev/null || true
fi

# 2) Fetch the latest code (unless a local --repo-dir was given).
TMP_DIR=""
if [[ -z "$REPO_DIR" ]]; then
    TMP_DIR="$(mktemp -d)"
    trap '[[ -n "$TMP_DIR" ]] && rm -rf "$TMP_DIR"' EXIT
    info "Fetching latest code ($BRANCH)..."
    fetched=0
    if command -v git >/dev/null 2>&1; then
        if git clone --depth 1 --branch "$BRANCH" "$(gh_url "$REPO_URL")" "$TMP_DIR/src" 2>"$TMP_DIR/git.err"; then
            fetched=1
        else
            warn "git clone failed ($(tail -n1 "$TMP_DIR/git.err" 2>/dev/null)); falling back to tarball."
        fi
    fi
    if [[ "$fetched" -eq 0 ]]; then
        # archive/<ref> takes a branch or a tag alike (--branch v2.4.1 pins a release).
        curl -fsSL "$(gh_url "$REPO_URL/archive/$BRANCH.tar.gz")" -o "$TMP_DIR/src.tgz" || {
            err "Fetch failed. GitHub may be blocked — retry with --gh-mirror <proxy>, --repo-dir <local>, or the offline package."
            exit 1
        }
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
pip_install -r "$APP_DIR/server/requirements.txt" --quiet \
    || warn "pip step reported warnings."

# 5) Restart the service — the whole point. Migrations run on startup.
#    Units written before 2.4.0 lack UMask=0077, so files the service creates
#    (the database's -wal/-shm, backups, logs) come out readable by every local
#    user. Add it as a drop-in rather than rewriting units that may carry local
#    edits. A unit (or drop-in) that sets UMask itself is the operator's choice
#    and is left alone, as is any existing file where ours would go.
harden_unit() {
    local unit="$1" dir="/etc/systemd/system/$1.d"
    local file="$dir/50-umask.conf"
    systemctl cat "$unit" >/dev/null 2>&1 || return 0
    [[ "$(systemctl show -p UMask --value "$unit" 2>/dev/null)" == "0077" ]] && return 0
    if systemctl cat "$unit" 2>/dev/null | grep -q '^[[:space:]]*UMask='; then
        warn "$unit sets its own UMask ($(systemctl show -p UMask --value "$unit" 2>/dev/null)); left as it is."
        return 0
    fi
    if [[ -e "$file" || -L "$file" ]]; then  # not ours to rewrite
        warn "$unit: $file exists; left as it is (systemctl cat $unit)"
        return 0
    fi
    mkdir -p "$dir"
    printf '[Service]\nUMask=0077\n' > "$file"
    systemctl daemon-reload
    if [[ "$(systemctl show -p UMask --value "$unit" 2>/dev/null)" == "0077" ]]; then
        info "Added UMask=0077 to $unit ($file)"
    else
        rm -f "$file"
        rmdir "$dir" 2>/dev/null || true
        systemctl daemon-reload
        warn "$unit: its UMask is set in another drop-in; left as configured (systemctl cat $unit)"
    fi
}
harden_unit "$SERVICE.service"
harden_unit "$SERVICE-cleanup.service"

info "Restarting $SERVICE..."
systemctl daemon-reload 2>/dev/null || true
systemctl restart "$SERVICE"

# 6) Health-check (retry: gunicorn boot + on-startup DB migration can take a few
#    seconds — a single probe would false-trigger a rollback of a good upgrade).
#    Probe where the service listens: the --bind of its gunicorn command line
#    (config.yaml's listen_port is read by `app.py serve` only), over TLS when
#    gunicorn serves TLS itself (installs made with --no-nginx).
EXEC_START="$(systemctl show -p ExecStart --value "$SERVICE" 2>/dev/null || true)"
BIND="$(sed -nE 's/.* (--bind[= ]|-b ?)([^ ;]+).*/\2/p' <<<"$EXEC_START" | head -n1)"
if [[ -z "$BIND" ]]; then
    [[ -n "$EXEC_START" ]] && warn "No --bind found in $SERVICE's ExecStart; probing 127.0.0.1:5000."
    BIND=127.0.0.1:5000
fi
HOST="${BIND%:*}"
PORT="${BIND##*:}"
case "$HOST" in ""|0.0.0.0|"[::]") HOST=127.0.0.1 ;; esac
SCHEME=http
[[ "$EXEC_START" == *--certfile* ]] && SCHEME=https
HEALTH_URL="$SCHEME://$HOST:$PORT/health"
# A bind this script cannot read (a unix socket, a ${VARIABLE} systemd expands
# at start) would fail every probe and roll back a good upgrade: settle for
# the service staying up then.
if [[ ! "$HOST" =~ ^[][0-9A-Za-z.:-]+$ || ! "$PORT" =~ ^[0-9]+$ ]]; then
    warn "Cannot probe $SERVICE's bind address ($BIND); checking that it stays running instead."
    HEALTH_URL=""
fi
healthy=0
up=0  # consecutive active checks, when the bind cannot be probed
for _ in 1 2 3 4 5 6; do
    if [[ -z "$HEALTH_URL" ]]; then
        sleep 2
        if systemctl is-active --quiet "$SERVICE"; then up=$((up + 1)); else up=0; fi
        [[ "$up" -ge 3 ]] && { healthy=1; break; }
        continue
    fi
    if curl -fsSk "$HEALTH_URL" 2>/dev/null | grep -Eq '"ok": ?true'; then
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
    err "Health check FAILED after restart (${HEALTH_URL:-$SERVICE did not stay active}) — rolling back the code."
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
        err "If the schema migrated, also restore the DB (with the service stopped):"
        err "  systemctl stop $SERVICE && $PY $APP_DIR/server/app.py -c $CONF restore $DB_BAK && systemctl start $SERVICE"
    fi
    exit 1
fi
