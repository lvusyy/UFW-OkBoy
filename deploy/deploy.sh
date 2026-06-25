#!/usr/bin/env bash
# UFW OkBoy - One-Click Deployment Script
# Supports: Ubuntu/Debian (apt), CentOS/RHEL/Fedora (dnf/yum)
# SSL modes: domain → Let's Encrypt, no domain → self-signed (IP:port)
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/deploy.sh | bash
#   OR:
#   bash deploy.sh [--domain your.domain.com] [--port 443] [--no-nginx]
#
# Flags:
#   --domain <domain>   Use Let's Encrypt for this domain (requires DNS A record)
#   --port <port>       HTTPS port (default: 443; use a high port in CN setups)
#   --ip <addr>         Public IP for the self-signed cert + access URL (skip
#                       auto-detection; useful on NAT'd cloud VPS)
#   --mirror <url>      PyPI index URL (e.g. https://pypi.tuna.tsinghua.edu.cn/simple).
#                       If omitted and pypi.org is unreachable, a CN mirror is used.
#   --offline           Install Python deps from the bundled vendor/ wheels (no network)
#   --no-nginx          Skip nginx setup (use gunicorn directly with self-signed)
#   --self-signed       Force self-signed cert even if domain provided
#   --admin-user <name> First admin to auto-create (default: admin; use 'skip' to skip)
#   --app-dir <path>    Install directory (default: /opt/ufw-okboy)
#   -y, --yes           Non-interactive mode (skip all prompts)

set -euo pipefail

# ── Defaults ── #
APP_DIR="/opt/ufw-okboy"
DATA_DIR="/var/lib/ufw-okboy"
LOG_DIR="/var/log/ufw-okboy"
HTTPS_PORT=443
DOMAIN=""
PUBLIC_IP=""
PIP_MIRROR=""
OFFLINE=false
FORCE_SELF_SIGNED=false
NO_NGINX=false
NON_INTERACTIVE=false
ADMIN_USER=""          # first admin to auto-create; default "admin" (see bootstrap)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
# Bundled offline wheels (produced by build-release.sh) enable a zero-network
# Python dependency install — the reliable path where PyPI is slow/blocked.
VENDOR_DIR="$REPO_DIR/vendor"

# ── Color output ── #
if [[ -t 1 ]]; then
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    RED='\033[0;31m'
    CYAN='\033[0;36m'
    NC='\033[0m'
else
    GREEN=''; YELLOW=''; RED=''; CYAN=''; NC=''
fi

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
step()  { echo -e "\n${CYAN}=== $* ===${NC}"; }

# Best-effort PUBLIC IP for the self-signed cert SAN + the printed access URL.
# On a cloud VPS `hostname -I` returns the PRIVATE NIC address, not the address
# users actually reach — so prefer an explicit --ip, then a public echo service
# (short timeout; CN-reachable endpoints first), and only then the local NIC IP.
detect_public_ip() {
    if [[ -n "$PUBLIC_IP" ]]; then echo "$PUBLIC_IP"; return; fi
    local ip svc
    for svc in "https://4.ipw.cn" "https://api.ipify.org" "https://ifconfig.me/ip"; do
        ip="$(curl -fsS --max-time 4 "$svc" 2>/dev/null | tr -d '[:space:]')"
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then echo "$ip"; return; fi
    done
    ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    [[ -n "$ip" ]] && warn "Public IP auto-detect failed; using local IP $ip (pass --ip on a NAT'd VPS)." >&2
    echo "${ip:-127.0.0.1}"
}

# pip install with offline-vendor / mirror fallback. Args: pip-install arguments
# (e.g. -r requirements.txt). Order: bundled wheels (offline) > --mirror >
# probe pypi.org, else a CN mirror. This is what makes the install survive the
# slow/blocked PyPI access typical in mainland China.
pip_install() {
    local pip="$APP_DIR/venv/bin/pip"
    if [[ -d "$VENDOR_DIR" ]]; then
        info "Installing Python deps OFFLINE from $VENDOR_DIR"
        if "$pip" install --no-index --find-links "$VENDOR_DIR" "$@"; then return 0; fi
        [[ "$OFFLINE" == true ]] && { error "Offline install failed and --offline forbids network."; return 1; }
        warn "Offline install incomplete; falling back to an online index."
    elif [[ "$OFFLINE" == true ]]; then
        error "--offline set but no bundled wheels at $VENDOR_DIR (build with build-release.sh)."
        return 1
    fi
    local index="$PIP_MIRROR"
    if [[ -z "$index" ]]; then
        if ! curl -fsS --max-time 4 -o /dev/null https://pypi.org/simple/ 2>/dev/null; then
            index="https://pypi.tuna.tsinghua.edu.cn/simple"
            warn "pypi.org unreachable — using mirror: $index"
        fi
    fi
    if [[ -n "$index" ]]; then
        local host; host="$(echo "$index" | awk -F/ '{print $3}')"
        "$pip" install -i "$index" --trusted-host "$host" "$@"
    else
        "$pip" install "$@"
    fi
}

# ── Parse args ── #
while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain)       DOMAIN="$2"; shift 2 ;;
        --port)         HTTPS_PORT="$2"; shift 2 ;;
        --ip)           PUBLIC_IP="$2"; shift 2 ;;
        --mirror)       PIP_MIRROR="$2"; shift 2 ;;
        --offline)      OFFLINE=true; shift ;;
        --no-nginx)     NO_NGINX=true; shift ;;
        --self-signed)  FORCE_SELF_SIGNED=true; shift ;;
        --admin-user)   ADMIN_USER="$2"; shift 2 ;;
        --app-dir)      APP_DIR="$2"; shift 2 ;;
        -y|--yes)       NON_INTERACTIVE=true; shift ;;
        -h|--help)
            head -31 "$0"
            exit 0
            ;;
        *) error "Unknown option: $1"; exit 1 ;;
    esac
done

# ── Pre-flight checks ── #
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root."
    exit 1
fi

# ── Detect distribution ── #
detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        DISTRO_ID="$ID"
        DISTRO_FAMILY="$ID_LIKE"
        DISTRO_VERSION="$VERSION_ID"
    else
        error "Cannot detect distribution: /etc/os-release not found"
        exit 1
    fi
}

detect_distro
info "Detected distribution: $DISTRO_ID ${DISTRO_VERSION:-}"

# ── Package manager selection ── #
select_pkg_manager() {
    case "$DISTRO_ID" in
        ubuntu|debian|linuxmint|raspbian)
            PKG_UPDATE="apt-get update -qq"
            PKG_INSTALL="apt-get install -y -qq"
            NGINX_PKG="nginx"
            PYTHON_PKG="python3 python3-venv python3-pip"
            CERTBOT_PKG="certbot python3-certbot-nginx"
            UFW_PKG="ufw"
            ;;
        centos|rhel|rocky|almalinux|fedora|amzn)
            if command -v dnf &>/dev/null; then
                PKG_UPDATE="dnf check-update || true"
                PKG_INSTALL="dnf install -y"
            else
                PKG_UPDATE="yum check-update || true"
                PKG_INSTALL="yum install -y"
            fi
            NGINX_PKG="nginx"
            PYTHON_PKG="python3 python3-pip"
            CERTBOT_PKG="certbot python3-certbot-nginx"
            UFW_PKG="ufw"
            # EPEL needed for ufw on RHEL-based
            if [[ "$DISTRO_ID" != "fedora" ]]; then
                EPEL_PKG="epel-release"
            fi
            ;;
        *)
            error "Unsupported distribution: $DISTRO_ID"
            error "Supported: Ubuntu, Debian, CentOS, RHEL, Rocky, AlmaLinux, Fedora"
            exit 1
            ;;
    esac
}

select_pkg_manager

# ── Step 1: Install system dependencies ── #
step "Step 1/6: Installing system dependencies"

$PKG_UPDATE
if [[ -n "${EPEL_PKG:-}" ]]; then
    info "Installing EPEL repository..."
    $PKG_INSTALL $EPEL_PKG
fi

info "Installing: $UFW_PKG $NGINX_PKG $PYTHON_PKG"
$PKG_INSTALL $UFW_PKG $NGINX_PKG $PYTHON_PKG

if [[ "$FORCE_SELF_SIGNED" == false && -n "$DOMAIN" ]]; then
    info "Installing certbot for Let's Encrypt..."
    $PKG_INSTALL $CERTBOT_PKG
fi

# Ensure ufw is enabled
if ! ufw status | grep -q "Status: active"; then
    warn "UFW is not active. Enabling UFW..."
    ufw --force enable
fi

# ── Step 2: Create directories ── #
step "Step 2/6: Creating directories"

mkdir -p "$APP_DIR/server" "$APP_DIR/venv" "$DATA_DIR" "$LOG_DIR"
info "App dir:   $APP_DIR"
info "Data dir:  $DATA_DIR"
info "Log dir:   $LOG_DIR"

# ── Step 3: Copy application files ── #
step "Step 3/6: Installing application"

# Copy from repo or download
if [[ -f "$REPO_DIR/server/app.py" ]]; then
    info "Installing from local repository..."
    cp "$REPO_DIR/server/app.py" "$REPO_DIR/server/ufw_ops.py" "$REPO_DIR/server/db.py" \
       "$REPO_DIR/server/auth.py" "$REPO_DIR/server/requirements.txt" \
       "$REPO_DIR/server/config.example.yaml" "$APP_DIR/server/" 2>/dev/null || true
    # Copy static dir
    if [[ -d "$REPO_DIR/server/static" ]]; then
        cp -r "$REPO_DIR/server/static" "$APP_DIR/server/"
    fi
    # Copy tests
    if [[ -d "$REPO_DIR/server/tests" ]]; then
        mkdir -p "$APP_DIR/server/tests"
        cp -r "$REPO_DIR/server/tests/"* "$APP_DIR/server/tests/" 2>/dev/null || true
    fi
    # VERSION file so app.py --version and /health report the real version
    cp "$REPO_DIR/VERSION" "$APP_DIR/" 2>/dev/null || true
else
    error "Cannot find application files. Run from repository root or use curl install."
    exit 1
fi

# Create virtual environment
info "Setting up Python virtual environment..."
python3 -m venv "$APP_DIR/venv"
pip_install --upgrade pip --quiet || warn "pip self-upgrade skipped (non-fatal)."
pip_install -r "$APP_DIR/server/requirements.txt" --quiet

# Config file
if [[ ! -f "$APP_DIR/server/config.yaml" ]]; then
    cp "$APP_DIR/server/config.example.yaml" "$APP_DIR/server/config.yaml"
    info "Config created: $APP_DIR/server/config.yaml"
    warn "IMPORTANT: Edit config and create your first admin user!"
else
    info "Config already exists, preserving."
fi

# ── Step 4: SSL setup ── #
step "Step 4/6: Configuring SSL"

SSL_CERT=""
SSL_KEY=""

if [[ "$FORCE_SELF_SIGNED" == true || -z "$DOMAIN" ]]; then
    # Self-signed certificate — the default/recommended path for IP-based access
    # (no filed domain needed; works on any port). Clients trust it once: the web
    # UI adds a browser exception; CLI clients set verify_ssl=false / --insecure.
    info "Generating self-signed certificate (no domain → IP-based HTTPS)..."
    SSL_DIR="/etc/ssl/ufw-okboy"
    mkdir -p "$SSL_DIR"
    SSL_CERT="$SSL_DIR/selfsigned.crt"
    SSL_KEY="$SSL_DIR/selfsigned.key"

    # Public IP for the cert SAN (NOT hostname -I, which is the private NIC on a
    # cloud VPS and would never match the address users connect to).
    SERVER_IP="$(detect_public_ip)"

    # 10-year validity: a 1-year self-signed cert would silently expire and break
    # every knock; for an internal tool a long-lived cert is the kinder default.
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout "$SSL_KEY" \
        -out "$SSL_CERT" \
        -subj "/CN=$SERVER_IP" \
        -addext "subjectAltName=IP:$SERVER_IP" 2>/dev/null || \
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout "$SSL_KEY" \
        -out "$SSL_CERT" \
        -subj "/CN=$SERVER_IP" 2>/dev/null

    chmod 600 "$SSL_KEY"
    info "Self-signed cert: $SSL_CERT  (CN/SAN: $SERVER_IP, valid 10y)"
    info "Access via: https://$SERVER_IP:$HTTPS_PORT"
else
    # Let's Encrypt via certbot
    info "Requesting Let's Encrypt certificate for: $DOMAIN"
    if certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email --redirect; then
        SSL_CERT="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
        SSL_KEY="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
        info "Let's Encrypt cert installed for: $DOMAIN"
    else
        warn "Certbot failed, falling back to self-signed..."
        FORCE_SELF_SIGNED=true
        SSL_DIR="/etc/ssl/ufw-okboy"
        mkdir -p "$SSL_DIR"
        SSL_CERT="$SSL_DIR/selfsigned.crt"
        SSL_KEY="$SSL_DIR/selfsigned.key"
        SERVER_IP="$(detect_public_ip)"
        openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
            -keyout "$SSL_KEY" -out "$SSL_CERT" -subj "/CN=$SERVER_IP" \
            -addext "subjectAltName=IP:$SERVER_IP" 2>/dev/null || \
        openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
            -keyout "$SSL_KEY" -out "$SSL_CERT" -subj "/CN=$SERVER_IP" 2>/dev/null
        chmod 600 "$SSL_KEY"
    fi
fi

# ── Step 5: Configure nginx (or direct gunicorn) ── #
step "Step 5/6: Configuring web server"

if [[ "$NO_NGINX" == true ]]; then
    info "Skipping nginx (--no-nginx). Gunicorn will serve directly."
    # Update systemd service for direct gunicorn with SSL
    GUNICORN_CMD="$APP_DIR/venv/bin/gunicorn --bind 0.0.0.0:$HTTPS_PORT --workers 2 --timeout 30 \
        --access-logfile $LOG_DIR/access.log --error-logfile $LOG_DIR/error.log \
        --certfile $SSL_CERT --keyfile $SSL_KEY \
        'app:create_app()'"
else
    # Generate nginx config
    NGINX_CONF="/etc/nginx/sites-available/ufw-okboy.conf"
    NGINX_CONF_DIR="$(dirname "$NGINX_CONF")"
    mkdir -p "$NGINX_CONF_DIR" /etc/nginx/sites-enabled 2>/dev/null || true
    # Fallback for RHEL-based (no sites-available)
    if [[ ! -d "$NGINX_CONF_DIR" ]]; then
        NGINX_CONF="/etc/nginx/conf.d/ufw-okboy.conf"
    fi

    info "Generating nginx config: $NGINX_CONF"

    SERVER_NAME="${DOMAIN:-_}"
    cat > "$NGINX_CONF" << NGINXEOF
# UFW OkBoy - Nginx Reverse Proxy (auto-generated by deploy.sh)
server {
    listen $HTTPS_PORT ssl http2;
    server_name $SERVER_NAME;

    ssl_certificate     $SSL_CERT;
    ssl_certificate_key $SSL_KEY;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # Rate limiting (define in http block: limit_req_zone \$binary_remote_addr zone=okboy:10m rate=3r/s;)
    # limit_req_zone \$binary_remote_addr zone=okboy:10m rate=3r/s;

    location = / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
    }

    location /static/ {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        expires 1h;
    }

    location /api/ {
        # limit_req zone=okboy burst=5 nodelay;
        proxy_set_header X-Real-IP       \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Host            \$host;
        proxy_pass http://127.0.0.1:5000;
        proxy_connect_timeout 10s;
        proxy_read_timeout    30s;
    }

    location /health {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
    }

    access_log /var/log/nginx/ufw-okboy-access.log;
    error_log  /var/log/nginx/ufw-okboy-error.log;
}
NGINXEOF

    # Enable site (Debian/Ubuntu style)
    if [[ -d /etc/nginx/sites-enabled ]]; then
        ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/ufw-okboy.conf
    fi

    # Test and reload nginx
    if nginx -t 2>/dev/null; then
        systemctl reload nginx 2>/dev/null || systemctl restart nginx
        info "Nginx configured and reloaded."
    else
        warn "Nginx config test failed. Check $NGINX_CONF"
        nginx -t
    fi

    GUNICORN_CMD="$APP_DIR/venv/bin/gunicorn --bind 127.0.0.1:5000 --workers 2 --timeout 30 \
        --access-logfile $LOG_DIR/access.log --error-logfile $LOG_DIR/error.log \
        'app:create_app()'"
fi

# ── Step 6: Install systemd services ── #
step "Step 6/6: Installing systemd services"

# Main service
cat > /etc/systemd/system/ufw-okboy.service << SVCEOF
[Unit]
Description=UFW OkBoy - Dynamic Firewall Allowlist Manager
After=network.target
Wants=network-online.target

[Service]
Type=exec
User=root
Group=root
WorkingDirectory=$APP_DIR/server
ExecStart=$GUNICORN_CMD
Restart=on-failure
RestartSec=5
NoNewPrivileges=no
ProtectSystem=full
ReadWritePaths=$DATA_DIR $LOG_DIR /run /etc/ufw /lib/ufw
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
SVCEOF

# Cleanup service
cat > /etc/systemd/system/ufw-okboy-cleanup.service << CLEANUPEOF
[Unit]
Description=UFW OkBoy - Cleanup stale firewall rules

[Service]
Type=oneshot
User=root
WorkingDirectory=$APP_DIR/server
ExecStart=$APP_DIR/venv/bin/python app.py -c config.yaml cleanup --max-age 7
CLEANUPEOF

# Cleanup timer
cat > /etc/systemd/system/ufw-okboy-cleanup.timer << TIMEREOF
[Unit]
Description=Daily cleanup of stale UFW OkBoy rules

[Timer]
OnCalendar=daily
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
TIMEREOF

systemctl daemon-reload
systemctl enable ufw-okboy >/dev/null 2>&1 || true
# restart (NOT just start): on a re-run the service is already active, so
# `enable --now` would be a no-op and keep the OLD code running. restart
# reloads the new code and runs DB migrations on startup.
systemctl restart ufw-okboy
systemctl enable --now ufw-okboy-cleanup.timer 2>/dev/null || true

info "Services installed and started."

# ── Open firewall for HTTPS ── #
ufw allow $HTTPS_PORT/tcp comment "UFW OkBoy HTTPS" 2>/dev/null || true
warn "Cloud VPS: also open port $HTTPS_PORT/tcp in your provider's security group (安全组) — UFW alone is not enough."

# ── Bootstrap first admin (BOTH interactive and -y) ── #
# An admin is REQUIRED to do anything, so create one by default — including in
# non-interactive (-y) mode, where the old script skipped this and left the
# operator with NO admin and NO credentials.
PY="$APP_DIR/venv/bin/python"
APP="$APP_DIR/server/app.py"
CONF="$APP_DIR/server/config.yaml"

if [[ -z "$ADMIN_USER" ]]; then
    if [[ "$NON_INTERACTIVE" == true ]]; then
        ADMIN_USER="admin"
    else
        echo ""
        read -rp "Create your first admin user? Enter username [admin] (or 'skip'): " ADMIN_USER
        ADMIN_USER="${ADMIN_USER:-admin}"
    fi
fi

ADMIN_SECRET=""
if [[ "$ADMIN_USER" != "skip" && "$ADMIN_USER" != "none" ]]; then
    info "Creating admin user: $ADMIN_USER"
    # Detect success by capturing the 64-hex secret it prints. A duplicate (on a
    # re-run) prints no secret, so we fall through to the manual hint instead of
    # aborting under `set -e`.
    ADMIN_OUT="$("$PY" "$APP" -c "$CONF" user-add "$ADMIN_USER" --admin 2>&1)" || true
    ADMIN_SECRET="$(printf '%s' "$ADMIN_OUT" | grep -oE '[0-9a-f]{64}' | head -n1)"
    if [[ -n "$ADMIN_SECRET" ]]; then
        echo ""
        step "管理员已创建 / Admin created — 请妥善保存（仅此一次显示）"
        echo "  用户名 / USERNAME: $ADMIN_USER"
        echo "  密钥   / SECRET:   $ADMIN_SECRET"
        echo ""
        echo "  客户端配置 (~/.config/ufw-okboy/config, knock.sh):"
        echo "    SERVER_URL=https://${DOMAIN:-$SERVER_IP}:$HTTPS_PORT"
        echo "    USERNAME=$ADMIN_USER"
        echo "    SECRET=$ADMIN_SECRET"
        if [[ -z "$DOMAIN" || "$FORCE_SELF_SIGNED" == true ]]; then
            echo "    INSECURE=1   # self-signed cert: skip TLS verification"
        fi
    else
        warn "Admin '$ADMIN_USER' was not created (it may already exist)."
        warn "Create one manually:  $PY $APP -c $CONF user-add <name> --admin"
        warn "Rotate an existing user's secret:  $PY $APP -c $CONF revoke <name>"
    fi
fi

# ── Summary ── #
echo ""
step "Installation Complete!"
echo ""
echo "  App directory:  $APP_DIR"
echo "  Config file:     $APP_DIR/server/config.yaml"
echo "  Database:        $DATA_DIR/ufw-okboy.db"
echo "  Logs:            $LOG_DIR/"
echo ""
if [[ -n "$DOMAIN" && "$FORCE_SELF_SIGNED" == false ]]; then
    echo "  Access URL:      https://$DOMAIN"
else
    echo "  Access URL:      https://$SERVER_IP:$HTTPS_PORT"
    warn "  Self-signed cert: the browser shows a one-time warning — click through / add an exception."
    warn "  CLI clients: set verify_ssl: false (knock.py) or INSECURE=1 (knock.sh) for self-signed."
fi
echo ""
echo "  Management commands (run from any directory):"
echo "    $PY $APP -c $CONF user-add <name> --admin     # 创建另一个管理员"
echo "    $PY $APP -c $CONF user-list"
echo "    $PY $APP -c $CONF group-add <name> <port>"
echo "    $PY $APP -c $CONF user-join <user> <group>"
echo "    $PY $APP -c $CONF revoke <name>               # 轮换某用户密钥（旧凭据失效）"
echo ""
echo "  Service status:  systemctl status ufw-okboy"
echo "  View logs:       journalctl -u ufw-okboy -f"
echo ""
echo "  Next steps:"
echo "    1. Open the Access URL in your browser"
echo "    2. Login with your admin credentials"
echo "    3. Create user groups and add users"
echo ""
