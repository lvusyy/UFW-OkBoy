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
#   --port <port>       HTTPS port (default: 443)
#   --no-nginx          Skip nginx setup (use gunicorn directly with self-signed)
#   --self-signed       Force self-signed cert even if domain provided
#   --app-dir <path>    Install directory (default: /opt/ufw-okboy)
#   -y, --yes           Non-interactive mode (skip all prompts)

set -euo pipefail

# ── Defaults ── #
APP_DIR="/opt/ufw-okboy"
DATA_DIR="/var/lib/ufw-okboy"
LOG_DIR="/var/log/ufw-okboy"
HTTPS_PORT=443
DOMAIN=""
FORCE_SELF_SIGNED=false
NO_NGINX=false
NON_INTERACTIVE=false
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

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

# ── Parse args ── #
while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain)       DOMAIN="$2"; shift 2 ;;
        --port)         HTTPS_PORT="$2"; shift 2 ;;
        --no-nginx)     NO_NGINX=true; shift ;;
        --self-signed)  FORCE_SELF_SIGNED=true; shift ;;
        --app-dir)      APP_DIR="$2"; shift 2 ;;
        -y|--yes)       NON_INTERACTIVE=true; shift ;;
        -h|--help)
            head -20 "$0"
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
else
    error "Cannot find application files. Run from repository root or use curl install."
    exit 1
fi

# Create virtual environment
info "Setting up Python virtual environment..."
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --upgrade pip --quiet
"$APP_DIR/venv/bin/pip" install -r "$APP_DIR/server/requirements.txt" --quiet

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
    # Self-signed certificate
    info "Generating self-signed certificate..."
    SSL_DIR="/etc/ssl/ufw-okboy"
    mkdir -p "$SSL_DIR"
    SSL_CERT="$SSL_DIR/selfsigned.crt"
    SSL_KEY="$SSL_DIR/selfsigned.key"

    # Determine server IP for cert
    SERVER_IP=$(hostname -I | awk '{print $1}')
    if [[ -z "$SERVER_IP" ]]; then
        SERVER_IP="127.0.0.1"
    fi

    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$SSL_KEY" \
        -out "$SSL_CERT" \
        -subj "/CN=$SERVER_IP" \
        -addext "subjectAltName=IP:$SERVER_IP" 2>/dev/null || \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$SSL_KEY" \
        -out "$SSL_CERT" \
        -subj "/CN=$SERVER_IP" 2>/dev/null

    chmod 600 "$SSL_KEY"
    info "Self-signed cert: $SSL_CERT"
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
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$SSL_KEY" -out "$SSL_CERT" -subj "/CN=localhost" 2>/dev/null
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
systemctl enable --now ufw-okboy
systemctl enable --now ufw-okboy-cleanup.timer

info "Services installed and started."

# ── Open firewall for HTTPS ── #
ufw allow $HTTPS_PORT/tcp comment "UFW OkBoy HTTPS" 2>/dev/null || true

# ── Bootstrap first admin (interactive) ── #
if [[ "$NON_INTERACTIVE" == false ]]; then
    echo ""
    read -rp "Create your first admin user? Enter username (or skip): " ADMIN_USER
    if [[ -n "$ADMIN_USER" && "$ADMIN_USER" != "skip" ]]; then
        info "Creating admin user: $ADMIN_USER"
        "$APP_DIR/venv/bin/python" "$APP_DIR/server/app.py" -c "$APP_DIR/server/config.yaml" user-add "$ADMIN_USER" --admin
        echo ""
        warn "Save the secret above! You'll need it for the client config."
        warn "Client config file format:"
        echo "  SERVER_URL=https://${DOMAIN:-$SERVER_IP}:$HTTPS_PORT"
        echo "  USERNAME=$ADMIN_USER"
        echo "  SECRET=<the-secret-printed-above>"
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
    warn "  Self-signed cert: browsers will show a security warning."
    warn "  Add exception or use --no-verify-ssl on clients."
fi
echo ""
echo "  Management commands:"
echo "    $APP_DIR/venv/bin/python $APP_DIR/server/app.py user-list"
echo "    $APP_DIR/venv/bin/python $APP_DIR/server/app.py group-add <name> <port>"
echo "    $APP_DIR/venv/bin/python $APP_DIR/server/app.py user-join <user> <group>"
echo ""
echo "  Service status:  systemctl status ufw-okboy"
echo "  View logs:       journalctl -u ufw-okboy -f"
echo ""
echo "  Next steps:"
echo "    1. Open the Access URL in your browser"
echo "    2. Login with your admin credentials"
echo "    3. Create user groups and add users"
echo ""
