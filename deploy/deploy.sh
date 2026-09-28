#!/usr/bin/env bash
# UFW OkBoy - One-Click Deployment Script
# Supports: Ubuntu/Debian (apt), CentOS/RHEL/Fedora (dnf/yum)
# SSL modes: domain → Let's Encrypt, no domain → self-signed (IP:port)
#
# Usage (from a checkout or an unpacked release package, as root):
#   bash deploy/deploy.sh [--domain your.domain.com] [--port 443] [--no-nginx]
# One-liner without a checkout: deploy/quick-install.sh fetches the source and
# runs this script with the same flags.
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
#   --admin-user <name> Admin user to create after install (default: admin)
#   --app-dir <path>    Install directory (default: /opt/ufw-okboy)
#   -y, --yes           Accepted for scripted runs (the installer never prompts)

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
    BOLD='\033[1m'
    HILITE='\033[1;30;103m'   # bold black on bright-yellow — a highlighter for the secret
    NC='\033[0m'
else
    GREEN=''; YELLOW=''; RED=''; CYAN=''; BOLD=''; HILITE=''; NC=''
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
        # `|| true`: a failed/blocked echo service must not abort under set -e —
        # just try the next one, then fall back to the local NIC IP.
        ip="$(curl -fsS --max-time 4 "$svc" 2>/dev/null | tr -d '[:space:]' || true)"
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then echo "$ip"; return; fi
    done
    ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
    [[ -n "$ip" ]] && warn "Public IP auto-detect failed; using local IP $ip (pass --ip on a NAT'd VPS)." >&2
    echo "${ip:-127.0.0.1}"
}

# Self-signed certificate for $SERVER_IP into $SSL_CERT / $SSL_KEY (10 years:
# a 1-year self-signed cert would silently expire and break every knock). An
# existing key is reused, so a re-run renews the certificate but keeps the
# public key that clients pin (pin_sha256); remove the key to get a new one.
make_self_signed() {
    local key=(-newkey rsa:2048 -keyout "$SSL_KEY")
    if [[ -s "$SSL_KEY" ]] && openssl pkey -in "$SSL_KEY" -noout 2>/dev/null; then
        key=(-key "$SSL_KEY")
        info "Keeping the existing key $SSL_KEY (clients that pin it keep working)"
    fi
    openssl req -x509 -nodes -days 3650 "${key[@]}" -out "$SSL_CERT" \
        -subj "/CN=$SERVER_IP" -addext "subjectAltName=IP:$SERVER_IP" 2>/dev/null || \
    openssl req -x509 -nodes -days 3650 "${key[@]}" -out "$SSL_CERT" \
        -subj "/CN=$SERVER_IP" 2>/dev/null
    chmod 600 "$SSL_KEY"
}

# The certificate's public-key pin: base64(SHA-256(SubjectPublicKeyInfo)), the
# pin_sha256 / PIN_SHA256 of the clients (curl --pinnedpubkey sha256//...).
spki_pin() {
    openssl x509 -in "$1" -pubkey -noout | openssl pkey -pubin -outform der |
        openssl dgst -sha256 -binary | base64
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
        -y|--yes)       shift ;;   # nothing prompts; accepted for scripted runs
        -h|--help)
            awk 'NR > 1 && !/^#/ {exit} NR > 1 {sub(/^# ?/, ""); print}' "$0"
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
# The systemd units get --app-dir verbatim: keep it to a plain absolute path.
if [[ ! "$APP_DIR" =~ ^/[A-Za-z0-9._/-]+$ ]]; then
    error "--app-dir must be an absolute path of letters, digits, '.', '_', '-' and '/'."
    exit 1
fi

# ── Detect distribution ── #
detect_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        DISTRO_ID="$ID"
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
            # Packaged next to an older default python3 on RHEL-family 8/9
            # and Amazon Linux 2023 (see select_python below).
            PYTHON_ALT_VERSIONS="3.12 3.11"
            CERTBOT_PKG="certbot python3-certbot-nginx"
            UFW_PKG="ufw"
            # EPEL needed for ufw on RHEL-based. RHEL itself has no
            # epel-release package in its repositories: install it by URL.
            if [[ "$DISTRO_ID" == "rhel" ]]; then
                EPEL_PKG="https://dl.fedoraproject.org/pub/epel/epel-release-latest-${DISTRO_VERSION%%.*}.noarch.rpm"
            elif [[ "$DISTRO_ID" != "fedora" ]]; then
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

# The server needs Python 3.10+ able to create a venv with pip (Debian and
# Ubuntu ship ensurepip separately, in python3-venv / python3.X-venv). Use the
# distro's python3 when it qualifies, else a newer packaged one (installing it
# where the distro has it). Decided here, before UFW is touched.
find_python() {
    local c
    for c in python3 python3.14 python3.13 python3.12 python3.11 python3.10; do
        command -v "$c" >/dev/null 2>&1 || continue
        if "$c" -c 'import sys, ensurepip; sys.exit(sys.version_info < (3, 10))' 2>/dev/null; then
            command -v "$c"
            return 0
        fi
    done
    return 1
}
PYTHON="$(find_python || true)"
if [[ -z "$PYTHON" ]]; then
    for _v in ${PYTHON_ALT_VERSIONS:-}; do
        info "python3 is older than 3.10; installing python$_v..."
        if $PKG_INSTALL "python$_v" "python$_v-pip"; then break; fi
    done
    PYTHON="$(find_python || true)"
fi
if [[ -z "$PYTHON" ]]; then
    error "Python 3.10 or newer with venv support is required (found: $(python3 --version 2>&1 || echo none))."
    error "Ubuntu 22.04+, Debian 12+ and Fedora ship it; elsewhere install python3.10+ (and its -venv package on Debian/Ubuntu) first, then re-run."
    exit 1
fi
info "Using $("$PYTHON" --version 2>&1) ($PYTHON)"

# CRITICAL: allow SSH BEFORE enabling UFW. `ufw enable` sets the default
# incoming policy to DENY; without an SSH allow rule first, enabling UFW locks the
# operator out of their own server over port 22. Allow the sshd port(s) from
# sshd_config (default 22), the CURRENT SSH session's port (covers non-standard
# ports), and the OpenSSH app profile — belt and suspenders.
# Only when UFW is not active yet: on a re-run the SSH rules are whatever the
# operator made them — typically SSH closed to all but knock-authorized IPs —
# and re-adding "allow from anywhere" would silently reopen it.
# ufw translates its status line: read it in the C locale. Anything but a
# clear "inactive" or "active" stops here — guessing wrong reopens SSH.
UFW_STATUS="$(LC_ALL=C LANGUAGE=C ufw status 2>&1)" || { error "'ufw status' failed: $UFW_STATUS"; exit 1; }
case "$UFW_STATUS" in
    "Status: inactive"*|"Status: active"*) ;;
    *) error "Unexpected 'ufw status' output: $UFW_STATUS"; exit 1 ;;
esac
if [[ "$UFW_STATUS" == "Status: inactive"* ]]; then
    SSH_PORTS="$(awk '/^[[:space:]]*[Pp]ort[[:space:]]+[0-9]+/{print $2}' /etc/ssh/sshd_config 2>/dev/null)"
    [[ -z "$SSH_PORTS" ]] && SSH_PORTS="22"
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
        CUR_SSH_PORT="$(awk '{print $4}' <<<"$SSH_CONNECTION")"
        [[ -n "$CUR_SSH_PORT" ]] && SSH_PORTS="$SSH_PORTS $CUR_SSH_PORT"
    fi
    for _p in $SSH_PORTS; do
        ufw allow "$_p/tcp" comment "SSH (auto-allowed by ufw-okboy installer)" 2>/dev/null || true
    done
    ufw allow OpenSSH 2>/dev/null || true
    info "Allowed SSH (ports: $SSH_PORTS) before enabling UFW — avoids lockout."
else
    info "UFW is already active: its SSH rules are left as they are."
fi

# Ensure ufw is enabled
if [[ "$UFW_STATUS" == "Status: inactive"* ]]; then
    warn "UFW is not active. Enabling UFW (SSH already allowed above)..."
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

# Copy from the source tree, unless it is the install dir itself: a git
# checkout at $APP_DIR (the layout `app.py upgrade` updates with git pull).
if [[ -f "$REPO_DIR/server/app.py" && "$(cd "$REPO_DIR" && pwd -P)" == "$(cd "$APP_DIR" && pwd -P)" ]]; then
    info "Installing in place: $APP_DIR is the source checkout."
elif [[ -f "$REPO_DIR/server/app.py" ]]; then
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
# A venv made by an older interpreter keeps it: `python -m venv` does not
# replace an existing bin/python. Rebuild it then (the dependencies follow).
VENV_ARGS=()
if [[ -e "$APP_DIR/venv/bin/python" || -L "$APP_DIR/venv/bin/python" ]] \
        && ! "$APP_DIR/venv/bin/python" -c 'import sys; sys.exit(sys.version_info < (3, 10))' 2>/dev/null; then
    warn "Rebuilding $APP_DIR/venv: its interpreter is older than 3.10 or no longer runs."
    VENV_ARGS=(--clear)
fi
"$PYTHON" -m venv ${VENV_ARGS[@]+"${VENV_ARGS[@]}"} "$APP_DIR/venv"
pip_install --upgrade pip --quiet || warn "pip self-upgrade skipped (non-fatal)."
pip_install -r "$APP_DIR/server/requirements.txt" --quiet

# Config file
if [[ ! -f "$APP_DIR/server/config.yaml" ]]; then
    cp "$APP_DIR/server/config.example.yaml" "$APP_DIR/server/config.yaml"
    info "Config created: $APP_DIR/server/config.yaml"
    info "The defaults work as they are; an admin user is created at the end of this run."
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
    # UI adds a browser exception after checking the fingerprint; CLI clients
    # pin its public key (pin_sha256 / PIN_SHA256).
    info "Generating self-signed certificate (no domain → IP-based HTTPS)..."
    SSL_DIR="/etc/ssl/ufw-okboy"
    mkdir -p "$SSL_DIR"
    SSL_CERT="$SSL_DIR/selfsigned.crt"
    SSL_KEY="$SSL_DIR/selfsigned.key"

    # Public IP for the cert SAN (NOT hostname -I, which is the private NIC on a
    # cloud VPS and would never match the address users connect to).
    SERVER_IP="$(detect_public_ip)"

    make_self_signed
    info "Self-signed cert: $SSL_CERT  (CN/SAN: $SERVER_IP, valid 10y)"
    info "Access via: https://$SERVER_IP:$HTTPS_PORT"
else
    # Let's Encrypt via certbot. The HTTP-01 check (and every renewal) comes in
    # on port 80 and is answered by nginx; `certonly` only obtains the
    # certificate, the site itself is configured below.
    info "Requesting Let's Encrypt certificate for: $DOMAIN"
    ufw allow 80/tcp comment "UFW OkBoy: Let's Encrypt HTTP-01" >/dev/null 2>&1 || true
    systemctl enable --now nginx >/dev/null 2>&1 || true
    if [[ "$NO_NGINX" == true ]]; then
        RENEW_HOOK="systemctl restart ufw-okboy"   # gunicorn serves the certificate itself
    else
        RENEW_HOOK="systemctl reload nginx"
    fi
    if certbot certonly --nginx -d "$DOMAIN" --non-interactive --agree-tos \
            --register-unsafely-without-email --deploy-hook "$RENEW_HOOK"; then
        SSL_CERT="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
        SSL_KEY="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
        info "Let's Encrypt cert installed for: $DOMAIN"
        # Renewals run from certbot's timer: Debian/Ubuntu enable certbot.timer
        # on install, the RHEL family ships certbot-renew.timer disabled.
        systemctl enable --now certbot-renew.timer >/dev/null 2>&1 || systemctl enable --now certbot.timer >/dev/null 2>&1 || true
    else
        warn "Certbot failed, falling back to self-signed..."
        FORCE_SELF_SIGNED=true
        SSL_DIR="/etc/ssl/ufw-okboy"
        mkdir -p "$SSL_DIR"
        SSL_CERT="$SSL_DIR/selfsigned.crt"
        SSL_KEY="$SSL_DIR/selfsigned.key"
        SERVER_IP="$(detect_public_ip)"
        make_self_signed
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
    # Generate nginx config where this nginx reads it: Debian/Ubuntu include
    # sites-enabled/, the RHEL family only conf.d/.
    if grep -qs 'sites-enabled' /etc/nginx/nginx.conf; then
        NGINX_CONF="/etc/nginx/sites-available/ufw-okboy.conf"
        mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled
    else
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
    if [[ "$NGINX_CONF" == /etc/nginx/sites-available/* ]]; then
        ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/ufw-okboy.conf
    fi

    # Test and reload nginx; start it at boot (the RHEL family does not by default)
    if nginx -t 2>/dev/null; then
        systemctl enable nginx >/dev/null 2>&1 || true
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
UMask=0077

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
UMask=0077
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

# ── Bootstrap admin (always, both modes) ── #
# Create one admin here; its credentials are printed at the VERY END (last on
# screen, highlighted) so the token can't scroll out of view. Default user
# "admin" (override with --admin-user). Re-runs are harmless (duplicate → no token).
PY="$APP_DIR/venv/bin/python"
APP="$APP_DIR/server/app.py"
CONF="$APP_DIR/server/config.yaml"
ADMIN_USER="${ADMIN_USER:-admin}"

info "Creating admin user: $ADMIN_USER"
ADMIN_OUT="$("$PY" "$APP" -c "$CONF" user-add "$ADMIN_USER" --admin 2>&1)" || true
# `|| true`: on a re-run the user already exists, grep finds no token and exits
# non-zero — without this, `set -e`+pipefail would abort the whole script right
# here (before the summary), leaving the operator confused even though the server
# is fully installed.
ADMIN_SECRET="$(printf '%s' "$ADMIN_OUT" | grep -oE '[0-9a-f]{64}' | head -n1 || true)"

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
    warn "  Self-signed cert: the browser warns. Continue only if it shows this SHA-256 fingerprint:"
    warn "    $(openssl x509 -in "$SSL_CERT" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)"
    echo "  Client key pin:  $(spki_pin "$SSL_CERT")"
    echo "    (clients trust this server by it: pin_sha256 in knock.py / knock.ps1 configs,"
    echo "     PIN_SHA256 for knock.sh, --pin-sha256 / -PinSha256 for the client installers)"
fi
echo ""
if [[ -n "${SSH_PORTS:-}" ]]; then
    echo "  Firewall:        UFW active; SSH ($SSH_PORTS) + $HTTPS_PORT/tcp allowed."
else
    echo "  Firewall:        UFW active; $HTTPS_PORT/tcp allowed, SSH rules left as they were."
fi
warn "  Keep the SSH rule — removing it (or letting the tool manage port 22) can lock you out."
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
echo "    2. Login with your admin credentials (shown below)"
echo "    3. Create user groups and add users"
echo ""

# ── Admin credentials — printed LAST and HIGHLIGHTED so the token can't be missed ── #
echo ""
if [[ -n "$ADMIN_SECRET" ]]; then
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
    echo -e "  ${BOLD}管理员凭据 / ADMIN LOGIN — 请立即复制保存（仅此一次显示）${NC}"
    echo ""
    echo -e "    用户名 USERNAME:  ${BOLD}$ADMIN_USER${NC}"
    echo -e "    密钥   SECRET:    ${HILITE} $ADMIN_SECRET ${NC}"
    echo ""
    echo -e "  登录网页后，可在管理台自己那一行点「更换密钥」随时轮换。"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
else
    warn "管理员 '$ADMIN_USER' 已存在；如需更换密钥，登录网页管理台点「更换密钥」。"
fi
echo ""
