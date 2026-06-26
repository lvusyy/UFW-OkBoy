# UFW OkBoy

**Dynamic firewall allowlist manager** — authenticated clients automatically register their IP in UFW, swap rules seamlessly on IP change, and keep the firewall clean and traceable.

English | [中文](README.md)

<p align="center">
  <img src="docs/web-client.png" alt="Web client interface" width="380">
</p>

---

## What's New in v2.2.1

> ⚠️ **Use v2.2.1, not v2.2.0**: v2.2.0 could lock you out — it enabled UFW before allowing SSH. v2.2.1 fixes this.

| Item | Description |
|------|-------------|
| **SSH lock-out fix (critical)** | Install now **allows SSH before enabling UFW**, and auto-detects the real SSH port from `sshd_config` (including `sshd_config.d/*.conf` and custom ports) so the operator can't be locked out |
| **Admin manages system UFW rules (high-risk)** | New "Advanced (high-risk)" console panel lists/deletes **all** UFW rules (including ones not created by this tool); deletion is gated generic-confirm → SSH double-confirm → TOTP, audit-logged, and returns the refreshed list (numbers shift after a delete) |
| **Exposure reminder** | Rules that look like SSH and are open to `Anywhere` are flagged, nudging you to restrict the source to a group instead of the whole internet |
| **Simpler bootstrap** | Install creates `admin` directly and **prints the token highlighted** at the very end; the console supports **self-service secret rotation** — no reinstall needed |
| **Re-install no longer aborts** | Fixed the installer aborting under `set -e` on re-run (command substitutions now tolerate empty matches) |

## What's New in v2.2

| Feature | Description |
|---------|-------------|
| **China-friendly install** | Offline package (bundled manylinux wheels — zero-network dep install); automatic PyPI mirror fallback (`--mirror` to override); GitHub mirror `--gh-mirror`; public-IP auto-detection for the self-signed cert SAN (`--ip` to override); self-signed + IP + any high port as the default path — **no filed domain needed**; 10-year self-signed cert. See [国内部署专题](GUIDE.md#国内部署专题) |
| **Self-signed-friendly clients** | `knock.sh` supports `-k`/`INSECURE`; `knock.py` honors `verify_ssl: false`; fixed an install-client config-format bug that silently broke auto-knock |
| **Admin console robustness** | Fixed the "Unexpected token '<'" crash after copying a token (root cause: nginx rate-limit returning an HTML error page); safe non-JSON parsing + idempotent-GET backoff on the client; strict JSON error contract for all `/api` paths |
| **Deeper hardening** | step-up coverage completed (admin toggling another user's membership); TOTP disable/re-enroll now replay-protected; username/group + port validation; generic login error to prevent user enumeration |
| **Stability** | reconcile tolerates a single failed ufw rule (stale cleanup still runs); DB switched to thread-local connections; credentials persisted only after the first knock validates them |

## v2.1.1 Security Fixes

| Fix | Description |
|-----|-------------|
| **Privilege escalation closed** | Admin writes (create user/group, membership add/remove) lacked step-up; a stolen admin secret (no TOTP) could bypass the gate and mint a new admin. All admin writes now go through step-up. |
| **2FA takeover prevented** | Re-enrolling TOTP requires a current code, so a leaked session can't overwrite/disable an admin's 2FA. |
| **IP spoofing hardened** | `X-Forwarded-For` now uses the rightmost hop (what the trusted proxy actually saw); a client can't forge the leftmost entry to register an arbitrary IP. |
| **TOTP replay protection** | A consumed code is rejected on reuse within its window (RFC 6238 §5.2); failed step-ups count toward the IP throttle. Toggle with `totp_replay_protection`. |

## What's New in v2.1

| Feature | Description |
|---------|-------------|
| **Admin web console** | In-browser user/group/rule CRUD, membership management, promote, revoke, audit log, self-service TOTP — no CLI required |
| **Bilingual UI (i18n)** | 中文 / English toggle across the web client and admin console |
| **Search + pagination** | Filter and paginate users/groups; mobile layout; one-click secret copy |
| **Per-IP abuse throttle** | Too many failed auths from one IP → HTTP 429 (keyed on IP, not username, to avoid locking out legit users) |
| **Force-offline + re-auth** | `revoke`: close ports + clear runtime state + rotate the secret so old credentials die instantly |
| **Admin TOTP step-up** | Sensitive admin actions require a 6-digit code (RFC 6238); see v2.1.1 above for full coverage + replay protection |
| **Audit log** | Every admin action recorded; view in the console or via `GET /api/admin/audit` |
| **Backup / restore** | Online SQLite backup API + SHA-256 checksum + rolling retention |
| **Versioned DB migrations** | A `schema_version` table + migration registry upgrade in place without data loss |
| **Anti-IP-spoofing (H-9)** | X-Real-IP / X-Forwarded-For trusted only from `trusted_proxies` |
| **One-click upgrade** | `deploy/upgrade.sh`: backup → pull → migrate → restart → health-check → auto-rollback |
| **Port uniqueness** | One group per (port, proto); duplicates rejected |

## Why

Your server's sensitive ports (admin panels, databases, APIs) sit behind UFW rules that allow only specific IPs. But client IPs change — switching WiFi, traveling, restarting routers — and every change means bothering the admin to edit the firewall by hand.

**UFW OkBoy automates this**: users authenticate through a web page once, and the server updates the firewall. When the IP changes, the next heartbeat swaps the rule seamlessly.

## How It Works

```
Client (Browser / Python / Shell)
    |
    | HTTPS + HMAC-SHA256 signed auth
    v
Nginx (reverse proxy, TLS, passes the real IP)
    |
    v
Flask API (verify identity, extract client IP, look up groups)
    |
    v
UFW (remove old rule → add new rule → comment: ufw-okboy:<user>:<group>)
    |
    v
SQLite (users / groups / membership / audit_log)
```

## Core Features

| Feature | Description |
|---------|-------------|
| **Web client** | Open in browser, auto-knocks every 30s, auto-reconnects on reopen. Mobile friendly |
| **Clean rules** | One rule per user per port, old IP auto-replaced on change, no stale entries |
| **Traceable rules** | Each UFW rule tagged `ufw-okboy:<user>:<group>`, visible in `ufw status` |
| **Group management** | Admins create groups, bind ports, and manage members via CLI / API / console |
| **Anti-sharing** | One IP per account — sharing credentials means mutual kicking; anomaly alerts on suspicious switching |
| **Auto-cleanup** | Rules for users inactive 7+ days purged by a daily timer |
| **Secure auth** | HMAC-SHA256 + timestamp, secret never transmitted, HTTPS, failed attempts recorded |
| **Three clients** | Web UI / Python script / Shell script (curl + openssl, zero deps) |

## One-Click Install

**Server (one line):**

```bash
# Self-signed cert (no domain, access via IP:port)
curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/quick-install.sh | bash -s -- --self-signed -y

# Domain mode (automatic Let's Encrypt)
curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/quick-install.sh | bash -s -- --domain your.server.com -y
```

**Client (one line):**

```bash
curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/install-client.sh | bash -s -- --server https://your-server --user alice --secret YOUR_SECRET
```

**One-click upgrade (installed server, restarts the service):**

```bash
curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/upgrade.sh | bash
```

> Backs up the DB + snapshots old code first; restarts and health-checks after updating, with auto-rollback on failure. Preserves config / nginx / SSL / database. Hard-refresh the browser (Ctrl-Shift-R) to load the new UI.

## Offline / Restricted Networks

For servers where GitHub/PyPI are slow or blocked (e.g. mainland China — see the
fuller 国内部署专题 in [GUIDE.md](GUIDE.md)):

```bash
# Most reliable: offline package — bundles Python wheels, only one tarball to fetch.
bash deploy/build-release.sh                       # on an online machine → dist/*.tar.gz
tar xzf ufw-okboy-*.tar.gz && cd ufw-okboy-*
sudo bash install.sh --self-signed --port 8443 -y  # auto-detects vendor/ for offline pip

# Online with mirrors:
#   --gh-mirror <proxy>   GitHub proxy prefix, e.g. https://ghfast.top
#                         (proxies expire often — find a current one at https://ghproxy.link/)
#   --mirror <url>        PyPI index (else a CN mirror is used automatically when pypi.org is down)
#   --ip <addr>           Public IP for the self-signed cert SAN (NAT'd cloud VPS)
```

No domain needed: the default self-signed path uses your **public IP** (10-year cert).
CLI clients trust it via `verify_ssl: false` (knock.py) or `INSECURE=1` (knock.sh).
Open the port in your cloud **security group** too — UFW alone is not enough.

## Manual Install

```bash
git clone https://github.com/lvusyy/UFW-OkBoy.git /opt/ufw-okboy
cd /opt/ufw-okboy

# Option 1: deploy script (recommended)
bash deploy/deploy.sh --self-signed -y

# Option 2: manual
python3 -m venv venv && venv/bin/pip install -r server/requirements.txt
cd server
../venv/bin/python app.py user-add admin --admin    # create the first admin
cp config.example.yaml config.yaml                  # edit config
sudo ../venv/bin/python app.py serve --debug         # start
```

**Management commands:**

```bash
python app.py user-add alice --admin     # add a user (admin)
python app.py user-list                  # list users
python app.py group-add ssh 22           # create a group (port 22)
python app.py user-join alice ssh        # add user to group
python app.py revoke alice               # force offline + rotate secret
python app.py backup                     # checksummed online DB backup
python app.py upgrade --check            # check GitHub for a newer release
```

**Client:**

Open `https://your-server.com/` in a browser → enter username and secret → click **Connect** → done.

## Documentation

See **[GUIDE.md](GUIDE.md)** (Chinese) for the complete deployment and usage guide: server deployment (UFW / Nginx / Systemd), key generation and distribution, client usage (Web / Python / Shell), group & port management, daily operations, security mechanisms, and FAQ.

## Project Structure

```
server/
  app.py              Flask API + CLI (serve / user-add / group-add / revoke / backup / upgrade / ...)
  ufw_ops.py          UFW operations + reconcile + state
  db.py               SQLite layer (6 tables + schema_version + migrations)
  auth.py             HMAC-SHA256 auth + admin/group checks + TOTP
  static/index.html   Web client + admin console + PIN vault (single-file SPA)
  config.example.yaml Server config template
  requirements.txt    Dependencies
  tests/              Unit tests (145 tests)
client/
  knock.py            Python client (stdlib only)
  knock.sh            Shell client (curl + openssl)
  config.example.yaml Client config template
nginx/
  ufw-okboy.conf      Nginx reverse proxy config
deploy/
  deploy.sh           One-click multi-distro deploy (self-signed / Let's Encrypt)
  quick-install.sh    curl | bash one-liner
  upgrade.sh          One-click upgrade (backup → migrate → restart → rollback)
  build-release.sh    Release builder (reads VERSION)
  ufw-okboy.service   Systemd service (Gunicorn)
  ufw-okboy-cleanup.* Stale-rule cleanup timer
  knock.*             Client auto-knock timer
VERSION               Single source of truth for the version
```

## License

MIT
