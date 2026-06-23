# UFW OkBoy - Dynamic Firewall Allowlist Manager

## Project Overview

A lightweight system that allows authorized clients to automatically register their IP addresses
in the server's UFW firewall allowlist. Designed for scenarios where client IPs change frequently
and manual allowlist management is impractical.

## Architecture

```
Client (Web UI / knock.py / knock.sh)
    |
    | HTTPS (port 443)
    v
Nginx (reverse proxy, TLS termination, passes X-Real-IP)
    |
    | HTTP (127.0.0.1:5000)
    v
Flask API (app.py) + Web Client (static/index.html)
    |
    | subprocess
    v
UFW Firewall (ufw_ops.py)
    |
    v
State Store (/var/lib/ufw-okboy/state.json)
```

### Client Options

1. **Web UI (recommended)**: Open `https://your-server/` in a browser. Login once,
   page auto-knocks every 30 seconds. Credentials saved to localStorage for
   automatic reconnection on page reopen. Works on mobile.
2. **Python client**: `knock.py` with `--watch 30` for headless servers.
3. **Shell client**: `knock.sh` (curl + openssl only, zero dependencies).

## Authentication Protocol

HMAC-SHA256 with timestamp, sent via `Authorization` header:

```
Authorization: HMAC-SHA256 <username>:<timestamp>:<signature>
signature = HMAC-SHA256(secret, "<username>:<timestamp>")
```

- Secret never transmitted over the wire
- Timestamp window: 300 seconds (configurable)
- HTTPS provides transport-layer encryption

## Key Design Decisions

- **One UFW rule per user per group per port**: old IP removed before adding new IP
- **UFW comment format**: `ufw-okboy:<username>:<group>` for traceability + precise deletion
- **SQLite is the single source of truth**: users/groups/membership/logs in DB (WAL); legacy JSON state one-time migrated
- **Idempotent reconcile**: knock heartbeat reconciles UFW rules against enabled groups every 30s (self-heals join/leave/concurrent-change/stale-old-IP) — no DB locks needed
- **Server-side authorization re-validation**: self-toggle may only re-enable previously-authorized groups; new grants require admin; optional `allowed_ports` whitelist
- **Versioned DB migrations**: `schema_version` table + `MIGRATIONS` registry; `init()` runs pending migrations; forward-compatible, no data drop
- **Manual upgrades only**: root service never auto-pulls code; `upgrade --check` notifies, `--force` upgrades with DB backup + health-check + auto-rollback
- **Server runs as root**: required for UFW management
- **Gunicorn for production**: Flask dev server only for testing

## Directory Structure

```
server/
  app.py              - Flask API + CLI management commands + upgrade command
  ufw_ops.py          - UFW firewall operations + reconcile + state management
  db.py               - SQLite layer (6 tables + schema_version + migrations)
  auth.py             - HMAC-SHA256 auth + admin/group-access checks
  static/index.html   - Web client UI + admin console + PIN vault (single SPA)
  config.example.yaml - Server configuration template
  requirements.txt    - Python dependencies (Flask, PyYAML, Gunicorn)
  tests/              - Unit tests (db/auth/admin_api/ip_lifecycle)
VERSION               - Single source of truth for version (read by app/build)
client/
  knock.py            - Python client (requires: pyyaml)
  knock.sh            - Shell client (zero dependencies, uses curl + openssl)
  config.example.yaml - Client configuration template
nginx/
  ufw-okboy.conf      - Nginx reverse proxy configuration example
deploy/
  deploy.sh           - One-click multi-distro deployment (SSL + nginx + systemd)
  install-server.sh   - Lightweight standalone install entry
  build-release.sh    - Release package builder (reads VERSION)
  quick-install.sh    - curl|bash one-liner
  ufw-okboy.service   - Systemd service for server
  ufw-okboy-cleanup.service - Systemd service for stale rule cleanup
  ufw-okboy-cleanup.timer   - Systemd timer for daily cleanup
  knock.service       - Systemd service for client auto-knock
  knock.timer         - Systemd timer for client periodic knock
```

## CLI Commands (Server)

```bash
python app.py --version                # Show version
python app.py serve                    # Start API server
python app.py serve --debug            # Start in debug mode
python app.py gen-secret [username]    # Generate a user secret
python app.py list                     # List managed users and rules
python app.py cleanup --max-age 7     # Remove rules older than 7 days
python app.py user-add <name> [--admin]  # Create a user (DB-backed)
python app.py user-del <name>            # Delete a user + clean UFW
python app.py user-list                 # List users
python app.py group-add <name> <port>   # Create a port group
python app.py group-del <name>          # Delete a group + clean UFW
python app.py user-join <user> <group>  # Add user to group (immediate UFW sync)
python app.py user-leave <user> <group> # Remove user from group
python app.py admin-add <user>          # Grant admin privileges
python app.py upgrade --check           # Check GitHub for newer release (notify only)
python app.py upgrade --force           # Manually upgrade (backup→pull→migrate→restart→health-check→rollback)
```

## Development

- Python 3.8+
- Server dependencies: `pip install -r server/requirements.txt`
- Client dependencies: `pip install pyyaml` (or use knock.sh for zero deps)
- Server requires root privileges for UFW management
- Test locally with `python app.py serve --debug`
