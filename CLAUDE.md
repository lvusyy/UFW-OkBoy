# UFW OkBoy - Dynamic Firewall Allowlist Manager

## Project Overview

A lightweight system that lets authorized clients register their current IP address in the
server's UFW allowlist ("knocking"). Users belong to port groups; a knock opens the user's
enabled group ports for the calling IP and closes those of the previous IP. Designed for
clients whose IPs change often, where manual allowlist management is impractical.

## Architecture

```text
Client (Web UI / knock.py / knock.sh / knock.ps1)
    |
    | HTTPS (443 or --port); Authorization: HMAC-SHA256 <user>:<ts>:<sig>
    v
Nginx (TLS termination, passes X-Real-IP / X-Forwarded-For)
    |          (--no-nginx installs: gunicorn serves TLS itself on 0.0.0.0:<port>)
    | HTTP 127.0.0.1:5000
    v
Gunicorn, 2 workers: "app:create_app()" (cwd server/, reads config.yaml at startup)
    |-- Flask API + web client / admin console (app.py, static/index.html)
    |-- SQLite store (db.py; /var/lib/ufw-okboy/ufw-okboy.db, WAL, files 0600)
    |
    | ufw subprocess, serialized by the host lock (ufw.lock, flock)
    v
UFW rules: allow from <ip> to any port <port> proto <proto> comment <prefix>:<user>:<group>
```

The CLI (`app.py <command>`) and the daily cleanup timer (`app.py cleanup`) open the same
database and take the same host lock as the server.

### Client Options

1. **Web UI (recommended)**: open `https://<server>/`; the page knocks every 30 seconds while
   open. "Remember credentials" keeps them in localStorage: in plaintext without a PIN
   (auto-reconnect on reopen), or in a PIN-encrypted vault (PBKDF2-SHA256, 600k iterations →
   AES-GCM; the PIN is asked on reopen). The admin console always requires the vault to be
   unlocked. Works on mobile.
2. **Python client**: `client/knock.py` (stdlib; PyYAML optional) with `--watch N`, or the
   systemd timer installed by `deploy/install-client.sh`.
3. **Shell client**: `client/knock.sh` (curl + openssl only).
4. **Windows client**: `client/knock.ps1` (PowerShell 5.1+/7, same config format as
   knock.py); `deploy/install-client.ps1` installs it as a SYSTEM scheduled task.

## Authentication Protocol

HMAC-SHA256 with timestamp, sent via `Authorization` header:

```text
Authorization: HMAC-SHA256 <username>:<timestamp>:<signature>
signature = lowercase hex HMAC-SHA256(secret, "<username>:<timestamp>")
```

- Secret never transmitted over the wire; generated secrets are `secrets.token_hex(32)`
- Timestamp window: ±`signature_ttl` seconds (default 300); a captured header can be replayed
  within the window (documented limitation, see SECURITY.md)
- Unknown user and bad signature both return `Invalid credentials` (a dummy HMAC keeps timing equal)
- Every failure is recorded in `failed_attempts`, which feeds the per-IP throttle
- Admin endpoints also require `is_admin`; sensitive admin writes require a TOTP step-up code
  (`X-TOTP-Code` header or `totp_code` body field) once the admin has enrolled

## Key Design Decisions

- **One rule per user per enabled group**, for the user's current IP; comment
  `<rule_prefix>:<user>:<group>` (rules from before groups: `<rule_prefix>:<user>`).
- **Reconcile on every knock** (`UFWManager.reconcile_user_rules`): add the missing rules for the
  new IP first, re-list (`ufw status numbered`), then delete stale rules (other IP, or group no
  longer enabled) by number from the highest down with `ufw --force delete <N>`; after an IP
  change the knock also removes by comment what is left on the old IP. Rule numbers are valid
  only while the host lock is held.
- **Host lock** (`HostLock`: flock on `ufw.lock` next to the DB, re-entrant per thread): knocks,
  admin writes, membership toggles, CLI commands and cleanup never interleave, across gunicorn
  workers and processes. A server request waits at most 20 s (then 503 "Firewall busy; retry
  shortly") and all its ufw commands must finish within 25 s of its start (gunicorn's timeout
  is 30 s); ufw runs in the C locale in its own process group, killed on timeout. `totp.lock`
  makes TOTP checks atomic with their per-account cap; `db.lock` guards restore (below).
- **Never take over host rules**: ufw keeps one rule per source/port/proto, so `add_rule` skips
  when a non-OkBoy rule (any action, `log` rules included) already exists for that triple.
- **Only one canonical IP reaches a rule**: proxy headers are honored only when the direct peer
  is in `trusted_proxies` (X-Real-IP, else the rightmost X-Forwarded-For entry); CIDRs, `any`,
  hostnames, loopback and unspecified addresses are refused (knock returns 400).
- **Removals are strict**: deletions match the comment at any address (`purge_rules`); a failed
  listing, an inactive ufw or a failed delete raises `RuntimeError`, and callers keep their DB
  state (user, group or membership kept; revoke keeps the current IP) so a retry or cleanup
  can finish the job.
- **SQLite is the single source of truth**: 6 data tables + `schema_version`; one connection per
  thread (WAL, `busy_timeout` 5 s, foreign keys on); DB files, snapshots and backups are 0600,
  a newly created data dir 0700. Legacy `users:` / `protected_ports:` / `state.json` are
  imported only when a new database is created (`Database.fresh`), never merely because the
  users table is empty.
- **Restore exclusivity**: every `Database` holds a shared flock on `db.lock`; `restore` takes it
  exclusively and also scans `/proc` for open handles, refusing while the service, a cleanup
  run or another `app.py` process has the database open.
- **Security**: per-IP failure throttle (HTTP 429 once failures within `throttle_window` reach
  `throttle_max_failures`); TOTP step-up (RFC 6238, stdlib only) on every admin write:
  create/delete user and group, add/remove a membership or toggle another user's, revoke,
  set-admin, system UFW rule deletion. Replay protection via `totp_last_counter`; wrong codes
  are capped per account across IPs (429); re-enrollment needs a current code and stays pending
  (`totp_pending_secret`) until activated. Revoke rotates the secret first, then purges the
  rules and clears the state.
- **Self-service limits**: a user may only toggle an existing membership (admins included); new
  grants go through the admin API with step-up; the optional `allowed_ports` whitelist applies
  to groups created through the API.
- **Versioned DB migrations**: `MIGRATIONS` registry (currently v1–v6) + `schema_version` table;
  `Database.init()` runs pending migrations at startup, under the host lock; migrations add
  columns/indexes (v5 rotates public sample secrets) and never drop data.
- **Manual upgrades only**: the root service never pulls code by itself. `upgrade --check`
  queries the latest GitHub release; `upgrade --force` works on git checkouts only (online DB
  backup → `git pull --ff-only` → migrate → restart → health check on
  `http://127.0.0.1:5000/health` → on failure `git reset --hard` to the previous HEAD and
  restart; the DB is not restored). Other installs are told to use `deploy/upgrade.sh`.
- **Server runs as root** (UFW management). **Gunicorn in production**; the Flask dev server
  (`serve`) is for testing only.
- **Logging**: under gunicorn the app loggers have no handler, so WARNING and above go to stderr
  → journald (`journalctl -u ufw-okboy`); `/var/log/ufw-okboy/*.log` hold gunicorn's own logs.
- **JSON error contract**: every `/api/` response is JSON `{"ok": ..., "error": ...}`, including
  framework errors (404/405 carry `code`) and unhandled exceptions (500); the SPA parses every
  body as JSON.

## Directory Structure

```text
server/
  app.py              - Flask app factory (create_app), REST API, CLI (argparse), upgrade
  ufw_ops.py          - UFWManager (add/remove/purge/reconcile/cleanup/sync, rule listing) + HostLock
  db.py               - SQLite layer: schema, migrations v1–v6, CRUD, logs, backup, restore claim
  auth.py             - HMAC verification, IP throttle, admin/membership checks, TOTP (RFC 6238)
  static/index.html   - Single-page web client + admin console + PIN vault (en/zh strings)
  config.example.yaml - Server configuration template
  requirements.txt    - flask, pyyaml, gunicorn
  tests/              - unittest suite; test_ufw_integration.py runs against real ufw
client/
  knock.py            - Python client (stdlib; PyYAML optional, else a minimal built-in parser)
  knock.sh            - Shell client (curl + openssl)
  knock.ps1           - Windows PowerShell 5.1+/7 client (one config file per server)
  config.example.yaml - Client configuration template (knock.py / knock.ps1)
deploy/
  deploy.sh           - Full install: packages, Python >= 3.10, UFW (SSH allowed first), SSL,
                        nginx, systemd units, admin user; the package's install.sh runs it
  quick-install.sh    - curl | bash entry: fetches master (optional --gh-mirror), runs deploy.sh
  install-server.sh   - App + Python deps + unit files only (no nginx/SSL, no service start)
  upgrade.sh          - Upgrades a non-git install: DB backup, copy, deps, UMask drop-in,
                        restart, health check on the unit's --bind, code rollback
  build-release.sh    - Builds ufw-okboy-vX.Y.Z.tar.gz + .sha256 with vendored wheels
                        (CPython 3.10–3.14, x86_64 and aarch64); used by release.yml
  install-client.sh   - Linux client installer (knock.py + systemd timer)
  install-client.ps1  - Windows client installer (knock.ps1 + SYSTEM scheduled task)
  ufw-okboy.service   - Server unit (gunicorn on 127.0.0.1:5000, UMask=0077)
  ufw-okboy-cleanup.service / ufw-okboy-cleanup.timer - Daily `cleanup --max-age 7`
  knock.service / knock.timer - Example client units for knock.sh (every 2 minutes)
nginx/
  ufw-okboy.conf      - Example reverse-proxy site (needs limit_req_zone in the http block)
docs/
  web-client.png      - Screenshot used by the READMEs
.github/workflows/
  ci.yml              - Unit tests (Python 3.10–3.14), real-ufw integration test,
                        bash -n + shellcheck, release-package offline-install check
  release.yml         - On v* tags: tests, build-release.sh, GitHub Release (notes from CHANGELOG.md)
VERSION               - Single source of truth for the version (read by app.py and the scripts)
README.md, README.en.md, GUIDE.md (Chinese user/admin guide), CHANGELOG.md, SECURITY.md, LICENSE
```

## CLI Commands (Server)

On a server, run as root with the venv interpreter:
`cd /opt/ufw-okboy/server && sudo ../venv/bin/python app.py -c config.yaml <command>`.

```bash
python app.py [-c CONFIG] <command>       # -c/--config goes before the command; default: config.yaml next to app.py
python app.py -V | --version              # Show version
python app.py serve [--debug]             # Flask dev server on listen_host:listen_port (testing only)
python app.py gen-secret [username]       # Print a random secret + a legacy `users:` snippet (no DB write)
python app.py list                        # Legacy config users, DB users + IPs, managed rules (plain `ufw status`)
python app.py cleanup [--max-age 7]       # Purge ALL rules of users whose last knock is older than N days; clear their state
python app.py sync                        # Refill current_ip/last_knock of existing DB users from ufw rules, then reconcile
python app.py user-add <name> [--admin]   # Create a user, print its random secret (exit 1 if it exists)
python app.py user-del <name>             # Purge the user's rules, then delete the user
python app.py user-list                   # List users
python app.py group-add <name> <port> [--proto tcp|udp]  # Create a port group (one group per port+proto)
python app.py group-del <name>            # Purge the group's rules, then delete the group
python app.py group-list                  # List groups
python app.py user-join <user> <group>    # Add or re-enable a membership; add the rule now if the user has a current IP
python app.py user-leave <user> <group>   # Purge the membership's rules, then remove it
python app.py admin-add <user>            # Grant admin (demote only via the API / admin console)
python app.py revoke <user> [--no-rotate] # Rotate the secret (unless --no-rotate), purge rules, clear state
python app.py backup [--dir DIR]          # SQLite online backup + .sha256; keeps the newest backup_keep
python app.py restore <file>              # Verify .sha256, snapshot the current DB, replace it (service stopped)
python app.py upgrade --check             # Query GitHub for the latest release (notify only)
python app.py upgrade --force [-y]        # Upgrade a git checkout (see Key Design Decisions)
```

## Development

- Python 3.10+ (the code uses `X | None` annotations); CI runs the unit tests on 3.10–3.14.
- Server dependencies: `pip install -r server/requirements.txt`.
- Clients: knock.py needs only the stdlib (PyYAML optional); knock.sh needs curl + openssl;
  knock.ps1 needs nothing beyond PowerShell.
- Unit tests (no root and no ufw needed; ufw calls are mocked):

  ```bash
  cd server
  python -m unittest discover -s tests -v
  ```

- Integration test against real ufw (`server/tests/test_ufw_integration.py`): skipped unless
  `UFW_OKBOY_INTEGRATION=1`. It changes the firewall of whatever runs it, so run it as root in a
  throwaway network + mount namespace with a private copy of `/etc/ufw`, as the
  `ufw-integration` job in `.github/workflows/ci.yml` does:

  ```bash
  cd server
  sudo env PY="$(command -v python3)" unshare --mount --net --fork bash -c '
    set -e
    ip link set lo up
    tmp=$(mktemp -d); cp -a /etc/ufw "$tmp/ufw"; mount --bind "$tmp/ufw" /etc/ufw
    export LANG=C LC_ALL=C UFW_OKBOY_INTEGRATION=1
    "$PY" -m unittest tests.test_ufw_integration -v'
  ```

- Shell scripts: CI runs `bash -n` and `shellcheck -S warning` on `deploy/*.sh` and `client/knock.sh`.
- Release package: `bash deploy/build-release.sh [version] [output_dir]`; `REQUIRE_WHEELS=1` makes a
  missing wheel set fatal (the release workflow and the CI package job set it).
- Local run: `python app.py -c <config> serve --debug`. Real knocks need root and ufw; point
  `db_path` and `backup_dir` somewhere writable.
- Web UI strings live in the `I18N` table in `static/index.html`: add every key to both `en` and `zh`.
- Behavior changes must be reflected in GUIDE.md (Chinese) and the config templates.
