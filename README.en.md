# UFW OkBoy

[![CI](https://github.com/lvusyy/UFW-OkBoy/actions/workflows/ci.yml/badge.svg)](https://github.com/lvusyy/UFW-OkBoy/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/lvusyy/UFW-OkBoy?sort=semver)](https://github.com/lvusyy/UFW-OkBoy/releases)
[![Python](https://img.shields.io/badge/python-3.10%E2%80%933.14-3776AB?logo=python&logoColor=white)](https://www.python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**A dynamic UFW allowlist.** An authorized user authenticates once and the server opens the ports they are allowed to use to their current IP; when the IP changes the rule follows, when they stop using it the access is withdrawn, and every rule can be traced to a user and a group.

[简体中文](README.md) | English

<p align="center">
  <img src="docs/web-client.png" alt="Web client" width="380">
</p>

## Why

Ports such as SSH, admin panels and databases are usually open to a few fixed IPs only. But people's egress IPs keep changing — a home line reconnects, a laptop changes networks, someone travels — and every change means someone has to log in and edit the firewall.

UFW OkBoy lets authorized users "knock" for themselves: a client periodically sends a signed request, and once the server has verified it, the request's source IP is allowed to the ports of the user's groups. Rules for an old IP are replaced when it changes, and a daily cleanup withdraws the access of users who stopped knocking.

## Features

- **Group-based access**: a group binds one port and protocol; once a user is in a group, a knock opens that port to their current IP.
- **Automatic IP switching**: every knock reconciles the firewall with the database — rules for the new IP are added first, then rules for the old IP and for groups no longer enabled are removed. Every rule carries the comment `ufw-okboy:<user>:<group>`.
- **Automatic expiry**: a daily cleanup removes all rules of users who have not knocked for 7 days.
- **Four clients**: web (renews every 30 seconds), Python `knock.py`, shell `knock.sh` (curl and openssl only), Windows `knock.ps1` (scheduled task, built-in PowerShell).
- **Web admin console**: users, groups, memberships, audit log, TOTP and the system firewall rules, all in the browser.
- **Authentication and safeguards**: HMAC-SHA256 signatures, so the secret never crosses the network; TOTP step-up for admin writes; failed authentication throttled per IP and failed TOTP codes capped per account; every firewall change serialized by a cross-process lock; operations recorded in an audit log.
- **Works on restricted networks**: release packages bundle the Python dependencies for an offline install; GitHub and PyPI mirrors are supported; a self-signed certificate on a high port works without a domain name.

## How it works

```text
Client (browser / knock.py / knock.sh / knock.ps1)
    │  HTTPS; Authorization: HMAC-SHA256 <user>:<timestamp>:<signature>
    ▼
Nginx (TLS termination, passes X-Real-IP)
    │  http://127.0.0.1:5000
    ▼
Gunicorn + Flask (server/app.py) ──── SQLite (users, groups, memberships, audit)
    │  ufw commands (serialized by a cross-process lock)
    ▼
UFW: allow from <client IP> to any port <port> proto <proto>   # ufw-okboy:<user>:<group>
```

The signature is `HMAC-SHA256(secret, "<user>:<timestamp>")`; a timestamp more than `signature_ttl` (300 seconds by default) away from the server's clock is rejected.

## Requirements

- Linux with UFW, and root.
- Python 3.10 or newer. Ubuntu 22.04+, Debian 12+ and Fedora ship it; on RHEL-family 8/9 the default `python3` is older and the installer installs `python3.12` (or `python3.11`) instead.
- The installer supports Debian/Ubuntu and the RHEL family (RHEL, Rocky, AlmaLinux, Fedora; ufw comes from EPEL). On the RHEL family, disable firewalld first, and with SELinux enforcing a few more settings are needed: see the [guide](GUIDE.md#环境要求).

## Quick start

### 1. Install the server

One-line online install (self-signed certificate; open `https://server-ip:port/` afterwards):

```bash
curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/quick-install.sh \
  | sudo bash -s -- --self-signed --port 8443 -y
```

With a domain name that resolves to the server, replace `--self-signed` with `--domain your.example.com` to get a Let's Encrypt certificate. Issuing and renewing it go through port 80: the installer opens it in UFW, and the cloud security group must allow it too.

Or install a specific version from its release package (the Python dependencies are included, no PyPI access needed):

```bash
V=v2.4.1
curl -fsSLO https://github.com/lvusyy/UFW-OkBoy/releases/download/$V/ufw-okboy-$V.tar.gz
curl -fsSLO https://github.com/lvusyy/UFW-OkBoy/releases/download/$V/ufw-okboy-$V.tar.gz.sha256
sha256sum -c ufw-okboy-$V.tar.gz.sha256
tar xzf ufw-okboy-$V.tar.gz && cd ufw-okboy-$V
sudo bash install.sh --self-signed --port 8443 -y
```

The secret of the admin user `admin` is printed at the **very end** of the output, once only — save it right away.

> On a cloud server, also open the port in the provider's security group. UFW and the security group are two separate layers; both must allow it.

### 2. Log in

Open `https://server:port/` in a browser, enter `admin` and the secret, and click **Connect**. The page renews every 30 seconds, so your current IP stays on the allowlist.

### 3. Add users and groups

In the admin console (**Admin**), create users, create groups (port + protocol) and add users to groups; a new user's secret is shown when it is created. Or from the command line:

```bash
cd /opt/ufw-okboy/server
sudo ../venv/bin/python app.py -c config.yaml user-add alice          # prints alice's secret
sudo ../venv/bin/python app.py -c config.yaml group-add web 8080
sudo ../venv/bin/python app.py -c config.yaml user-join alice web
```

> **Before letting it manage SSH (port 22)**: make sure your own knock succeeds, open a new SSH session from another terminal to confirm you can log in, and only then close the current one. Otherwise you can lock yourself out.

Then give the user the server address, their username and their secret; they can use the web page or one of the clients below.

## Clients

| Client | Use it on | Install |
|--------|-----------|---------|
| Web | Computers and phones with a browser | Just open the server address |
| `knock.py` | Linux servers, headless machines | `deploy/install-client.sh` (systemd timer) |
| `knock.sh` | Machines with only curl + openssl | Copy the script, add a cron job |
| `knock.ps1` | Windows | `deploy/install-client.ps1` (SYSTEM scheduled task) |

Linux (installs `knock.py` and a systemd timer; knocks every 30 seconds by default):

```bash
curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/install-client.sh \
  | sudo bash -s -- --server https://your-server:8443 --user alice --secret <secret> --no-verify-ssl
```

Windows (in PowerShell run as Administrator; the secret is prompted for and not echoed; add `-NoVerifySsl` for a self-signed server):

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/install-client.ps1))) -Server https://your-server:8443 -User alice
```

The scheduled task knocks every minute as SYSTEM and starts at boot. For more servers, run it again with another `-Server`; add `-Uninstall` to remove it.

`--no-verify-ssl` and `-NoVerifySsl` turn off TLS certificate verification, for self-signed certificates. With verification off, a man in the middle can capture a knock and replay it while the signature is valid (300 seconds by default), getting their own address allowlisted. On networks you don't trust, use a trusted certificate, such as the Let's Encrypt one `--domain` obtains.

## Upgrading

```bash
curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/upgrade.sh \
  | sudo bash -s -- --branch v2.4.1
```

The script backs up the database, updates the code and dependencies, restarts the service and health-checks it, and moves back to the previous code if the check fails. The configuration, certificates and database are kept. You can also upgrade offline from an unpacked release package: `sudo bash deploy/upgrade.sh --repo-dir . -y`. If `/opt/ufw-okboy` is a git checkout, follow [the upgrade section of the guide](GUIDE.md#升级与版本管理) instead. After upgrading, reload the page with Ctrl+Shift+R.

## Security

- Authenticated requests carry a signature, never the secret; a new secret is returned once over HTTPS when a user is created or a secret is rotated. The transport relies on HTTPS.
- Once an admin has enabled TOTP, every admin write needs a code; with `require_admin_totp: true`, admins who have not enabled TOTP cannot perform these operations until they do.
- The database, backups and any configuration file holding secrets are readable by root only.
- Known limitations (for example, a signature can be replayed while it is valid) and how to report a vulnerability: see [SECURITY.md](SECURITY.md). Please do not report vulnerabilities in public issues.

## FAQ

**Can't reach SSH after installing?**
Since v2.2.1 the installer allows SSH before it enables UFW, and it leaves the SSH rules alone when UFW is already active. If you are locked out anyway, log in through your provider's console or VNC and run `sudo ufw allow 22/tcp`.

**The web page opens but the port is still closed?**
Most likely the cloud security group does not allow that port.

**Forgot or leaked a secret?**
In the admin console, click **Revoke** for that user: it closes their ports and replaces their secret, so the old one stops working at once. For your own secret, click **Rotate secret**. From the command line: `sudo ../venv/bin/python app.py -c config.yaml revoke <user>`.

**Installed with v2.2.1 or earlier?**
The old installer created a sample user `alice` whose secret is public. Upgrading to v2.2.2 or later invalidates that secret; afterwards check with `user-list` whether `alice` is still there, and delete it if you don't need it. See [CHANGELOG · v2.2.2](CHANGELOG.md#v222-2026-09-27).

More in [GUIDE.md](GUIDE.md) (Chinese), including [deploying from mainland China](GUIDE.md#国内部署专题).

## Documentation

- [GUIDE.md](GUIDE.md) (Chinese): deployment, configuration, CLI, REST API, clients, operations, security design
- [CHANGELOG.md](CHANGELOG.md): release history and upgrade notes
- [SECURITY.md](SECURITY.md): security policy and vulnerability reporting
- [Releases](https://github.com/lvusyy/UFW-OkBoy/releases): packages and checksums

## Development

```bash
cd server
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

The real-ufw integration test (`tests/test_ufw_integration.py`) needs root and runs in private network and mount namespaces, so it never touches the host firewall; see the [CI workflow](.github/workflows/ci.yml) for how.

## License

[MIT](LICENSE)
