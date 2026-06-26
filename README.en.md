# UFW OkBoy

**Dynamic firewall allowlist manager** — users authenticate once, the server adds their IP to UFW automatically; when the IP changes the next heartbeat swaps the rule seamlessly, keeping the firewall clean and traceable.

English | [中文](README.md)

<p align="center">
  <img src="docs/web-client.png" alt="Web client interface" width="380">
</p>

---

## What it is

Your server's sensitive ports (admin panels, databases, SSH, APIs) sit behind UFW rules that allow only specific IPs. But people's IPs keep changing — switching WiFi, traveling, restarting routers — and every change means bothering the admin to edit the firewall by hand.

**UFW OkBoy automates this**: a user opens a web page and logs in once; the page "knocks" every 30s and the server updates the firewall. IP changed → swapped automatically. Person gone → the rule expires and is cleaned up.

## What it does

| Capability | Description |
|------------|-------------|
| 🌐 **One-click web client** | Open in a browser and log in — auto-renews, auto-reconnects, mobile friendly |
| 🔄 **Automatic IP swap** | One rule per user per port; the old IP is replaced on change, no stale entries |
| 👥 **Group authorization** | Admins create groups, bind ports, manage members; users self-toggle authorized groups |
| 🖥️ **Web admin console** | Users / groups / rules, audit log, TOTP, system firewall rules — all in the browser, no SSH needed |
| 🔐 **Secure auth** | HMAC-SHA256 + timestamp (secret never sent), TOTP step-up, failure throttle, audit log |
| 🌏 **Restricted-network friendly** | Offline package + mirror fallback + self-signed cert + public IP + high ports — no filed domain needed |
| 🧰 **Three clients** | Web / Python (`knock.py`) / Shell (`knock.sh`, zero deps) |

## Quick start

### 1. Install the server (one line, as root)

```bash
# Self-signed cert, no domain — access via IP:port (the most common path)
curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/quick-install.sh | bash -s -- --self-signed -y
```

> Have a domain? Replace `--self-signed` with `--domain your.server.com` for automatic Let's Encrypt.
> The installer prints the `admin` account and its token **highlighted at the very end** — copy it.

### 2. Start using it

Open `https://your-server:port/` → enter `admin` and the token → click **Connect**.
The page auto-renews every 30s, keeping your current IP in the allowlist. Need to rotate the secret? Click "Rotate secret" in the console — no reinstall.

### 3. Add users and ports (a few clicks in the console)

Click **Admin** after logging in: create a user (get a token), create a group (bind a port), add the user to the group.
Then send "server address + username + token" to your teammate — they open the page and log in (headless servers use the CLI client below).

### CLI client for headless servers

```bash
curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/install-client.sh \
  | bash -s -- --server https://your-server:port --user alice --secret USER_TOKEN
```

## Offline / restricted networks

For servers where GitHub/PyPI are slow or blocked, or domains require filing. **The most reliable path is the offline package**:

```bash
# Build on a machine with network (bundles dependency wheels)
bash deploy/build-release.sh
# Copy dist/ufw-okboy-*.tar.gz to the server, then:
tar xzf ufw-okboy-*.tar.gz && cd ufw-okboy-* && sudo bash install.sh --self-signed -y
```

Online but GitHub is blocked → use a mirror (proxies expire; find a current one at <https://ghproxy.link/>):

```bash
curl -fsSL https://ghfast.top/https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/quick-install.sh \
  | bash -s -- --gh-mirror https://ghfast.top --self-signed --port 8443 --ip <YOUR_PUBLIC_IP> -y
```

📖 Step-by-step + troubleshooting: the Chinese **[国内部署专题](GUIDE.md#国内部署专题)** (mainland-China deployment).

## FAQ

**Locked out of SSH after install?**
Make sure you're on **v2.2.1+** (older versions had this issue, now fixed); the new installer allows SSH before enabling the firewall. If locked out: log in via your cloud provider's **console / VNC** and run `sudo ufw allow 22/tcp && sudo ufw reload`.

**Web page opens but the port won't connect?**
99% of the time your **cloud security group** hasn't opened that port. UFW and the cloud security group are two layers — open **both**.

**Self-signed cert → client TLS error?**
Set `verify_ssl: false` in `knock.py`'s `config.yaml`; set `INSECURE=1` (or pass `--insecure`) for `knock.sh`. The HMAC secret never goes over the wire — this only disables transport-layer cert verification.

**Lost or leaked a secret?**
In the console, click "Rotate secret" for that user (or self-rotate your own); or run `python app.py revoke <user>` on the server — closes ports + rotates the secret, old credentials die instantly.

**How do I upgrade?**
```bash
curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/upgrade.sh | bash
```
Backup → update → restart → health-check, with auto-rollback; config / DB / certs are preserved. Hard-refresh the browser (Ctrl-Shift-R) after upgrading.

More in the **[full guide](GUIDE.md)** (Chinese).

## Docs & versions

- 📘 **[Full deployment & usage guide · GUIDE.md](GUIDE.md)** (Chinese) — server / Nginx / Systemd, manual install, key distribution, clients, operations, security, FAQ
- 📝 **[Changelog · CHANGELOG.md](CHANGELOG.md)** | **[GitHub Releases](https://github.com/lvusyy/UFW-OkBoy/releases)**

## License

MIT
