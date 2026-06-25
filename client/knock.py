#!/usr/bin/env python3
"""UFW OkBoy Client - Register your IP with the server's firewall allowlist.

Usage:
    python knock.py                        # Knock once (register IP)
    python knock.py status                 # Check current registration
    python knock.py knock --watch 300      # Knock every 5 minutes
    python knock.py -c /path/config.yaml   # Use custom config path
"""

import argparse
import hashlib
import hmac
import json
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# Attempt to load yaml; fall back to a simple parser if unavailable
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


# ====================================================================== #
#  Configuration
# ====================================================================== #

def _parse_simple_yaml(text: str) -> dict:
    """Minimal single-level YAML parser (fallback when pyyaml is not installed).

    Only supports top-level ``key: value`` pairs. Sufficient for client config.
    """
    result = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            key, _, value = line.partition(":")
            value = value.strip().strip('"').strip("'")
            result[key.strip()] = value
    return result


def load_config(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        sys.exit(f"Config file not found: {path}")
    text = p.read_text(encoding="utf-8")

    if HAS_YAML:
        cfg = yaml.safe_load(text)
    else:
        cfg = _parse_simple_yaml(text)

    # Validate required fields
    for field in ("server_url", "username", "secret"):
        if not cfg.get(field):
            sys.exit(f"Config error: '{field}' is required")
    return cfg


# ====================================================================== #
#  HMAC Authentication
# ====================================================================== #

def build_auth_header(username: str, secret: str) -> str:
    """Build the HMAC-SHA256 Authorization header value."""
    ts = str(int(time.time()))
    message = f"{username}:{ts}"
    signature = hmac.new(
        secret.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"HMAC-SHA256 {username}:{ts}:{signature}"


# ====================================================================== #
#  HTTP Client (stdlib only, zero external dependencies)
# ====================================================================== #

def _request(method: str, url: str, headers: dict,
             verify_ssl: bool = True, timeout: int = 15) -> dict:
    """Send an HTTP request and return the parsed JSON response."""
    req = urllib.request.Request(url, method=method, headers=headers)

    ctx = None
    if not verify_ssl:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            return json.loads(body)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return {"ok": False, "error": f"HTTP {e.code}: {body[:200]}"}
    except urllib.error.URLError as e:
        return {"ok": False, "error": f"Connection failed: {e.reason}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def knock(server_url: str, username: str, secret: str,
          verify_ssl: bool = True) -> dict:
    """Send a knock request to register the current IP."""
    auth = build_auth_header(username, secret)
    url = f"{server_url.rstrip('/')}/api/knock"
    return _request("POST", url, {"Authorization": auth}, verify_ssl)


def status(server_url: str, username: str, secret: str,
           verify_ssl: bool = True) -> dict:
    """Query current registration status."""
    auth = build_auth_header(username, secret)
    url = f"{server_url.rstrip('/')}/api/status"
    return _request("GET", url, {"Authorization": auth}, verify_ssl)


# ====================================================================== #
#  CLI
# ====================================================================== #

def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def main():
    parser = argparse.ArgumentParser(
        description="UFW OkBoy Client - Register your IP with the firewall allowlist",
    )
    parser.add_argument(
        "-c", "--config", default="config.yaml",
        help="Config file path (default: config.yaml)",
    )
    parser.add_argument(
        "action", nargs="?", default="knock", choices=["knock", "status"],
        help="Action to perform (default: knock)",
    )
    parser.add_argument(
        "--watch", type=int, metavar="SECONDS",
        help="Repeat the action every N seconds (watch mode)",
    )
    parser.add_argument(
        "--no-verify-ssl", action="store_true",
        help="Skip SSL certificate verification (not recommended)",
    )
    args = parser.parse_args()

    cfg = load_config(args.config)
    server_url = cfg["server_url"]
    username = cfg["username"]
    secret = cfg["secret"]
    # TLS verification: config `verify_ssl: false` suits self-signed servers
    # (common for IP-based / high-port CN deployments); the --no-verify-ssl flag,
    # when passed, always forces verification off. The HMAC secret is never sent
    # over the wire, so this drops only transport verification, not auth secrecy.
    cfg_verify = cfg.get("verify_ssl", True)
    if isinstance(cfg_verify, str):
        cfg_verify = cfg_verify.strip().lower() not in ("false", "0", "no", "off")
    verify_ssl = bool(cfg_verify) and not args.no_verify_ssl

    action_fn = knock if args.action == "knock" else status

    if args.watch:
        print(f"[{_now()}] Watch mode: {args.action} every {args.watch}s")
        while True:
            try:
                result = action_fn(server_url, username, secret, verify_ssl)
                ok = result.get("ok", False)
                msg = result.get("message") or result.get("error", "")
                ip = result.get("ip", "")
                symbol = "OK" if ok else "FAIL"
                print(f"[{_now()}] [{symbol}] {ip} - {msg}")
            except KeyboardInterrupt:
                print(f"\n[{_now()}] Stopped.")
                break
            except Exception as e:
                print(f"[{_now()}] [ERROR] {e}")
            try:
                time.sleep(args.watch)
            except KeyboardInterrupt:
                print(f"\n[{_now()}] Stopped.")
                break
    else:
        result = action_fn(server_url, username, secret, verify_ssl)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        sys.exit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
