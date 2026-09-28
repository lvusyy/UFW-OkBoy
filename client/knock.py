#!/usr/bin/env python3
"""UFW OkBoy Client - Register your IP with the server's firewall allowlist.

Usage:
    python knock.py                        # Knock once (register IP)
    python knock.py status                 # Check current registration
    python knock.py knock --watch 300      # Knock every 5 minutes
    python knock.py -c /path/config.yaml   # Use custom config path
"""

import argparse
import base64
import hashlib
import hmac
import http.client
import json
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
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

# pin_sha256: base64 of a SHA-256 digest, 43 characters and one '=' of padding.
PIN_RE = re.compile(r"[A-Za-z0-9+/]{43}=")


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
    pin = str(cfg.get("pin_sha256") or "").strip()
    if pin and not PIN_RE.fullmatch(pin):
        sys.exit("Config error: 'pin_sha256' must be the base64 SHA-256 of the "
                 "server's public key (44 characters ending in '=')")
    cfg["pin_sha256"] = pin
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
#  Public-key pinning
# ====================================================================== #

def _der_value(der: bytes, pos: int):
    """Return (start, end) of the value of the DER element at pos."""
    length = der[pos + 1]
    pos += 2
    if length & 0x80:
        size = length & 0x7F
        length = int.from_bytes(der[pos:pos + size], "big")
        pos += size
    if pos + length > len(der):
        raise ValueError("truncated certificate")
    return pos, pos + length


def spki_sha256(cert_der: bytes) -> str:
    """base64(SHA-256(SubjectPublicKeyInfo)) of a DER certificate: the pin
    format of pin_sha256 (and of curl --pinnedpubkey sha256//...)."""
    tbs, _ = _der_value(cert_der, 0)             # Certificate -> tbsCertificate
    pos, _ = _der_value(cert_der, tbs)           # first field of tbsCertificate
    if cert_der[pos] == 0xA0:                    # [0] version (absent in v1)
        pos = _der_value(cert_der, pos)[1]
    for _ in range(5):                           # serial, signature, issuer, validity, subject
        pos = _der_value(cert_der, pos)[1]
    end = _der_value(cert_der, pos)[1]           # subjectPublicKeyInfo
    return base64.b64encode(hashlib.sha256(cert_der[pos:end]).digest()).decode()


def _pinned_request(method: str, url: str, headers: dict, pin: str,
                    timeout: int = 15) -> dict:
    """Send a request over a connection whose server key matches pin.

    The certificate is not checked against a CA or the host name (a
    self-signed server is the point); the pin is checked right after the
    handshake, before anything is sent.
    """
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        return {"ok": False, "error": "pin_sha256 needs an https:// server_url"}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    conn = None
    try:
        conn = http.client.HTTPSConnection(parts.hostname, parts.port or 443,
                                           timeout=timeout, context=ctx)
        conn.connect()
        seen = spki_sha256(conn.sock.getpeercert(binary_form=True))
        if seen != pin:
            return {"ok": False, "error": "Server public key does not match "
                    f"pin_sha256 (the server presented {seen}); nothing was sent"}
        path = parts.path + (f"?{parts.query}" if parts.query else "")
        conn.request(method, path, headers=headers)
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", errors="replace")
    except (OSError, http.client.HTTPException, ValueError, IndexError) as e:
        return {"ok": False, "error": f"Connection failed: {e}"}
    finally:
        if conn is not None:
            conn.close()
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return {"ok": False, "error": f"HTTP {resp.status}: {body[:200]}"}


# ====================================================================== #
#  HTTP Client (stdlib only, zero external dependencies)
# ====================================================================== #

def _request(method: str, url: str, headers: dict,
             verify_ssl: bool = True, timeout: int = 15, pin: str = "") -> dict:
    """Send an HTTP request and return the parsed JSON response."""
    if pin:
        return _pinned_request(method, url, headers, pin, timeout)
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
          verify_ssl: bool = True, pin: str = "") -> dict:
    """Send a knock request to register the current IP."""
    auth = build_auth_header(username, secret)
    url = f"{server_url.rstrip('/')}/api/knock"
    return _request("POST", url, {"Authorization": auth}, verify_ssl, pin=pin)


def status(server_url: str, username: str, secret: str,
           verify_ssl: bool = True, pin: str = "") -> dict:
    """Query current registration status."""
    auth = build_auth_header(username, secret)
    url = f"{server_url.rstrip('/')}/api/status"
    return _request("GET", url, {"Authorization": auth}, verify_ssl, pin=pin)


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
        help="Skip SSL certificate verification (not recommended; "
             "not used when pin_sha256 is set)",
    )
    args = parser.parse_args()

    cfg = load_config(args.config)
    server_url = cfg["server_url"]
    username = cfg["username"]
    secret = cfg["secret"]
    # TLS verification: `pin_sha256` accepts exactly the server key it names
    # (the way to trust a self-signed server) and then decides alone. Without
    # it, config `verify_ssl: false` or the --no-verify-ssl flag turns
    # verification off: the HMAC secret is never sent over the wire, but a man
    # in the middle can then capture a request and replay it while it is valid.
    pin = cfg["pin_sha256"]
    cfg_verify = cfg.get("verify_ssl", True)
    if isinstance(cfg_verify, str):
        cfg_verify = cfg_verify.strip().lower() not in ("false", "0", "no", "off")
    verify_ssl = bool(cfg_verify) and not args.no_verify_ssl

    action_fn = knock if args.action == "knock" else status

    if args.watch:
        print(f"[{_now()}] Watch mode: {args.action} every {args.watch}s")
        while True:
            try:
                result = action_fn(server_url, username, secret, verify_ssl, pin)
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
        result = action_fn(server_url, username, secret, verify_ssl, pin)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        sys.exit(0 if result.get("ok") else 1)


if __name__ == "__main__":
    main()
