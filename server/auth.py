"""Authorization layer for UFW OkBoy.

DB-backed HMAC-SHA256 authentication, admin checks, and group-membership
access checks. The HMAC-SHA256 wire format is identical to the legacy
config-dict implementation so existing clients (knock.py, knock.sh, and
the Web UI) continue to authenticate without any client-side change.

The database is the single source of truth for user secrets, admin flags,
and group memberships after the TASK-001 migration.
"""

import base64
import hashlib
import hmac
import logging
import secrets
import sqlite3
import struct
import time
from urllib.parse import quote

from db import Database

logger = logging.getLogger("ufw-okboy.auth")


def verify_hmac(db: Database, auth_header: str | None, ttl: int = 300,
                client_ip: str | None = None) -> tuple[str | None, str | None]:
    """Verify the HMAC-SHA256 Authorization header against the database.

    Header format: ``HMAC-SHA256 <username>:<timestamp>:<hex_signature>``
    Where signature = HMAC-SHA256(secret, "<username>:<timestamp>").

    On every failure branch a row is recorded in ``failed_attempts`` via
    ``db.record_failed_attempt`` before returning ``(None, reason)``.

    Args:
        db: Database instance used for user lookup and failure recording.
        auth_header: Raw value of the HTTP ``Authorization`` header.
        ttl: Maximum allowed clock skew in seconds.
        client_ip: Optional client IP recorded with failed attempts.

    Returns:
        (username, None) on success, or (None, error_message) on failure.
    """
    if not auth_header or not auth_header.startswith("HMAC-SHA256 "):
        db.record_failed_attempt(None, client_ip, "Missing or invalid Authorization header")
        return None, "Missing or invalid Authorization header"

    payload = auth_header[len("HMAC-SHA256 "):]

    parts = payload.split(":", 2)
    if len(parts) != 3:
        db.record_failed_attempt(None, client_ip, "Malformed auth payload (expected username:timestamp:signature)")
        return None, "Malformed auth payload (expected username:timestamp:signature)"
    username, ts_str, signature = parts

    try:
        ts = int(ts_str)
    except ValueError:
        db.record_failed_attempt(username, client_ip, "Invalid timestamp")
        return None, "Invalid timestamp"
    if abs(int(time.time()) - ts) > ttl:
        db.record_failed_attempt(username, client_ip, "Signature expired")
        return None, "Signature expired"

    row = db.get_user_by_username(username)
    if row is None:
        db.record_failed_attempt(username, client_ip, "Unknown user")
        return None, "Unknown user"

    expected = hmac.new(
        row["secret"].encode("utf-8"),
        f"{username}:{ts_str}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(signature, expected):
        db.record_failed_attempt(username, client_ip, "Invalid signature")
        return None, "Invalid signature"

    return username, None


def check_ip_throttle(db: Database, client_ip: str | None,
                      max_failures: int, window_seconds: int) -> str | None:
    """Return an error string if *client_ip* has too many recent failures.

    Throttling is keyed on the **IP**, not the username, on purpose: keying on
    username would let an attacker lock out a legitimate user just by spamming
    bad signatures for their name (an account-lockout DoS — flagged Medium in
    the project risk register). The HMAC secret is 256-bit, so this is not
    guess-prevention (online guessing is already infeasible); it throttles
    abuse/probing and narrows the replay surface.

    A non-positive *max_failures* disables the throttle (returns None). The
    throttle rejection itself is NOT recorded as a new failed attempt, so the
    window slides cleanly: an IP unlocks once its failures age past
    *window_seconds*.
    """
    if max_failures <= 0 or not client_ip:
        return None
    if db.count_recent_failed_attempts(client_ip, window_seconds) >= max_failures:
        return "Too many failed attempts; try again later"
    return None


def is_admin(db: Database, username: str) -> bool:
    """Return True if *username* exists and has the admin flag set."""
    row = db.get_user_by_username(username)
    return bool(row and row["is_admin"])


def user_has_group_access(db: Database, username: str, group_id: int,
                          allow_reenable: bool = False) -> bool:
    """Return True if *username* may use / (re-)enable membership in *group_id*.

    By default (``allow_reenable=False``) this returns True only when an
    enabled membership row exists — i.e. the user is currently authorized.

    When ``allow_reenable=True`` (used by the self-toggle path), the check is
    broadened: a *previously authorized* membership (a row exists, whether
    enabled or disabled) also passes. This lets a user re-enable a group they
    were once granted, while still blocking them from enabling a group they
    have never been authorized for — closing the self-escalation gap (VULN-A).
    New authorizations must come from an admin via the join API.

    Args:
        db: Database instance used for the membership lookup.
        username: Username to check.
        group_id: Target group id.
        allow_reenable: If True, treat a previously_authorized (historical)
            membership row as sufficient for re-enabling.

    Returns:
        True when access is permitted under the rules above.
    """
    if allow_reenable:
        # Previously authorized: any row (enabled or disabled) for this user+group.
        row = db.conn.execute(
            "SELECT 1 FROM user_group_membership m "
            "JOIN users u ON u.id = m.user_id "
            "WHERE u.username=? AND m.group_id=?",
            (username, group_id),
        ).fetchone()
        return row is not None
    # Default: currently enabled membership only.
    row = db.conn.execute(
        "SELECT m.enabled FROM user_group_membership m "
        "JOIN users u ON u.id = m.user_id "
        "WHERE u.username=? AND m.group_id=? AND m.enabled=1",
        (username, group_id),
    ).fetchone()
    return row is not None


def require_admin(db: Database, auth_header: str | None, ttl: int = 300,
                  client_ip: str | None = None) -> tuple[sqlite3.Row | None, str | None]:
    """Verify the HMAC header and require admin privileges.

    Args:
        db: Database instance used for auth and admin verification.
        auth_header: Raw value of the HTTP ``Authorization`` header.
        ttl: Maximum allowed clock skew in seconds.
        client_ip: Optional client IP recorded with failed attempts.

    Returns:
        (user_row, None) when the caller is an admin, otherwise
        (None, error_message).
    """
    username, err = verify_hmac(db, auth_header, ttl, client_ip)
    if err:
        return None, err
    if not is_admin(db, username):
        db.record_failed_attempt(username, client_ip, "Admin privileges required")
        return None, "Admin privileges required"
    return db.get_user_by_username(username), None


# ====================================================================== #
#  TOTP (RFC 6238) — step-up verification for admin-sensitive operations
# ====================================================================== #
#
# Stdlib-only HOTP/TOTP (no pyotp dependency). HMAC-SHA1 is the RFC default
# and what authenticator apps (Google Authenticator, Authy, ...) expect — the
# SHA-1 collision weakness does NOT affect HMAC-SHA1's use here. Correctness is
# pinned to the RFC 6238 Appendix B test vectors in the test suite.

def generate_totp_secret() -> str:
    """Return a fresh base32 TOTP secret (160-bit, unpadded — app-friendly)."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _b32decode(secret: str) -> bytes:
    """Decode an unpadded/padded base32 secret to raw key bytes."""
    padded = secret.upper() + ("=" * (-len(secret) % 8))
    return base64.b32decode(padded)


def _hotp(key: bytes, counter: int, digits: int = 6) -> str:
    """RFC 4226 HOTP: dynamic-truncated HMAC-SHA1, zero-padded to *digits*."""
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    binary = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10 ** digits)).zfill(digits)


def totp_now(secret: str, t: int | None = None,
             step: int = 30, digits: int = 6) -> str:
    """Return the current TOTP code for *secret* (RFC 6238)."""
    t = int(time.time()) if t is None else t
    return _hotp(_b32decode(secret), t // step, digits)


def verify_totp(secret: str | None, code: str | None, t: int | None = None,
                step: int = 30, digits: int = 6, window: int = 1) -> bool:
    """Constant-time verify *code* against *secret*, tolerating ±*window* steps.

    The window absorbs clock skew between the server and the authenticator
    (default ±1 step = ±30s). Returns False for empty secret/code.
    """
    if not secret or not code:
        return False
    code = code.strip()
    t = int(time.time()) if t is None else t
    key = _b32decode(secret)
    counter = t // step
    for w in range(-window, window + 1):
        if hmac.compare_digest(_hotp(key, counter + w, digits), code):
            return True
    return False


def totp_uri(secret: str, username: str, issuer: str = "UFW-OkBoy") -> str:
    """Build an otpauth:// URI for QR/manual enrollment in an authenticator app."""
    label = quote(f"{issuer}:{username}")
    return (f"otpauth://totp/{label}?secret={secret}"
            f"&issuer={quote(issuer)}&digits=6&period=30")
