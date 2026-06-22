"""Authorization layer for UFW OkBoy.

DB-backed HMAC-SHA256 authentication, admin checks, and group-membership
access checks. The HMAC-SHA256 wire format is identical to the legacy
config-dict implementation so existing clients (knock.py, knock.sh, and
the Web UI) continue to authenticate without any client-side change.

The database is the single source of truth for user secrets, admin flags,
and group memberships after the TASK-001 migration.
"""

import hashlib
import hmac
import logging
import sqlite3
import time

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


def is_admin(db: Database, username: str) -> bool:
    """Return True if *username* exists and has the admin flag set."""
    row = db.get_user_by_username(username)
    return bool(row and row["is_admin"])


def user_has_group_access(db: Database, username: str, group_id: int) -> bool:
    """Return True if *username* has an enabled membership in *group_id*.

    Args:
        db: Database instance used for the membership lookup.
        username: Username to check.
        group_id: Target group id.

    Returns:
        True only when an enabled membership row exists.
    """
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
