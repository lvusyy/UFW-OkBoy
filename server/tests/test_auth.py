"""Unit tests for the authorization layer (server/auth.py).

Run from the server/ directory with:
    python -m unittest tests.test_auth -v
"""

import hashlib
import hmac
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db import Database
import auth


def build_auth_header(username: str, secret: str, ts: int | None = None) -> str:
    """Build an HMAC-SHA256 Authorization header (mirrors knock.py)."""
    if ts is None:
        ts = int(time.time())
    message = f"{username}:{ts}"
    signature = hmac.new(
        secret.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"HMAC-SHA256 {username}:{ts}:{signature}"


class TestAuth(unittest.TestCase):
    """Shared fixture: a fresh Database seeded with a user, admin, group, membership."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="ufw-okboy-auth-test-")
        self.db_path = os.path.join(self.tmpdir, "test.db")
        self.db = Database(self.db_path)
        self.db.init()

        self.alice_secret = "secret-alice"
        self.admin_secret = "secret-admin"
        self.alice_id = self.db.create_user("alice", self.alice_secret, is_admin=False)
        self.admin_id = self.db.create_user("admin", self.admin_secret, is_admin=True)
        self.group_id = self.db.create_group("g", 8080, "tcp")
        self.db.add_membership(self.alice_id, self.group_id, enabled=1)

    def tearDown(self) -> None:
        self.db.close()

    # -- verify_hmac --------------------------------------------------- #

    def test_verify_hmac_success(self) -> None:
        header = build_auth_header("alice", self.alice_secret)
        username, err = auth.verify_hmac(self.db, header)
        self.assertEqual(username, "alice")
        self.assertIsNone(err)

    def test_verify_hmac_bad_signature(self) -> None:
        header = build_auth_header("alice", self.alice_secret)
        header = header[:-1] + ("0" if header[-1] != "0" else "1")
        username, err = auth.verify_hmac(self.db, header)
        self.assertIsNone(username)
        self.assertEqual(err, "Invalid signature")
        rows = self.db.conn.execute(
            "SELECT * FROM failed_attempts WHERE reason='Invalid signature'",
        ).fetchall()
        self.assertEqual(len(rows), 1)

    def test_verify_hmac_expired(self) -> None:
        old_ts = int(time.time()) - 3600
        header = build_auth_header("alice", self.alice_secret, ts=old_ts)
        username, err = auth.verify_hmac(self.db, header, ttl=300)
        self.assertIsNone(username)
        self.assertEqual(err, "Signature expired")

    def test_verify_hmac_unknown_user(self) -> None:
        header = build_auth_header("mallory", "no-such-secret")
        username, err = auth.verify_hmac(self.db, header)
        self.assertIsNone(username)
        self.assertEqual(err, "Unknown user")

    def test_verify_hmac_missing_header(self) -> None:
        username, err = auth.verify_hmac(self.db, None)
        self.assertIsNone(username)
        self.assertEqual(err, "Missing or invalid Authorization header")

    def test_verify_hmac_records_client_ip(self) -> None:
        header = build_auth_header("mallory", "no-such-secret")
        auth.verify_hmac(self.db, header, client_ip="203.0.113.9")
        row = self.db.conn.execute(
            "SELECT ip, username FROM failed_attempts WHERE reason='Unknown user'",
        ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["ip"], "203.0.113.9")
        self.assertEqual(row["username"], "mallory")

    # -- is_admin ------------------------------------------------------ #

    def test_is_admin(self) -> None:
        self.assertTrue(auth.is_admin(self.db, "admin"))
        self.assertFalse(auth.is_admin(self.db, "alice"))
        self.assertFalse(auth.is_admin(self.db, "nobody"))

    # -- require_admin ------------------------------------------------- #

    def test_require_admin_allows_admin(self) -> None:
        header = build_auth_header("admin", self.admin_secret)
        user_row, err = auth.require_admin(self.db, header)
        self.assertIsNone(err)
        self.assertIsNotNone(user_row)
        self.assertEqual(user_row["username"], "admin")
        self.assertEqual(user_row["is_admin"], 1)

    def test_require_admin_denies_non_admin(self) -> None:
        header = build_auth_header("alice", self.alice_secret)
        user_row, err = auth.require_admin(self.db, header)
        self.assertIsNone(user_row)
        self.assertEqual(err, "Admin privileges required")

    def test_require_admin_rejects_bad_auth(self) -> None:
        user_row, err = auth.require_admin(self.db, "HMAC-SHA256 admin:bad:bad")
        self.assertIsNone(user_row)
        self.assertIsNotNone(err)

    # -- user_has_group_access ----------------------------------------- #

    def test_user_has_group_access_enabled_and_disabled(self) -> None:
        self.assertTrue(auth.user_has_group_access(self.db, "alice", self.group_id))

        self.db.set_membership_enabled(self.alice_id, self.group_id, 0)
        self.assertFalse(auth.user_has_group_access(self.db, "alice", self.group_id))

        self.db.set_membership_enabled(self.alice_id, self.group_id, 1)
        self.assertTrue(auth.user_has_group_access(self.db, "alice", self.group_id))

        self.assertFalse(auth.user_has_group_access(self.db, "alice", 999999))
        self.assertFalse(auth.user_has_group_access(self.db, "admin", self.group_id))


if __name__ == "__main__":
    unittest.main()
