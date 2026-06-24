"""Unit tests for Wave 2 — TOTP (RFC 6238) step-up on admin-sensitive ops.

Correctness of the TOTP/HOTP primitive is pinned to the RFC 6238 Appendix B
test vectors. The integration tests then verify enrollment + step-up
enforcement on revoke / delete-user / delete-group.

Run from the server/ directory with:
    python -m unittest tests.test_totp_stepup -v
"""

import base64
import hashlib
import hmac
import os
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db import Database
from ufw_ops import UFWManager
import auth
import app as app_module


def build_auth_header(username: str, secret: str, ts: int | None = None) -> str:
    if ts is None:
        ts = int(time.time())
    message = f"{username}:{ts}"
    signature = hmac.new(
        secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256,
    ).hexdigest()
    return f"HMAC-SHA256 {username}:{ts}:{signature}"


class TestTOTPVectors(unittest.TestCase):
    """Pin the HOTP/TOTP primitive to the RFC 6238 Appendix B vectors (SHA-1)."""

    SEED = b"12345678901234567890"  # the RFC's shared secret (ASCII, 20 bytes)
    VECTORS = [
        (59, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
        (20000000000, "65353130"),
    ]

    def test_hotp_matches_rfc6238_vectors(self) -> None:
        for t, expected in self.VECTORS:
            self.assertEqual(auth._hotp(self.SEED, t // 30, digits=8), expected)

    def test_totp_now_via_base32_matches_rfc(self) -> None:
        secret = base64.b32encode(self.SEED).decode("ascii")
        for t, expected in self.VECTORS:
            self.assertEqual(auth.totp_now(secret, t=t, digits=8), expected)

    def test_verify_totp_window_and_rejection(self) -> None:
        secret = auth.generate_totp_secret()
        code = auth.totp_now(secret, t=300)          # counter = 10
        self.assertTrue(auth.verify_totp(secret, code, t=300))
        self.assertTrue(auth.verify_totp(secret, code, t=330))   # +1 step, in window
        self.assertFalse(auth.verify_totp(secret, code, t=360))  # +2 steps, out
        self.assertFalse(auth.verify_totp(secret, "000000", t=300))
        self.assertFalse(auth.verify_totp(secret, None, t=300))
        self.assertFalse(auth.verify_totp(None, code, t=300))


class TestTOTPStepUp(unittest.TestCase):
    """Enrollment + step-up enforcement against the live admin API."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="ufw-okboy-totp-test-")
        self.db_path = os.path.join(self.tmpdir, "test.db")
        seed = Database(self.db_path)
        seed.init()
        self.admin_id = seed.create_user("admin", "admin-secret", is_admin=True)
        self.alice_id = seed.create_user("alice", "alice-secret", is_admin=False)
        self.group_id = seed.create_group("default-8080", 8080, "tcp")
        seed.add_membership(self.alice_id, self.group_id, enabled=1)
        seed.close()

        self.config_path = self._write_config()
        self._ufw_patcher = patch.object(UFWManager, "_run_ufw", return_value="")
        self._ufw_patcher.start()
        self.addCleanup(self._ufw_patcher.stop)

        self.flask_app = app_module.create_app(self.config_path)
        self.client = self.flask_app.test_client()

    def _write_config(self, **overrides) -> str:
        cfg = {
            "protected_ports": [8080], "proto": "tcp", "db_path": self.db_path,
            "signature_ttl": 300, "rule_prefix": "ufw-okboy",
            "users": {"admin": {"secret": "admin-secret"},
                      "alice": {"secret": "alice-secret"}},
        }
        cfg.update(overrides)
        path = os.path.join(self.tmpdir, f"config-{len(overrides)}.yaml")
        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(cfg, f)
        return path

    def _admin_header(self) -> str:
        return build_auth_header("admin", "admin-secret")

    def _enroll_admin(self) -> str:
        """Enroll + activate TOTP for admin; return the secret."""
        r = self.client.post(
            "/api/admin/totp/enroll", headers={"Authorization": self._admin_header()},
        ).get_json()
        secret = r["secret"]
        self.assertTrue(r["otpauth_uri"].startswith("otpauth://totp/"))
        act = self.client.post(
            "/api/admin/totp/activate",
            headers={"Authorization": self._admin_header()},
            json={"totp_code": auth.totp_now(secret)},
        )
        self.assertEqual(act.status_code, 200)
        self.assertTrue(act.get_json()["totp_enabled"])
        return secret

    # -- enrollment --------------------------------------------------- #

    def test_activate_rejects_wrong_code(self) -> None:
        self.client.post("/api/admin/totp/enroll",
                         headers={"Authorization": self._admin_header()})
        bad = self.client.post(
            "/api/admin/totp/activate",
            headers={"Authorization": self._admin_header()},
            json={"totp_code": "000000"},
        )
        self.assertEqual(bad.status_code, 400)

    # -- step-up enforcement on revoke -------------------------------- #

    def test_revoke_requires_code_when_enrolled(self) -> None:
        self._enroll_admin()
        no_code = self.client.post(
            f"/api/admin/users/{self.alice_id}/revoke",
            headers={"Authorization": self._admin_header()},
        )
        self.assertEqual(no_code.status_code, 403)
        self.assertTrue(no_code.get_json()["totp_required"])

    def test_revoke_succeeds_with_valid_code(self) -> None:
        secret = self._enroll_admin()
        ok = self.client.post(
            f"/api/admin/users/{self.alice_id}/revoke",
            headers={"Authorization": self._admin_header()},
            json={"totp_code": auth.totp_now(secret)},
        )
        self.assertEqual(ok.status_code, 200)
        self.assertTrue(ok.get_json()["ok"])

    def test_revoke_via_header_code(self) -> None:
        secret = self._enroll_admin()
        ok = self.client.post(
            f"/api/admin/users/{self.alice_id}/revoke",
            headers={"Authorization": self._admin_header(),
                     "X-TOTP-Code": auth.totp_now(secret)},
        )
        self.assertEqual(ok.status_code, 200)

    def test_delete_user_and_group_require_code(self) -> None:
        self._enroll_admin()
        du = self.client.delete(
            f"/api/admin/users/{self.alice_id}",
            headers={"Authorization": self._admin_header()},
        )
        self.assertEqual(du.status_code, 403)
        dg = self.client.delete(
            f"/api/admin/groups/{self.group_id}",
            headers={"Authorization": self._admin_header()},
        )
        self.assertEqual(dg.status_code, 403)

    # -- backward compatibility / scope ------------------------------- #

    def test_unenrolled_admin_revoke_still_works(self) -> None:
        """Opt-in: an admin without TOTP is not blocked (require_admin_totp=false)."""
        ok = self.client.post(
            f"/api/admin/users/{self.alice_id}/revoke",
            headers={"Authorization": self._admin_header()},
        )
        self.assertEqual(ok.status_code, 200)

    def test_stepup_scope_reads_skip_writes_require(self) -> None:
        """Step-up is scoped: read-only ops (listing) skip the code even when
        enrolled, but state-changing writes require it. Creating a user is a
        write that can mint an admin, so it MUST be gated — otherwise a stolen
        admin session (no code) could bypass the step-up that protects
        promote/delete/revoke just by creating a fresh admin instead."""
        secret = self._enroll_admin()
        # Read-only: listing users never needs a code.
        lst = self.client.get("/api/admin/users",
                              headers={"Authorization": self._admin_header()})
        self.assertEqual(lst.status_code, 200)
        # Write without a code → blocked.
        no_code = self.client.post(
            "/api/admin/users", headers={"Authorization": self._admin_header()},
            json={"username": "newbie"},
        )
        self.assertEqual(no_code.status_code, 403)
        # Same write with a valid code → allowed.
        with_code = self.client.post(
            "/api/admin/users", headers={"Authorization": self._admin_header()},
            json={"username": "newbie", "totp_code": auth.totp_now(secret)},
        )
        self.assertEqual(with_code.status_code, 201)

    def test_require_admin_totp_blocks_unenrolled(self) -> None:
        """require_admin_totp=true forces enrollment before sensitive ops."""
        cfg_path = self._write_config(require_admin_totp=True)
        app2 = app_module.create_app(cfg_path)
        client2 = app2.test_client()
        r = client2.post(
            f"/api/admin/users/{self.alice_id}/revoke",
            headers={"Authorization": self._admin_header()},
        )
        self.assertEqual(r.status_code, 403)
        self.assertTrue(r.get_json()["totp_enroll_required"])

    # -- secret hygiene + disable ------------------------------------- #

    def test_totp_secret_not_leaked_in_user_list(self) -> None:
        self._enroll_admin()
        data = self.client.get(
            "/api/admin/users", headers={"Authorization": self._admin_header()},
        ).get_json()
        for u in data["users"]:
            self.assertNotIn("totp_secret", u)
            self.assertNotIn("secret", u)

    def test_disable_requires_code_then_clears(self) -> None:
        secret = self._enroll_admin()
        no_code = self.client.delete(
            "/api/admin/totp", headers={"Authorization": self._admin_header()},
        )
        self.assertEqual(no_code.status_code, 403)
        ok = self.client.delete(
            "/api/admin/totp", headers={"Authorization": self._admin_header()},
            json={"totp_code": auth.totp_now(secret)},
        )
        self.assertEqual(ok.status_code, 200)
        self.assertFalse(ok.get_json()["totp_enabled"])

    def test_reenroll_when_enabled_requires_current_code(self) -> None:
        """Re-enrolling while TOTP is enabled must prove current possession;
        otherwise a stolen admin session (no code) could overwrite the secret
        and reset totp_enabled=0, hijacking or disabling the admin's 2FA."""
        secret = self._enroll_admin()
        no_code = self.client.post(
            "/api/admin/totp/enroll",
            headers={"Authorization": self._admin_header()},
        )
        self.assertEqual(no_code.status_code, 403)
        ok = self.client.post(
            "/api/admin/totp/enroll",
            headers={"Authorization": self._admin_header()},
            json={"totp_code": auth.totp_now(secret)},
        )
        self.assertEqual(ok.status_code, 200)
        self.assertIn("secret", ok.get_json())

    def test_stepup_code_cannot_be_replayed(self) -> None:
        """A consumed step-up code is rejected on reuse within its window
        (RFC 6238 §5.2 replay protection)."""
        secret = self._enroll_admin()
        code = auth.totp_now(secret)
        first = self.client.post(
            f"/api/admin/users/{self.alice_id}/revoke",
            headers={"Authorization": self._admin_header(), "X-TOTP-Code": code},
        )
        self.assertEqual(first.status_code, 200)
        # Same code, same window → replay rejected.
        second = self.client.post(
            f"/api/admin/users/{self.alice_id}/revoke",
            headers={"Authorization": self._admin_header(), "X-TOTP-Code": code},
        )
        self.assertEqual(second.status_code, 403)
        self.assertTrue(second.get_json()["totp_required"])


class TestSchemaMigration(unittest.TestCase):
    """The additive column migration upgrades an old users table in place."""

    def test_migrate_adds_totp_columns_to_legacy_table(self) -> None:
        tmp = tempfile.mkdtemp(prefix="ufw-okboy-mig-test-")
        path = os.path.join(tmp, "legacy.db")
        # Simulate a pre-TOTP users table (no totp columns).
        import sqlite3
        conn = sqlite3.connect(path)
        conn.execute(
            "CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "username TEXT UNIQUE NOT NULL, secret TEXT NOT NULL, "
            "is_admin INTEGER NOT NULL DEFAULT 0, current_ip TEXT, "
            "last_knock INTEGER, created_at TEXT NOT NULL DEFAULT (datetime('now')))"
        )
        conn.execute("INSERT INTO users (username, secret) VALUES ('legacy', 's')")
        conn.commit()
        conn.close()

        db = Database(path)
        db.init()  # should ALTER in the missing columns idempotently
        try:
            cols = {r["name"] for r in db.conn.execute("PRAGMA table_info(users)")}
            self.assertIn("totp_secret", cols)
            self.assertIn("totp_enabled", cols)
            # Existing row preserved, new column defaulted.
            row = db.get_user_by_username("legacy")
            self.assertEqual(row["totp_enabled"], 0)
            db.init()  # second call is a no-op (idempotent)
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
