"""Unit tests for Wave 1 P0 security hardening.

Covers:
- Per-IP abuse throttle (failed_attempts ENFORCEMENT, not just recording)
- Admin revoke (close ports + clear state + rotate secret = "force re-auth")
- Audit-log viewing API

Run from the server/ directory with:
    python -m unittest tests.test_security_wave1 -v
"""

import argparse
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
    """Build an HMAC-SHA256 Authorization header (mirrors knock.py)."""
    if ts is None:
        ts = int(time.time())
    message = f"{username}:{ts}"
    signature = hmac.new(
        secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256,
    ).hexdigest()
    return f"HMAC-SHA256 {username}:{ts}:{signature}"


class TestSecurityWave1(unittest.TestCase):
    """Fixture: admin + alice (member of default-8080), throttle_max_failures=3."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="ufw-okboy-sec-test-")
        self.db_path = os.path.join(self.tmpdir, "test.db")

        seed = Database(self.db_path)
        seed.init()
        self.admin_id = seed.create_user("admin", "admin-secret", is_admin=True)
        self.alice_id = seed.create_user("alice", "alice-secret", is_admin=False)
        self.group_id = seed.create_group("default-8080", 8080, "tcp")
        seed.add_membership(self.alice_id, self.group_id, enabled=1)
        seed.close()

        self.config_path = os.path.join(self.tmpdir, "config.yaml")
        with open(self.config_path, "w", encoding="utf-8") as f:
            yaml.dump({
                "protected_ports": [8080],
                "proto": "tcp",
                "db_path": self.db_path,
                "listen_host": "127.0.0.1",
                "listen_port": 5000,
                "signature_ttl": 300,
                "rule_prefix": "ufw-okboy",
                "throttle_max_failures": 3,
                "throttle_window": 300,
                "users": {
                    "admin": {"secret": "admin-secret"},
                    "alice": {"secret": "alice-secret"},
                },
            }, f)

        self._ufw_patcher = patch.object(UFWManager, "_run_ufw", return_value="")
        self._mock_ufw = self._ufw_patcher.start()
        self.addCleanup(self._ufw_patcher.stop)

        self.flask_app = app_module.create_app(self.config_path)
        self.client = self.flask_app.test_client()

    def _open_db(self) -> Database:
        return Database(self.db_path)

    def _admin_header(self) -> str:
        return build_auth_header("admin", "admin-secret")

    def _alice_header(self) -> str:
        return build_auth_header("alice", "alice-secret")

    def _knock_online(self, ip: str) -> None:
        """Bring alice online at *ip* (sets current_ip via the knock path)."""
        resp = self.client.post(
            "/api/knock",
            headers={"Authorization": self._alice_header(), "X-Real-IP": ip},
        )
        self.assertEqual(resp.status_code, 200)

    def _count_audit(self, action: str) -> int:
        db = self._open_db()
        try:
            row = db.conn.execute(
                "SELECT COUNT(*) AS c FROM audit_log WHERE action=?", (action,),
            ).fetchone()
            return row["c"]
        finally:
            db.close()

    # -- Revoke: close ports + clear state + rotate secret ------------- #

    def test_revoke_closes_ports_clears_state_and_rotates(self) -> None:
        self._knock_online("203.0.113.5")
        old_alice = self._alice_header()

        resp = self.client.post(
            f"/api/admin/users/{self.alice_id}/revoke",
            headers={"Authorization": self._admin_header()},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["ok"])
        self.assertTrue(data["rotated"])
        new_secret = data.get("secret")
        self.assertTrue(new_secret and len(new_secret) > 0)

        # Runtime state cleared (current_ip wiped).
        db = self._open_db()
        try:
            self.assertIsNone(db.get_user(self.alice_id)["current_ip"])
        finally:
            db.close()

        # UFW port-closing was invoked for the enabled group.
        self.assertTrue(self._mock_ufw.called)

        # Old credential is now INVALID; the rotated secret works.
        old = self.client.get("/api/status", headers={"Authorization": old_alice})
        self.assertEqual(old.status_code, 401)
        new = self.client.get(
            "/api/status",
            headers={"Authorization": build_auth_header("alice", new_secret)},
        )
        self.assertEqual(new.status_code, 200)
        self.assertGreaterEqual(self._count_audit("revoke"), 1)

    def test_revoke_no_rotate_keeps_secret(self) -> None:
        self._knock_online("203.0.113.6")
        resp = self.client.post(
            f"/api/admin/users/{self.alice_id}/revoke",
            headers={"Authorization": self._admin_header()},
            json={"rotate_secret": False},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertFalse(data["rotated"])
        self.assertNotIn("secret", data)

        db = self._open_db()
        try:
            self.assertIsNone(db.get_user(self.alice_id)["current_ip"])
        finally:
            db.close()

        # Credential unchanged → still authenticates.
        ok = self.client.get("/api/status", headers={"Authorization": self._alice_header()})
        self.assertEqual(ok.status_code, 200)

    def test_revoke_requires_admin(self) -> None:
        resp = self.client.post(
            f"/api/admin/users/{self.alice_id}/revoke",
            headers={"Authorization": self._alice_header()},
        )
        self.assertEqual(resp.status_code, 403)

    def test_revoke_user_not_found(self) -> None:
        resp = self.client.post(
            "/api/admin/users/999999/revoke",
            headers={"Authorization": self._admin_header()},
        )
        self.assertEqual(resp.status_code, 404)

    # -- Audit viewing ------------------------------------------------- #

    def test_audit_list_returns_entries(self) -> None:
        # Generate an audit event.
        self.client.post(
            "/api/admin/users",
            headers={"Authorization": self._admin_header()},
            json={"username": "carol"},
        )
        resp = self.client.get(
            "/api/admin/audit", headers={"Authorization": self._admin_header()},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["ok"])
        self.assertGreaterEqual(len(data["audit"]), 1)
        actions = {e["action"] for e in data["audit"]}
        self.assertIn("user_add", actions)

    def test_audit_requires_admin(self) -> None:
        resp = self.client.get(
            "/api/admin/audit", headers={"Authorization": self._alice_header()},
        )
        self.assertEqual(resp.status_code, 403)

    # -- Throttle: failed_attempts ENFORCEMENT ------------------------- #

    def test_throttle_blocks_same_ip_after_threshold(self) -> None:
        """3 failures from one IP → 4th request (even valid) gets 429."""
        attacker = "203.0.113.50"
        codes = []
        for _ in range(3):
            r = self.client.post(
                "/api/knock",
                headers={"Authorization": "HMAC-SHA256 alice:bad:bad",
                         "X-Real-IP": attacker},
            )
            codes.append(r.status_code)
        self.assertEqual(codes, [401, 401, 401])

        # 4th request from the same IP with a VALID header is still blocked.
        blocked = self.client.post(
            "/api/knock",
            headers={"Authorization": self._alice_header(), "X-Real-IP": attacker},
        )
        self.assertEqual(blocked.status_code, 429)

    def test_throttle_is_per_ip_not_global(self) -> None:
        """A different IP is unaffected by another IP's failures."""
        for _ in range(3):
            self.client.post(
                "/api/knock",
                headers={"Authorization": "HMAC-SHA256 alice:bad:bad",
                         "X-Real-IP": "203.0.113.50"},
            )
        other = self.client.post(
            "/api/knock",
            headers={"Authorization": "HMAC-SHA256 alice:bad:bad",
                     "X-Real-IP": "203.0.113.99"},
        )
        # Not 429 — reaches auth and fails normally.
        self.assertEqual(other.status_code, 401)

    def test_throttle_disabled_with_zero(self) -> None:
        """max_failures <= 0 disables the throttle; None ip is never throttled."""
        db = self._open_db()
        try:
            for _ in range(10):
                db.record_failed_attempt("alice", "203.0.113.7", "Invalid signature")
            self.assertIsNone(auth.check_ip_throttle(db, "203.0.113.7", 0, 300))
            self.assertIsNone(auth.check_ip_throttle(db, None, 3, 300))
            # Sanity: with the throttle on, the same IP IS over the limit.
            self.assertIsNotNone(auth.check_ip_throttle(db, "203.0.113.7", 3, 300))
        finally:
            db.close()

    def test_normal_repeated_knock_not_throttled(self) -> None:
        """Legit traffic is never a false positive: successes record no failures."""
        for _ in range(6):  # > throttle_max_failures (3)
            r = self.client.post(
                "/api/knock",
                headers={"Authorization": self._alice_header(),
                         "X-Real-IP": "203.0.113.20"},
            )
            self.assertEqual(r.status_code, 200)

    # -- Revoke: depth coverage --------------------------------------- #

    def _deleted_ports(self) -> set:
        """Ports that the mocked UFW was asked to delete (legacy delete path)."""
        ports = set()
        for c in self._mock_ufw.call_args_list:
            a = c.args
            if "delete" in a and "port" in a:
                ports.add(a[a.index("port") + 1])
        return ports

    def test_revoke_closes_every_enabled_group_port(self) -> None:
        db = self._open_db()
        try:
            g2 = db.create_group("extra", 2222, "tcp")
            db.add_membership(self.alice_id, g2, enabled=1)
        finally:
            db.close()
        self._knock_online("203.0.113.8")
        self._mock_ufw.reset_mock()

        resp = self.client.post(
            f"/api/admin/users/{self.alice_id}/revoke",
            headers={"Authorization": self._admin_header()},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertTrue({"8080", "2222"}.issubset(self._deleted_ports()))

    def test_revoke_offline_user_skips_ufw(self) -> None:
        """A user who never knocked (current_ip None) revokes without UFW calls."""
        self._mock_ufw.reset_mock()
        resp = self.client.post(
            f"/api/admin/users/{self.alice_id}/revoke",
            headers={"Authorization": self._admin_header()},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.get_json()["rotated"])
        self.assertFalse(self._mock_ufw.called)

    def test_cli_revoke_clears_state_and_rotates(self) -> None:
        self._knock_online("203.0.113.9")
        ns = argparse.Namespace(config=self.config_path, username="alice", no_rotate=False)
        app_module.cmd_revoke(ns)
        db = self._open_db()
        try:
            u = db.get_user_by_username("alice")
            self.assertIsNone(u["current_ip"])
            self.assertNotEqual(u["secret"], "alice-secret")  # rotated
        finally:
            db.close()
        self.assertGreaterEqual(self._count_audit("revoke"), 1)

    def test_rotate_secret_invalidates_old_credential(self) -> None:
        db = self._open_db()
        try:
            db.rotate_secret(self.alice_id, "brand-new-secret")
            self.assertEqual(db.get_user(self.alice_id)["secret"], "brand-new-secret")
            old_u, _ = auth.verify_hmac(db, build_auth_header("alice", "alice-secret"))
            self.assertIsNone(old_u)
            new_u, _ = auth.verify_hmac(db, build_auth_header("alice", "brand-new-secret"))
            self.assertEqual(new_u, "alice")
        finally:
            db.close()

    # -- Audit: limit + ordering -------------------------------------- #

    def test_audit_limit_and_ordering(self) -> None:
        for name in ("u1", "u2", "u3"):
            self.client.post(
                "/api/admin/users",
                headers={"Authorization": self._admin_header()},
                json={"username": name},
            )
        resp = self.client.get(
            "/api/admin/audit?limit=2",
            headers={"Authorization": self._admin_header()},
        )
        data = resp.get_json()
        self.assertEqual(len(data["audit"]), 2)          # clamped to limit
        ids = [e["id"] for e in data["audit"]]
        self.assertEqual(ids, sorted(ids, reverse=True))  # newest first


if __name__ == "__main__":
    unittest.main()
