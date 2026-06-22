"""Unit tests for admin CLI commands and admin REST API (TASK-004).

Run from the server/ directory with:
    python -m unittest tests.test_admin_api -v
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
        secret.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"HMAC-SHA256 {username}:{ts}:{signature}"


def _ns(**kwargs) -> argparse.Namespace:
    """Build an argparse.Namespace with a default config path."""
    kwargs.setdefault("config", None)
    return argparse.Namespace(**kwargs)


class TestAdminAPI(unittest.TestCase):
    """Shared fixture: temp config + pre-seeded DB with admin, regular user, group."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="ufw-okboy-admin-test-")
        self.db_path = os.path.join(self.tmpdir, "test.db")

        seed = Database(self.db_path)
        seed.init()
        self.admin_id = seed.create_user("admin", "admin-secret", is_admin=True)
        self.alice_id = seed.create_user("alice", "alice-secret", is_admin=False)
        self.group_id = seed.create_group("default-8080", 8080, "tcp")
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
                "users": {
                    "admin": {"secret": "admin-secret"},
                    "alice": {"secret": "alice-secret"},
                },
            }, f)

        self._ufw_patcher = patch.object(UFWManager, "_run_ufw", return_value="")
        self._ufw_patcher.start()
        self.addCleanup(self._ufw_patcher.stop)

        self.flask_app = app_module.create_app(self.config_path)
        self.client = self.flask_app.test_client()

    def tearDown(self) -> None:
        pass

    def _open_db(self) -> Database:
        """Open a fresh Database connection for assertions."""
        return Database(self.db_path)

    def _admin_header(self) -> str:
        return build_auth_header("admin", "admin-secret")

    def _alice_header(self) -> str:
        return build_auth_header("alice", "alice-secret")

    def _count_audit(self, action: str) -> int:
        """Count audit_log rows matching *action*."""
        db = self._open_db()
        try:
            row = db.conn.execute(
                "SELECT COUNT(*) AS c FROM audit_log WHERE action=?", (action,),
            ).fetchone()
            return row["c"]
        finally:
            db.close()

    # -- CLI: user-add ------------------------------------------------- #

    def test_cli_user_add_creates_user(self) -> None:
        args = _ns(config=self.config_path, username="bob", admin=False)
        app_module.cmd_user_add(args)

        db = self._open_db()
        try:
            user = db.get_user_by_username("bob")
            self.assertIsNotNone(user)
            self.assertEqual(user["is_admin"], 0)
            self.assertGreater(len(user["secret"]), 0)
        finally:
            db.close()
        self.assertGreaterEqual(self._count_audit("user_add"), 1)

    # -- CLI: user-list ------------------------------------------------ #

    def test_cli_user_list_outputs_users(self) -> None:
        args = _ns(config=self.config_path)
        app_module.cmd_user_list(args)

    # -- CLI: group-add ----------------------------------------------- #

    def test_cli_group_add_creates_group(self) -> None:
        args = _ns(config=self.config_path, name="ssh", port=22, proto="tcp")
        app_module.cmd_group_add(args)

        db = self._open_db()
        try:
            group = db.get_group_by_name("ssh")
            self.assertIsNotNone(group)
            self.assertEqual(group["port"], 22)
            self.assertEqual(group["proto"], "tcp")
        finally:
            db.close()
        self.assertGreaterEqual(self._count_audit("group_add"), 1)

    # -- CLI: user-join ----------------------------------------------- #

    def test_cli_user_join_creates_membership(self) -> None:
        args = _ns(config=self.config_path, username="alice", groupname="default-8080")
        app_module.cmd_user_join(args)

        db = self._open_db()
        try:
            groups = db.get_user_groups(self.alice_id, only_enabled=True)
            names = {g["name"] for g in groups}
            self.assertIn("default-8080", names)
        finally:
            db.close()
        self.assertGreaterEqual(self._count_audit("user_join"), 1)

    # -- API: GET /api/admin/users requires admin --------------------- #

    def test_api_get_users_requires_admin(self) -> None:
        resp = self.client.get(
            "/api/admin/users",
            headers={"Authorization": self._alice_header()},
        )
        self.assertEqual(resp.status_code, 403)
        data = resp.get_json()
        self.assertFalse(data["ok"])

    def test_api_get_users_admin_succeeds(self) -> None:
        resp = self.client.get(
            "/api/admin/users",
            headers={"Authorization": self._admin_header()},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["ok"])
        usernames = {u["username"] for u in data["users"]}
        self.assertIn("admin", usernames)
        self.assertIn("alice", usernames)
        for u in data["users"]:
            self.assertNotIn("secret", u)

    def test_api_get_users_no_auth_returns_401(self) -> None:
        resp = self.client.get("/api/admin/users")
        self.assertEqual(resp.status_code, 401)

    # -- API: POST /api/admin/users ----------------------------------- #

    def test_api_post_user_creates_and_audits(self) -> None:
        resp = self.client.post(
            "/api/admin/users",
            headers={"Authorization": self._admin_header()},
            json={"username": "carol", "is_admin": False},
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["username"], "carol")
        self.assertGreater(len(data["secret"]), 0)

        db = self._open_db()
        try:
            user = db.get_user_by_username("carol")
            self.assertIsNotNone(user)
        finally:
            db.close()
        self.assertGreaterEqual(self._count_audit("user_add"), 1)

    def test_api_post_user_duplicate_returns_409(self) -> None:
        resp = self.client.post(
            "/api/admin/users",
            headers={"Authorization": self._admin_header()},
            json={"username": "alice"},
        )
        self.assertEqual(resp.status_code, 409)

    # -- API: DELETE /api/admin/users/<id> ---------------------------- #

    def test_api_delete_user_removes_and_audits(self) -> None:
        create = self.client.post(
            "/api/admin/users",
            headers={"Authorization": self._admin_header()},
            json={"username": "dave"},
        )
        dave_id = create.get_json()["id"]

        resp = self.client.delete(
            f"/api/admin/users/{dave_id}",
            headers={"Authorization": self._admin_header()},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["ok"])

        db = self._open_db()
        try:
            self.assertIsNone(db.get_user(dave_id))
        finally:
            db.close()
        self.assertGreaterEqual(self._count_audit("user_del"), 1)

    def test_api_delete_user_not_found_returns_404(self) -> None:
        resp = self.client.delete(
            "/api/admin/users/999999",
            headers={"Authorization": self._admin_header()},
        )
        self.assertEqual(resp.status_code, 404)

    # -- API: GET/POST /api/admin/groups ------------------------------ #

    def test_api_get_groups_admin_succeeds(self) -> None:
        resp = self.client.get(
            "/api/admin/groups",
            headers={"Authorization": self._admin_header()},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["ok"])
        self.assertGreaterEqual(len(data["groups"]), 1)

    def test_api_post_group_creates(self) -> None:
        resp = self.client.post(
            "/api/admin/groups",
            headers={"Authorization": self._admin_header()},
            json={"name": "ssh-group", "port": 2222, "proto": "tcp"},
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["name"], "ssh-group")
        self.assertEqual(data["port"], 2222)

        db = self._open_db()
        try:
            group = db.get_group_by_name("ssh-group")
            self.assertIsNotNone(group)
        finally:
            db.close()
        self.assertGreaterEqual(self._count_audit("group_add"), 1)

    def test_api_post_groups_requires_admin(self) -> None:
        resp = self.client.post(
            "/api/admin/groups",
            headers={"Authorization": self._alice_header()},
            json={"name": "evil", "port": 6667},
        )
        self.assertEqual(resp.status_code, 403)

    # -- API: DELETE /api/admin/groups/<id> --------------------------- #

    def test_api_delete_group_removes_and_audits(self) -> None:
        create = self.client.post(
            "/api/admin/groups",
            headers={"Authorization": self._admin_header()},
            json={"name": "temp-group", "port": 9999},
        )
        gid = create.get_json()["id"]

        resp = self.client.delete(
            f"/api/admin/groups/{gid}",
            headers={"Authorization": self._admin_header()},
        )
        self.assertEqual(resp.status_code, 200)

        db = self._open_db()
        try:
            self.assertIsNone(db.get_group(gid))
        finally:
            db.close()
        self.assertGreaterEqual(self._count_audit("group_del"), 1)

    # -- API: POST /api/admin/users/<id>/groups ----------------------- #

    def test_api_post_membership_creates(self) -> None:
        resp = self.client.post(
            f"/api/admin/users/{self.alice_id}/groups",
            headers={"Authorization": self._admin_header()},
            json={"group_id": self.group_id, "enabled": True},
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["group_id"], self.group_id)

        db = self._open_db()
        try:
            groups = db.get_user_groups(self.alice_id, only_enabled=True)
            gids = {g["id"] for g in groups}
            self.assertIn(self.group_id, gids)
        finally:
            db.close()
        self.assertGreaterEqual(self._count_audit("user_join"), 1)

    def test_api_post_membership_user_not_found(self) -> None:
        resp = self.client.post(
            "/api/admin/users/999999/groups",
            headers={"Authorization": self._admin_header()},
            json={"group_id": self.group_id},
        )
        self.assertEqual(resp.status_code, 404)

    # -- Backward compat: /api/knock ---------------------------------- #

    def test_knock_backward_compat(self) -> None:
        """Existing HMAC header (non-admin) is still accepted on /api/knock."""
        resp = self.client.post(
            "/api/knock",
            headers={
                "Authorization": self._alice_header(),
                "X-Real-IP": "203.0.113.10",
            },
        )
        self.assertNotEqual(resp.status_code, 401)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["ip"], "203.0.113.10")

    def test_knock_rejects_bad_auth(self) -> None:
        resp = self.client.post(
            "/api/knock",
            headers={
                "Authorization": "HMAC-SHA256 alice:bad:bad",
                "X-Real-IP": "203.0.113.10",
            },
        )
        self.assertEqual(resp.status_code, 401)

    def test_status_backward_compat(self) -> None:
        """Existing /api/status endpoint still works with HMAC auth."""
        resp = self.client.get(
            "/api/status",
            headers={"Authorization": self._alice_header()},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["username"], "alice")


if __name__ == "__main__":
    unittest.main()
