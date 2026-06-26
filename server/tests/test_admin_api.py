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
from unittest.mock import Mock, patch

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

    # -- JSON error contract (regression: SPA chokes on HTML error pages) -- #

    def test_unknown_api_route_returns_json(self) -> None:
        """An unknown /api/ path returns JSON 404, not Werkzeug's HTML page.

        The SPA parses every response as JSON; an HTML body surfaced to the user
        as the cryptic "Unexpected token '<'".
        """
        resp = self.client.get("/api/does-not-exist")
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(resp.mimetype, "application/json")
        self.assertFalse(resp.get_json()["ok"])

    def test_method_not_allowed_returns_json(self) -> None:
        """A wrong HTTP verb on an /api/ route returns JSON 405, not HTML."""
        resp = self.client.put("/api/admin/users")
        self.assertEqual(resp.status_code, 405)
        self.assertEqual(resp.mimetype, "application/json")
        self.assertFalse(resp.get_json()["ok"])

    def test_unhandled_exception_returns_json(self) -> None:
        """An unhandled error inside a handler returns JSON 500, not HTML."""
        with patch.object(Database, "list_users", side_effect=RuntimeError("boom")):
            resp = self.client.get(
                "/api/admin/users",
                headers={"Authorization": self._admin_header()},
            )
        self.assertEqual(resp.status_code, 500)
        self.assertEqual(resp.mimetype, "application/json")
        self.assertFalse(resp.get_json()["ok"])

    # -- input validation (names break the ':'-delimited UFW comment scheme) -- #

    def test_create_user_rejects_invalid_name(self) -> None:
        for bad in ["bad:name", "has space", "a" * 65, "x/y"]:
            resp = self.client.post(
                "/api/admin/users",
                headers={"Authorization": self._admin_header()},
                json={"username": bad},
            )
            self.assertEqual(resp.status_code, 400, f"name={bad!r}")
            self.assertFalse(resp.get_json()["ok"])

    def test_create_group_rejects_invalid_name(self) -> None:
        resp = self.client.post(
            "/api/admin/groups",
            headers={"Authorization": self._admin_header()},
            json={"name": "web:prod", "port": 9000},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertFalse(resp.get_json()["ok"])

    def test_create_group_rejects_out_of_range_port(self) -> None:
        for bad in [0, -1, 70000]:
            resp = self.client.post(
                "/api/admin/groups",
                headers={"Authorization": self._admin_header()},
                json={"name": "svc", "port": bad},
            )
            self.assertEqual(resp.status_code, 400, f"port={bad}")

    def test_add_membership_non_int_group_id_returns_400(self) -> None:
        create = self.client.post(
            "/api/admin/users",
            headers={"Authorization": self._admin_header()},
            json={"username": "bob"},
        )
        bob_id = create.get_json()["id"]
        resp = self.client.post(
            f"/api/admin/users/{bob_id}/groups",
            headers={"Authorization": self._admin_header()},
            json={"group_id": "not-an-int"},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertFalse(resp.get_json()["ok"])

    # -- system firewall rules (advanced / high-risk) ----------------- #

    _SAMPLE_UFW = (
        "Status: active\n"
        "\n"
        "     To                         Action      From\n"
        "     --                         ------      ----\n"
        "[ 1] 22/tcp                     ALLOW IN    Anywhere\n"
        "[ 2] 8080/tcp                   ALLOW IN    203.0.113.5"
        "                # ufw-okboy:alice:default-8080\n"
        "[ 3] 443                        ALLOW IN    Anywhere\n"
        "[ 4] OpenSSH                    ALLOW IN    Anywhere\n"
    )

    def test_ufw_list_all_rules_parses_numbered_output(self) -> None:
        """list_all_rules() parses `ufw status numbered`, flagging SSH + okboy rules.

        Splitting on the action keyword (not rigid columns) must handle bare
        ports, app profiles (OpenSSH), comments, and the okboy prefix.
        """
        db = self._open_db()
        try:
            ufw = UFWManager("ufw-okboy", db=db)
            with patch("ufw_ops.subprocess.run", return_value=Mock(stdout=self._SAMPLE_UFW)):
                rules = ufw.list_all_rules()
        finally:
            db.close()
        self.assertEqual([r["number"] for r in rules], [1, 2, 3, 4])
        by_num = {r["number"]: r for r in rules}
        self.assertTrue(by_num[1]["looks_like_ssh"])        # 22/tcp
        self.assertTrue(by_num[2]["is_okboy"])              # ufw-okboy comment
        self.assertFalse(by_num[2]["looks_like_ssh"])       # 8080 is not SSH
        self.assertFalse(by_num[3]["looks_like_ssh"])       # 443
        self.assertTrue(by_num[4]["looks_like_ssh"])        # OpenSSH profile
        self.assertEqual(by_num[2]["action"], "ALLOW IN")
        self.assertEqual(by_num[2]["from"], "203.0.113.5")
        self.assertEqual(by_num[2]["comment"], "ufw-okboy:alice:default-8080")

    _SSH_RULE = {
        "number": 1, "to": "22/tcp", "action": "ALLOW IN", "from": "Anywhere",
        "comment": "", "is_okboy": False, "looks_like_ssh": True,
    }
    _WEB_RULE = {
        "number": 2, "to": "8080/tcp", "action": "ALLOW IN", "from": "Anywhere",
        "comment": "", "is_okboy": False, "looks_like_ssh": False,
    }

    def test_api_ufw_rules_requires_admin(self) -> None:
        resp = self.client.get(
            "/api/admin/ufw/rules",
            headers={"Authorization": self._alice_header()},
        )
        self.assertEqual(resp.status_code, 403)

    def test_api_ufw_rules_admin_lists(self) -> None:
        with patch.object(UFWManager, "list_all_rules", return_value=[self._SSH_RULE]):
            resp = self.client.get(
                "/api/admin/ufw/rules",
                headers={"Authorization": self._admin_header()},
            )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["rules"], [self._SSH_RULE])

    def test_api_ufw_delete_ssh_requires_confirm(self) -> None:
        """Deleting an SSH-looking rule without confirm_ssh → 409, no actual delete."""
        with patch.object(UFWManager, "list_all_rules", return_value=[self._SSH_RULE]), \
                patch.object(UFWManager, "delete_rule") as mdel:
            resp = self.client.post(
                "/api/admin/ufw/delete",
                headers={"Authorization": self._admin_header()},
                json={"number": 1},
            )
        self.assertEqual(resp.status_code, 409)
        self.assertTrue(resp.get_json()["ssh_warning"])
        mdel.assert_not_called()

    def test_api_ufw_delete_ssh_confirmed_deletes_and_audits(self) -> None:
        with patch.object(UFWManager, "list_all_rules", return_value=[self._SSH_RULE]), \
                patch.object(UFWManager, "delete_rule") as mdel:
            resp = self.client.post(
                "/api/admin/ufw/delete",
                headers={"Authorization": self._admin_header()},
                json={"number": 1, "confirm_ssh": True},
            )
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.get_json()["ok"])
        mdel.assert_called_once_with(1)
        self.assertGreaterEqual(self._count_audit("ufw_rule_delete"), 1)

    def test_api_ufw_delete_non_ssh_deletes_without_confirm(self) -> None:
        with patch.object(UFWManager, "list_all_rules", return_value=[self._WEB_RULE]), \
                patch.object(UFWManager, "delete_rule") as mdel:
            resp = self.client.post(
                "/api/admin/ufw/delete",
                headers={"Authorization": self._admin_header()},
                json={"number": 2},
            )
        self.assertEqual(resp.status_code, 200)
        mdel.assert_called_once_with(2)

    def test_api_ufw_delete_not_found_returns_404(self) -> None:
        with patch.object(UFWManager, "list_all_rules", return_value=[]):
            resp = self.client.post(
                "/api/admin/ufw/delete",
                headers={"Authorization": self._admin_header()},
                json={"number": 99},
            )
        self.assertEqual(resp.status_code, 404)

    def test_api_ufw_delete_non_int_returns_400(self) -> None:
        resp = self.client.post(
            "/api/admin/ufw/delete",
            headers={"Authorization": self._admin_header()},
            json={"number": "abc"},
        )
        self.assertEqual(resp.status_code, 400)

    def test_api_ufw_delete_requires_admin(self) -> None:
        resp = self.client.post(
            "/api/admin/ufw/delete",
            headers={"Authorization": self._alice_header()},
            json={"number": 1},
        )
        self.assertEqual(resp.status_code, 403)


if __name__ == "__main__":
    unittest.main()
