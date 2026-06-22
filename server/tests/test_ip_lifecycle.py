"""Unit tests for group-aware IP lifecycle (TASK-003).

Covers the /api/knock group-aware rule management, the
PATCH /api/membership toggle endpoint, and the group-suffixed UFW
comment format.

Run from the server/ directory with:
    python -m unittest tests.test_ip_lifecycle -v
"""

import hashlib
import hmac
import json
import os
import sys
import tempfile
import time
import unittest

import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db import Database
from ufw_ops import UFWManager
from app import create_app


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


class StubUFWManager(UFWManager):
    """UFWManager subclass that records add_rule/remove_rule calls without running ufw."""

    def __init__(self, db: Database) -> None:
        super().__init__(rule_prefix="ufw-okboy", db=db)
        self.add_calls: list[dict] = []
        self.remove_calls: list[dict] = []

    def add_rule(self, ip: str, port: int, username: str, proto: str = "tcp",
                 group: str | None = None) -> None:
        self.add_calls.append({
            "ip": ip, "port": port, "username": username,
            "proto": proto, "group": group,
        })

    def remove_rule(self, ip: str, port: int, username: str, proto: str = "tcp",
                    group: str | None = None) -> None:
        self.remove_calls.append({
            "ip": ip, "port": port, "username": username,
            "proto": proto, "group": group,
        })


class CommentCaptureUFW(UFWManager):
    """UFWManager subclass that captures raw _run_ufw args to verify comment text."""

    def __init__(self, db: Database) -> None:
        super().__init__(rule_prefix="ufw-okboy", db=db)
        self.captured: list[tuple] = []

    def _run_ufw(self, *args: str) -> str:
        self.captured.append(args)
        return ""


class TestIPLifecycle(unittest.TestCase):
    """Shared fixture: temp DB seeded with one user and two groups (one enabled, one disabled)."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="ufw-okboy-lifecycle-test-")
        self.db_path = os.path.join(self.tmpdir, "test.db")
        self.db = Database(self.db_path)
        self.db.init()

        self.secret = "secret-alice"
        self.user_id = self.db.create_user("alice", self.secret, is_admin=False)
        self.g_web_id = self.db.create_group("web", 8080, "tcp")
        self.g_db_id = self.db.create_group("db", 3306, "tcp")
        self.db.add_membership(self.user_id, self.g_web_id, enabled=1)
        self.db.add_membership(self.user_id, self.g_db_id, enabled=0)

        self.ufw = StubUFWManager(self.db)

        self.config_path = os.path.join(self.tmpdir, "config.yaml")
        with open(self.config_path, "w", encoding="utf-8") as f:
            yaml.dump({
                "protected_ports": [8080],
                "proto": "tcp",
                "users": {"alice": {"secret": self.secret}},
                "db_path": self.db_path,
                "signature_ttl": 300,
            }, f)

        self.app = create_app(
            self.config_path, db_override=self.db, ufw_override=self.ufw,
        )
        self.client = self.app.test_client()

    def tearDown(self) -> None:
        self.db.close()

    def _auth_header(self) -> str:
        return build_auth_header("alice", self.secret)

    def _knock(self, ip: str = "203.0.113.10"):
        return self.client.post(
            "/api/knock",
            headers={"Authorization": self._auth_header(), "X-Real-IP": ip},
        )

    def _toggle(self, user_id: int, group_id: int, enabled: bool):
        return self.client.patch(
            f"/api/membership/{user_id}/{group_id}",
            data=json.dumps({"enabled": enabled}),
            content_type="application/json",
            headers={"Authorization": self._auth_header()},
        )

    # -- knock group-aware --------------------------------------------- #

    def test_knock_creates_rules_only_for_enabled_groups(self) -> None:
        resp = self._knock("203.0.113.10")
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertTrue(body["ok"])
        self.assertTrue(body["changed"])

        self.assertEqual(len(self.ufw.add_calls), 1)
        call = self.ufw.add_calls[0]
        self.assertEqual(call["ip"], "203.0.113.10")
        self.assertEqual(call["port"], 8080)
        self.assertEqual(call["proto"], "tcp")
        self.assertEqual(call["group"], "web")
        self.assertEqual(call["username"], "alice")

        ports_added = {c["port"] for c in self.ufw.add_calls}
        self.assertNotIn(3306, ports_added)

    def test_knock_ip_change_removes_old_from_all_enabled(self) -> None:
        self._knock("203.0.113.10")
        self.ufw.add_calls.clear()
        self.ufw.remove_calls.clear()

        resp = self._knock("198.51.100.7")
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertTrue(body["changed"])
        self.assertEqual(body["old_ip"], "203.0.113.10")

        self.assertEqual(len(self.ufw.remove_calls), 1)
        rm = self.ufw.remove_calls[0]
        self.assertEqual(rm["ip"], "203.0.113.10")
        self.assertEqual(rm["port"], 8080)
        self.assertEqual(rm["group"], "web")

        self.assertEqual(len(self.ufw.add_calls), 1)
        add = self.ufw.add_calls[0]
        self.assertEqual(add["ip"], "198.51.100.7")
        self.assertEqual(add["port"], 8080)

    def test_disabled_group_excluded_from_knock(self) -> None:
        resp = self._knock("203.0.113.20")
        self.assertEqual(resp.status_code, 200)

        groups_added = {c["group"] for c in self.ufw.add_calls}
        self.assertIn("web", groups_added)
        self.assertNotIn("db", groups_added)

        body = resp.get_json()
        self.assertEqual(body["groups"], ["web"])

    def test_knock_heartbeat_no_rule_changes(self) -> None:
        self._knock("203.0.113.30")
        self.ufw.add_calls.clear()
        self.ufw.remove_calls.clear()

        resp = self._knock("203.0.113.30")
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertFalse(body["changed"])
        self.assertEqual(len(self.ufw.add_calls), 0)
        self.assertEqual(len(self.ufw.remove_calls), 0)

    # -- membership toggle --------------------------------------------- #

    def test_toggle_membership_off_removes_rules(self) -> None:
        self._knock("203.0.113.40")
        self.ufw.add_calls.clear()
        self.ufw.remove_calls.clear()

        resp = self._toggle(self.user_id, self.g_web_id, enabled=False)
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertTrue(body["ok"])
        self.assertFalse(body["enabled"])

        self.assertEqual(len(self.ufw.remove_calls), 1)
        rm = self.ufw.remove_calls[0]
        self.assertEqual(rm["ip"], "203.0.113.40")
        self.assertEqual(rm["port"], 8080)
        self.assertEqual(rm["group"], "web")
        self.assertEqual(len(self.ufw.add_calls), 0)

    def test_toggle_membership_on_adds_rules(self) -> None:
        self._knock("203.0.113.50")
        self.ufw.add_calls.clear()
        self.ufw.remove_calls.clear()

        resp = self._toggle(self.user_id, self.g_db_id, enabled=True)
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertTrue(body["ok"])
        self.assertTrue(body["enabled"])

        self.assertEqual(len(self.ufw.add_calls), 1)
        add = self.ufw.add_calls[0]
        self.assertEqual(add["ip"], "203.0.113.50")
        self.assertEqual(add["port"], 3306)
        self.assertEqual(add["group"], "db")
        self.assertEqual(len(self.ufw.remove_calls), 0)

    def test_toggle_membership_forbidden_for_other_user(self) -> None:
        other_id = self.db.create_user("bob", "secret-bob", is_admin=False)
        resp = self.client.patch(
            f"/api/membership/{other_id}/{self.g_web_id}",
            data=json.dumps({"enabled": False}),
            content_type="application/json",
            headers={"Authorization": self._auth_header()},
        )
        self.assertEqual(resp.status_code, 403)

    def test_toggle_membership_requires_enabled_bool(self) -> None:
        resp = self.client.patch(
            f"/api/membership/{self.user_id}/{self.g_web_id}",
            data=json.dumps({"enabled": "maybe"}),
            content_type="application/json",
            headers={"Authorization": self._auth_header()},
        )
        self.assertEqual(resp.status_code, 400)

    # -- status includes groups ---------------------------------------- #

    def test_status_includes_enabled_groups(self) -> None:
        resp = self.client.get(
            "/api/status",
            headers={"Authorization": self._auth_header()},
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertTrue(body["ok"])
        names = {g["name"] for g in body["enabled_groups"]}
        self.assertEqual(names, {"web"})

    # -- ufw comment format -------------------------------------------- #

    def test_add_rule_comment_includes_group_suffix(self) -> None:
        ufw = CommentCaptureUFW(self.db)
        ufw.add_rule("1.2.3.4", 8080, "alice", "tcp", group="web")
        args = ufw.captured[0]
        comment = args[args.index("comment") + 1]
        self.assertEqual(comment, "ufw-okboy:alice:web")

    def test_add_rule_comment_backward_compatible(self) -> None:
        ufw = CommentCaptureUFW(self.db)
        ufw.add_rule("1.2.3.4", 8080, "alice", "tcp")
        args = ufw.captured[0]
        comment = args[args.index("comment") + 1]
        self.assertEqual(comment, "ufw-okboy:alice")


if __name__ == "__main__":
    unittest.main()
