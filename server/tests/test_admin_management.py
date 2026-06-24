"""Tests for admin per-user group listing and admin-flag toggle endpoints.

Run from the server/ directory with:
    python -m unittest tests.test_admin_management -v
"""

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
import app as app_module


def build_auth_header(username: str, secret: str) -> str:
    ts = int(time.time())
    sig = hmac.new(secret.encode(), f"{username}:{ts}".encode(), hashlib.sha256).hexdigest()
    return f"HMAC-SHA256 {username}:{ts}:{sig}"


class TestAdminManagement(unittest.TestCase):

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="ufw-okboy-adminmgmt-")
        self.db_path = os.path.join(self.tmpdir, "t.db")
        seed = Database(self.db_path)
        seed.init()
        self.admin_id = seed.create_user("admin", "admin-secret", is_admin=True)
        self.alice_id = seed.create_user("alice", "alice-secret")
        self.g1 = seed.create_group("web", 8080, "tcp")
        self.g2 = seed.create_group("ssh", 22, "tcp")
        seed.add_membership(self.alice_id, self.g1, enabled=1)  # member of web only
        seed.close()

        cfg = os.path.join(self.tmpdir, "c.yaml")
        with open(cfg, "w", encoding="utf-8") as f:
            yaml.dump({
                "protected_ports": [8080], "proto": "tcp", "db_path": self.db_path,
                "rule_prefix": "ufw-okboy",
                "users": {"admin": {"secret": "admin-secret"},
                          "alice": {"secret": "alice-secret"}},
            }, f)
        self._p = patch.object(UFWManager, "_run_ufw", return_value="")
        self._p.start()
        self.addCleanup(self._p.stop)
        self.client = app_module.create_app(cfg).test_client()

    def _admin(self):
        return {"Authorization": build_auth_header("admin", "admin-secret")}

    def _alice(self):
        return {"Authorization": build_auth_header("alice", "alice-secret")}

    def test_user_groups_reports_membership_state(self) -> None:
        data = self.client.get(
            f"/api/admin/users/{self.alice_id}/groups", headers=self._admin(),
        ).get_json()
        self.assertTrue(data["ok"])
        by_name = {g["name"]: g for g in data["groups"]}
        self.assertTrue(by_name["web"]["is_member"])
        self.assertTrue(by_name["web"]["enabled"])
        self.assertFalse(by_name["ssh"]["is_member"])

    def test_user_groups_requires_admin(self) -> None:
        r = self.client.get(
            f"/api/admin/users/{self.alice_id}/groups", headers=self._alice(),
        )
        self.assertEqual(r.status_code, 403)

    def test_set_admin_promotes_and_demotes(self) -> None:
        up = self.client.post(
            f"/api/admin/users/{self.alice_id}/admin",
            headers=self._admin(), json={"is_admin": True},
        )
        self.assertEqual(up.status_code, 200)
        db = Database(self.db_path)
        try:
            self.assertEqual(db.get_user(self.alice_id)["is_admin"], 1)
        finally:
            db.close()

    def test_set_admin_requires_admin(self) -> None:
        r = self.client.post(
            f"/api/admin/users/{self.alice_id}/admin",
            headers=self._alice(), json={"is_admin": True},
        )
        self.assertEqual(r.status_code, 403)


if __name__ == "__main__":
    unittest.main()
