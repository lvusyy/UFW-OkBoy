"""Tests for the public sample-secret fix (v2.2.2).

Up to v2.2.1 the installers copied config.example.yaml verbatim, and the first
run seeded its sample user "alice", whose secret is published in this repo.

Run from the server/ directory with:
    python -m unittest tests.test_placeholder_seed -v
"""

import hashlib
import hmac
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db import Database, is_placeholder_secret
from ufw_ops import UFWManager
import app as app_module

SAMPLE_SECRET = "CHANGE_ME_run_python_app_py_gen_secret_alice"
EXAMPLE_CONFIG = Path(__file__).resolve().parents[1] / "config.example.yaml"


def build_auth_header(username: str, secret: str) -> str:
    """Build an HMAC-SHA256 Authorization header (mirrors knock.py)."""
    message = f"{username}:{int(time.time())}"
    signature = hmac.new(secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"HMAC-SHA256 {message}:{signature}"


class TestPlaceholderSeed(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="ufw-okboy-seed-test-")
        self.db_path = os.path.join(self.tmpdir, "test.db")
        self.state_path = os.path.join(self.tmpdir, "state.json")

    def _write_config(self, cfg: dict) -> str:
        path = os.path.join(self.tmpdir, "config.yaml")
        with open(path, "w", encoding="utf-8") as f:
            yaml.dump({"db_path": self.db_path, "state_file": self.state_path, **cfg}, f)
        return path

    def _seed_v221_install(self) -> int:
        """Build the DB a v2.2.1 install left behind: sample user in default-8080, schema v4."""
        db = Database(self.db_path)
        db.init()
        alice = db.create_user("alice", SAMPLE_SECRET)
        db.add_membership(alice, db.create_group("default-8080", 8080, "tcp"))
        db.set_user_ip(alice, "203.0.113.7")
        db.conn.execute("DELETE FROM schema_version WHERE version >= 5")  # v2.2.1 stopped at 4
        db.conn.commit()
        db.close()
        return alice

    def test_example_config_seeds_nothing(self) -> None:
        """The shipped example (what the installers copy) creates no user or group."""
        with open(EXAMPLE_CONFIG, encoding="utf-8") as f:
            example = yaml.safe_load(f)
        example.pop("db_path", None)
        example.pop("state_file", None)
        db = app_module.open_database(app_module.load_config(self._write_config(example)))
        try:
            self.assertEqual(db.list_users(), [])
            self.assertEqual(db.list_groups(), [])
        finally:
            db.close()

    def test_sample_secret_in_old_config_is_replaced(self) -> None:
        """An old config.yaml still carrying the sample user seeds it with a random secret."""
        cfg = app_module.load_config(self._write_config({
            "protected_ports": [8080],
            "users": {"alice": {"secret": SAMPLE_SECRET}, "bob": {"secret": "b" * 64},
                      "carol": {"secret": 1234567890123456}},  # unquoted digits load as an int
        }))
        db = app_module.open_database(cfg)
        try:
            alice = db.get_user_by_username("alice")
            self.assertFalse(is_placeholder_secret(alice["secret"]))
            self.assertEqual(len(alice["secret"]), 64)
            self.assertEqual(db.get_user_by_username("bob")["secret"], "b" * 64)
            self.assertEqual(db.get_user_by_username("carol")["secret"], "1234567890123456")
        finally:
            db.close()

    def test_legacy_state_keeps_sample_user_ip(self) -> None:
        """A v1 upgrade keeps tracking the IP the sample user already opened, so
        cleanup / revoke / user-del can still close that rule."""
        with open(self.state_path, "w", encoding="utf-8") as f:
            json.dump({"alice": {"ip": "203.0.113.7", "last_knock": 1700000000}}, f)
        cfg = app_module.load_config(self._write_config({
            "protected_ports": [8080],
            "users": {"alice": {"secret": SAMPLE_SECRET}},
        }))
        db = app_module.open_database(cfg)
        try:
            alice = db.get_user_by_username("alice")
            self.assertFalse(is_placeholder_secret(alice["secret"]))
            self.assertEqual(alice["current_ip"], "203.0.113.7")
            self.assertEqual([g["name"] for g in db.get_user_groups(alice["id"])], ["default-8080"])
        finally:
            db.close()

    def test_migration_rotates_seeded_sample_secret(self) -> None:
        """Upgrading rotates the published secret but keeps the user, groups and IP."""
        alice = self._seed_v221_install()
        db = Database(self.db_path)
        db.create_user("bob", "b" * 64)
        try:
            self.assertEqual(db.run_migrations(), [5, 6])
            row = db.get_user_by_username("alice")
            self.assertFalse(is_placeholder_secret(row["secret"]))
            self.assertEqual(len(row["secret"]), 64)
            # The IP stays so `revoke` / `user-del` can still find and close its rules.
            self.assertEqual(row["current_ip"], "203.0.113.7")
            self.assertEqual([g["name"] for g in db.get_user_groups(alice)], ["default-8080"])
            self.assertEqual(db.get_user_by_username("bob")["secret"], "b" * 64)
            audit = db.conn.execute(
                "SELECT target FROM audit_log WHERE action = 'rotate_placeholder_secret'"
            ).fetchall()
            self.assertEqual([r["target"] for r in audit], ["alice"])
        finally:
            db.close()

    def test_upgraded_install_rejects_sample_secret(self) -> None:
        """End to end: once the upgraded app starts, the published secret cannot knock."""
        self._seed_v221_install()
        config_path = self._write_config({
            "protected_ports": [8080],
            "users": {"alice": {"secret": SAMPLE_SECRET}},
        })
        with patch.object(UFWManager, "_run_ufw", return_value=""):
            client = app_module.create_app(config_path).test_client()
            resp = client.post(
                "/api/knock",
                headers={"Authorization": build_auth_header("alice", SAMPLE_SECRET),
                         "X-Real-IP": "198.51.100.9"},
            )
        self.assertEqual(resp.status_code, 401)

    def test_admin_api_rejects_sample_secret(self) -> None:
        """An admin cannot create a user with the published secret (a random one is fine)."""
        db = Database(self.db_path)
        db.init()
        db.create_user("admin", "a" * 64, is_admin=True)
        db.close()
        config_path = self._write_config({})
        with patch.object(UFWManager, "_run_ufw", return_value=""):
            client = app_module.create_app(config_path).test_client()

            def create_user(body: dict) -> int:
                return client.post(
                    "/api/admin/users", json=body,
                    headers={"Authorization": build_auth_header("admin", "a" * 64)},
                ).status_code

            self.assertEqual(create_user({"username": "alice", "secret": SAMPLE_SECRET}), 400)
            self.assertEqual(create_user({"username": "alice", "secret": 123}), 400)
            self.assertEqual(create_user({"username": "alice"}), 201)


if __name__ == "__main__":
    unittest.main()
