"""Unit tests for the SQLite Database layer (server/db.py).

Run from the server/ directory with:
    python -m unittest tests.test_db -v
"""

import json
import tempfile
import unittest
from pathlib import Path

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db import Database


class TestDatabase(unittest.TestCase):
    """Shared fixture: a fresh Database in a temporary directory."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="ufw-okboy-test-")
        self.db_path = os.path.join(self.tmpdir, "test.db")
        self.db = Database(self.db_path)
        self.db.init()

    def tearDown(self) -> None:
        self.db.close()

    # -- User CRUD ----------------------------------------------------- #

    def test_create_and_get_user(self) -> None:
        uid = self.db.create_user("alice", "secret-alice", is_admin=False)
        self.assertIsInstance(uid, int)
        self.assertGreater(uid, 0)

        row = self.db.get_user_by_username("alice")
        self.assertIsNotNone(row)
        self.assertEqual(row["username"], "alice")
        self.assertEqual(row["secret"], "secret-alice")
        self.assertEqual(row["is_admin"], 0)

        by_id = self.db.get_user(uid)
        self.assertIsNotNone(by_id)
        self.assertEqual(by_id["id"], uid)

        self.db.set_user_admin(uid, True)
        self.assertEqual(self.db.get_user(uid)["is_admin"], 1)

        users = self.db.list_users()
        self.assertEqual(len(users), 1)

        self.db.delete_user(uid)
        self.assertIsNone(self.db.get_user(uid))
        self.assertIsNone(self.db.get_user_by_username("alice"))

    # -- Group CRUD ---------------------------------------------------- #

    def test_group_crud(self) -> None:
        gid = self.db.create_group("default-8080", 8080, "tcp")
        self.assertGreater(gid, 0)

        row = self.db.get_group(gid)
        self.assertIsNotNone(row)
        self.assertEqual(row["name"], "default-8080")
        self.assertEqual(row["port"], 8080)
        self.assertEqual(row["proto"], "tcp")

        by_name = self.db.get_group_by_name("default-8080")
        self.assertIsNotNone(by_name)
        self.assertEqual(by_name["id"], gid)

        groups = self.db.list_groups()
        self.assertEqual(len(groups), 1)

        self.db.delete_group(gid)
        self.assertIsNone(self.db.get_group(gid))
        self.assertIsNone(self.db.get_group_by_name("default-8080"))

    # -- Membership ---------------------------------------------------- #

    def test_membership_toggle(self) -> None:
        uid = self.db.create_user("bob", "secret-bob")
        gid = self.db.create_group("default-22", 22)
        self.db.add_membership(uid, gid, enabled=1)

        members = self.db.get_group_members(gid)
        self.assertEqual(len(members), 1)
        self.assertEqual(members[0]["username"], "bob")

        self.db.set_membership_enabled(uid, gid, 0)
        all_groups = self.db.get_user_groups(uid, only_enabled=False)
        self.assertEqual(len(all_groups), 1)
        enabled_only = self.db.get_user_groups(uid, only_enabled=True)
        self.assertEqual(len(enabled_only), 0)

        self.db.set_membership_enabled(uid, gid, 1)
        self.assertEqual(len(self.db.get_user_groups(uid, only_enabled=True)), 1)

        self.db.remove_membership(uid, gid)
        self.assertEqual(len(self.db.get_user_groups(uid, only_enabled=False)), 0)

    def test_get_user_groups_only_enabled(self) -> None:
        uid = self.db.create_user("carol", "secret-carol")
        g1 = self.db.create_group("g1", 1001)
        g2 = self.db.create_group("g2", 1002)
        self.db.add_membership(uid, g1, enabled=1)
        self.db.add_membership(uid, g2, enabled=0)

        all_groups = self.db.get_user_groups(uid, only_enabled=False)
        self.assertEqual({g["name"] for g in all_groups}, {"g1", "g2"})

        enabled = self.db.get_user_groups(uid, only_enabled=True)
        self.assertEqual({g["name"] for g in enabled}, {"g1"})

    # -- Migration ----------------------------------------------------- #

    def test_migrate_from_json_creates_default_groups(self) -> None:
        config_users = {
            "alice": {"secret": "s1"},
            "bob": {"secret": "s2"},
        }
        state = {
            "alice": {"ip": "10.0.0.1", "last_knock": 1700000000},
        }
        state_path = os.path.join(self.tmpdir, "state.json")
        with open(state_path, "w", encoding="utf-8") as f:
            json.dump(state, f)

        self.db.migrate_from_json(state_path, config_users, [8080, 9090], "tcp")

        self.assertEqual(len(self.db.list_users()), 2)
        self.assertEqual(self.db.get_user_ip("alice"), "10.0.0.1")
        alice = self.db.get_user_by_username("alice")
        self.assertEqual(alice["last_knock"], 1700000000)

        g8080 = self.db.get_group_by_name("default-8080")
        g9090 = self.db.get_group_by_name("default-9090")
        self.assertIsNotNone(g8080)
        self.assertIsNotNone(g9090)
        self.assertEqual(g8080["port"], 8080)
        self.assertEqual(g9090["proto"], "tcp")

        alice_groups = self.db.get_user_groups(alice["id"], only_enabled=True)
        self.assertEqual({g["name"] for g in alice_groups}, {"default-8080", "default-9090"})

        bob = self.db.get_user_by_username("bob")
        bob_groups = self.db.get_user_groups(bob["id"], only_enabled=True)
        self.assertEqual(len(bob_groups), 2)

    def test_migrate_from_json_missing_file(self) -> None:
        config_users = {"dave": {"secret": "s3"}}
        missing = os.path.join(self.tmpdir, "no-such.json")
        self.db.migrate_from_json(missing, config_users, [443], "tcp")

        self.assertIsNotNone(self.db.get_user_by_username("dave"))
        self.assertIsNone(self.db.get_user_ip("dave"))
        self.assertIsNotNone(self.db.get_group_by_name("default-443"))

    # -- State queries ------------------------------------------------- #

    def test_state_queries(self) -> None:
        uid = self.db.create_user("eve", "secret-eve")

        self.assertIsNone(self.db.get_user_ip("eve"))
        self.assertIsNone(self.db.get_user_last_knock("eve"))

        self.db.set_user_ip(uid, "192.0.2.5")
        self.assertEqual(self.db.get_user_ip("eve"), "192.0.2.5")

        self.db.update_knock_time(uid, "192.0.2.5")
        self.assertIsNotNone(self.db.get_user_last_knock("eve"))

        self.assertEqual(self.db.count_recent_ip_changes("eve", 3600), 0)

        self.db.log_operation("eve", "ip_change", ip="192.0.2.5")
        self.db.log_operation("eve", "ip_change", ip="198.51.100.1")
        self.assertEqual(self.db.count_recent_ip_changes("eve", 3600), 2)

        ips = self.db.get_recent_ip_change_ips("eve", 3600)
        self.assertEqual(set(ips), {"192.0.2.5", "198.51.100.1"})

        self.db.clear_user_state(uid)
        self.assertIsNone(self.db.get_user_ip("eve"))
        self.assertIsNone(self.db.get_user_last_knock("eve"))

    def test_logging_helpers(self) -> None:
        self.db.log_audit("admin", "create_user", target="alice", detail="initial")
        self.db.log_operation("alice", "knock", ip="1.2.3.4")
        self.db.record_failed_attempt("mallory", "5.6.7.8", "bad signature")

        rows = self.db.conn.execute("SELECT * FROM audit_log").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["actor"], "admin")

        rows = self.db.conn.execute("SELECT * FROM operation_log").fetchall()
        self.assertEqual(len(rows), 1)

        rows = self.db.conn.execute("SELECT * FROM failed_attempts").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["reason"], "bad signature")

    def test_schema_has_six_tables(self) -> None:
        rows = self.db.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
        names = {r["name"] for r in rows}
        self.assertEqual(
            names,
            {"users", "groups", "user_group_membership", "audit_log", "operation_log", "failed_attempts"},
        )

    def test_foreign_key_cascade(self) -> None:
        uid = self.db.create_user("frank", "s")
        gid = self.db.create_group("g", 1234)
        self.db.add_membership(uid, gid)
        self.assertEqual(len(self.db.get_group_members(gid)), 1)

        self.db.delete_user(uid)
        self.assertEqual(len(self.db.get_group_members(gid)), 0)


if __name__ == "__main__":
    unittest.main()
