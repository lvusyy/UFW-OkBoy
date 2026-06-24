"""Tests for the versioned DB migration mechanism (TASK-002/008)."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db import Database, CURRENT_SCHEMA_VERSION, MIGRATIONS


class TestMigrations(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="ufw-migration-test-")
        self.db_path = os.path.join(self.tmpdir, "test.db")

    def test_fresh_init_records_baseline_v1(self) -> None:
        db = Database(self.db_path)
        db.init()
        # Fresh init applies all migrations through the latest (v2 = TOTP cols).
        self.assertEqual(db.get_schema_version(), CURRENT_SCHEMA_VERSION)
        db.close()

    def test_pre_existing_db_records_baseline_without_reseed(self) -> None:
        """A v2.0 DB (6 tables, no schema_version) upgraded in place: record
        baseline v1 WITHOUT re-running the JSON import (no duplicate seeding)."""
        db = Database(self.db_path)
        # Simulate a pre-v2.1 install: create the data tables manually,
        # seed one user, but DO NOT create schema_version.
        db.conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT)")
        db.conn.execute("CREATE TABLE groups (id INTEGER PRIMARY KEY, name TEXT)")
        db.conn.execute("CREATE TABLE user_group_membership (user_id INT, group_id INT)")
        db.conn.execute("CREATE TABLE audit_log (id INTEGER PRIMARY KEY, actor TEXT)")
        db.conn.execute("CREATE TABLE operation_log (id INTEGER PRIMARY KEY, username TEXT)")
        db.conn.execute("CREATE TABLE failed_attempts (id INTEGER PRIMARY KEY, username TEXT)")
        db.conn.execute("INSERT INTO users (id, username) VALUES (1, 'preexisting')")
        db.conn.commit()
        db.run_migrations()
        # Migrations applied through latest; the pre-existing user is intact
        # (baseline v1 NOT re-seeded from JSON, v2 only ALTERs in TOTP columns).
        self.assertEqual(db.get_schema_version(), CURRENT_SCHEMA_VERSION)
        row = db.conn.execute("SELECT username FROM users WHERE id=1").fetchone()
        self.assertEqual(row["username"], "preexisting")
        db.close()

    def test_idempotent_reinit(self) -> None:
        """Re-running init() on an already-migrated DB applies nothing new."""
        db = Database(self.db_path)
        db.init()
        first = db.get_schema_version()
        applied = db.run_migrations()  # already current
        self.assertEqual(applied, [])
        self.assertEqual(db.get_schema_version(), first)
        db.close()

    def test_migrations_registry_nonempty(self) -> None:
        self.assertGreaterEqual(CURRENT_SCHEMA_VERSION, 1)
        self.assertTrue(any(v == 1 for v, _ in MIGRATIONS))

    def test_port_proto_unique_index_created_on_clean_db(self) -> None:
        """A fresh DB gets the defensive UNIQUE(port, proto) index on groups."""
        db = Database(self.db_path)
        db.init()
        idx = db.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' "
            "AND name='idx_groups_port_proto'"
        ).fetchone()
        self.assertIsNotNone(idx)
        db.close()

    def test_port_proto_index_skipped_when_duplicates_exist(self) -> None:
        """A legacy DB with duplicate (port, proto) groups must NOT crash the
        migration or lose data — the index is skipped; the app-level 409 check
        still guards new duplicates."""
        db = Database(self.db_path)
        db.init()
        db.conn.execute("DROP INDEX IF EXISTS idx_groups_port_proto")
        db.create_group("g1", 9000, "tcp")
        # Insert a raw duplicate (the index is gone, so SQLite allows it).
        db.conn.execute("INSERT INTO groups (name, port, proto) VALUES ('g2', 9000, 'tcp')")
        db.conn.commit()
        db._migration_004_groups_port_proto_unique()  # must not raise
        idx = db.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' "
            "AND name='idx_groups_port_proto'"
        ).fetchone()
        self.assertIsNone(idx)  # skipped — duplicates present
        count = db.conn.execute(
            "SELECT COUNT(*) AS c FROM groups WHERE port=9000"
        ).fetchone()["c"]
        self.assertEqual(count, 2)  # no data loss
        db.close()


if __name__ == "__main__":
    unittest.main()
