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


if __name__ == "__main__":
    unittest.main()
