"""Backup/restore tests — SQLite online backup API + checksum + retention.

Run from the server/ directory with:
    python -m unittest tests.test_backup -v
"""

import argparse
import os
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db import Database
import app as app_module


class TestBackupRestore(unittest.TestCase):

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="ufw-okboy-bak-")
        self.db_path = os.path.join(self.tmpdir, "live.db")
        self.config_path = self._write_config()

    def _write_config(self, **overrides) -> str:
        cfg = {
            "protected_ports": [8080], "proto": "tcp", "db_path": self.db_path,
            "rule_prefix": "ufw-okboy", "signature_ttl": 300,
            "users": {"alice": {"secret": "s"}},
        }
        cfg.update(overrides)
        path = os.path.join(self.tmpdir, f"config-{len(overrides)}.yaml")
        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(cfg, f)
        return path

    def test_backup_is_a_consistent_standalone_db(self) -> None:
        db = Database(self.db_path)
        db.init()
        db.create_user("u", "s")
        dest = os.path.join(self.tmpdir, "snap.db")
        db.backup(dest)
        db.close()
        b = Database(dest)
        try:
            row = b.conn.execute(
                "SELECT username FROM users WHERE username='u'",
            ).fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["username"], "u")
        finally:
            b.close()

    def test_checksum_stable_and_change_sensitive(self) -> None:
        p = os.path.join(self.tmpdir, "f.bin")
        with open(p, "wb") as f:
            f.write(b"hello")
        c1 = Database.checksum(p)
        self.assertEqual(c1, Database.checksum(p))
        with open(p, "ab") as f:
            f.write(b"!")
        self.assertNotEqual(c1, Database.checksum(p))

    def test_cmd_backup_writes_sidecar_and_prunes(self) -> None:
        bdir = os.path.join(self.tmpdir, "backups")
        cfg = self._write_config(backup_dir=bdir, backup_keep=2)
        Database(self.db_path).init()
        for _ in range(4):
            app_module.cmd_backup(argparse.Namespace(config=cfg, dir=None))
        dbs = sorted(Path(bdir).glob("ufw-okboy-*.db"))
        self.assertEqual(len(dbs), 2)
        for d in dbs:
            self.assertTrue(os.path.exists(str(d) + ".sha256"))

    def test_restore_roundtrip_reverts_post_backup_changes(self) -> None:
        db = Database(self.db_path)
        db.init()
        db.create_user("orig", "s")
        snap = os.path.join(self.tmpdir, "snap.db")
        db.backup(snap)
        with open(snap + ".sha256", "w", encoding="utf-8") as f:
            f.write(f"{Database.checksum(snap)}  snap.db\n")
        db.create_user("added_after", "s2")
        db.close()

        app_module.cmd_restore(
            argparse.Namespace(config=self.config_path, backup=snap),
        )
        db2 = Database(self.db_path)
        db2.init()
        try:
            self.assertIsNotNone(db2.get_user_by_username("orig"))
            self.assertIsNone(db2.get_user_by_username("added_after"))
        finally:
            db2.close()

    def test_restore_rejects_bad_checksum(self) -> None:
        db = Database(self.db_path)
        db.init()
        snap = os.path.join(self.tmpdir, "s.db")
        db.backup(snap)
        db.close()
        with open(snap + ".sha256", "w", encoding="utf-8") as f:
            f.write("deadbeef  s.db\n")
        with self.assertRaises(SystemExit):
            app_module.cmd_restore(
                argparse.Namespace(config=self.config_path, backup=snap),
            )


if __name__ == "__main__":
    unittest.main()
