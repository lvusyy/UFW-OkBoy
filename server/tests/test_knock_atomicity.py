"""Unit tests for D5 — atomic IP-change write in the knock path.

`db.record_ip_change` must apply the current_ip/last_knock update and the
ip_change operation-log row in a single transaction, so an interrupted knock
never leaves the anomaly/audit trail out of sync with the stored IP.

Run from the server/ directory with:
    python -m unittest tests.test_knock_atomicity -v
"""

import hashlib
import hmac
import os
import sqlite3
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


def build_auth_header(username: str, secret: str, ts: int | None = None) -> str:
    ts = int(time.time()) if ts is None else ts
    sig = hmac.new(secret.encode(), f"{username}:{ts}".encode(), hashlib.sha256).hexdigest()
    return f"HMAC-SHA256 {username}:{ts}:{sig}"


class TestRecordIpChange(unittest.TestCase):

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="ufw-okboy-atom-")
        self.db = Database(os.path.join(self.tmpdir, "t.db"))
        self.db.init()
        self.uid = self.db.create_user("u", "s")

    def tearDown(self) -> None:
        self.db.close()

    def test_applies_ip_knock_and_log_together(self) -> None:
        self.db.record_ip_change(self.uid, "u", "2.2.2.2", "1.1.1.1")
        user = self.db.get_user(self.uid)
        self.assertEqual(user["current_ip"], "2.2.2.2")
        self.assertIsNotNone(user["last_knock"])
        rows = self.db.conn.execute(
            "SELECT ip, detail FROM operation_log WHERE action='ip_change'",
        ).fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["ip"], "2.2.2.2")
        self.assertEqual(rows[0]["detail"], "old=1.1.1.1")

    def test_rolls_back_completely_on_failure(self) -> None:
        self.db.set_user_ip(self.uid, "1.1.1.1")
        # username=None violates operation_log.username NOT NULL → the INSERT
        # fails AFTER the UPDATE; the whole transaction must roll back.
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.record_ip_change(self.uid, None, "2.2.2.2", "1.1.1.1")
        # UPDATE reverted — current_ip unchanged, no partial log row.
        self.assertEqual(self.db.get_user(self.uid)["current_ip"], "1.1.1.1")
        count = self.db.conn.execute(
            "SELECT COUNT(*) AS c FROM operation_log",
        ).fetchone()["c"]
        self.assertEqual(count, 0)


class TestKnockEndToEnd(unittest.TestCase):

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="ufw-okboy-atom-e2e-")
        self.db_path = os.path.join(self.tmpdir, "t.db")
        seed = Database(self.db_path)
        seed.init()
        aid = seed.create_user("alice", "alice-secret")
        gid = seed.create_group("default-8080", 8080, "tcp")
        seed.add_membership(aid, gid, enabled=1)
        seed.close()

        cfg = os.path.join(self.tmpdir, "c.yaml")
        with open(cfg, "w", encoding="utf-8") as f:
            yaml.dump({
                "protected_ports": [8080], "proto": "tcp", "db_path": self.db_path,
                "rule_prefix": "ufw-okboy", "users": {"alice": {"secret": "alice-secret"}},
            }, f)
        self._p = patch.object(UFWManager, "_run_ufw", return_value="")
        self._p.start()
        self.addCleanup(self._p.stop)
        self.client = app_module.create_app(cfg).test_client()

    def _knock(self, ip):
        return self.client.post(
            "/api/knock",
            headers={"Authorization": build_auth_header("alice", "alice-secret"),
                     "X-Real-IP": ip},
        )

    def test_ip_change_leaves_consistent_state(self) -> None:
        self.assertEqual(self._knock("203.0.113.1").status_code, 200)
        r = self._knock("203.0.113.2")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["changed"])

        db = Database(self.db_path)
        try:
            user = db.get_user_by_username("alice")
            self.assertEqual(user["current_ip"], "203.0.113.2")
            # The latest ip_change row matches the stored IP (state ↔ log in sync).
            latest = db.conn.execute(
                "SELECT ip, detail FROM operation_log WHERE action='ip_change' "
                "ORDER BY id DESC LIMIT 1",
            ).fetchone()
            self.assertEqual(latest["ip"], "203.0.113.2")
            self.assertEqual(latest["detail"], "old=203.0.113.1")
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
