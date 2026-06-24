"""Tests for membership-toggle refinements H-10 (404-before-403) and H-11
(idempotent re-enable via reconcile).

Run from the server/ directory with:
    python -m unittest tests.test_membership_toggle -v
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


class TestMembershipToggle(unittest.TestCase):

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="ufw-okboy-toggle-")
        self.db_path = os.path.join(self.tmpdir, "t.db")
        seed = Database(self.db_path)
        seed.init()
        self.alice_id = seed.create_user("alice", "alice-secret")
        self.group_id = seed.create_group("web", 8080, "tcp")
        seed.add_membership(self.alice_id, self.group_id, enabled=1)
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

    def _alice(self) -> str:
        return build_auth_header("alice", "alice-secret")

    def test_h10_nonexistent_group_returns_404_not_403(self) -> None:
        """Self-enabling a typo'd group_id is reported as 404, not a misleading 403."""
        r = self.client.patch(
            "/api/me/membership/999999",
            headers={"Authorization": self._alice()},
            json={"enabled": True},
        )
        self.assertEqual(r.status_code, 404)

    def test_h11_reenable_is_idempotent(self) -> None:
        """Re-enabling an authorized group while online succeeds (reconcile, no
        duplicate-add error)."""
        # Bring alice online so the enable path touches UFW.
        self.client.post(
            "/api/knock",
            headers={"Authorization": self._alice(), "X-Real-IP": "203.0.113.5"},
        )
        r = self.client.patch(
            f"/api/me/membership/{self.group_id}",
            headers={"Authorization": self._alice()},
            json={"enabled": True},
        )
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["enabled"])


if __name__ == "__main__":
    unittest.main()
