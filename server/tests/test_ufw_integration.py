"""Real-ufw integration test for UFWManager's numbered deletes.

Skipped unless UFW_OKBOY_INTEGRATION=1: it changes the firewall of whatever it
runs on, so run it only in a throwaway network + mount namespace with a private
/etc/ufw, as root, e.g.:

    unshare --mount --net --fork bash -c '
        ip link set lo up; tmp=$(mktemp -d); cp -a /etc/ufw "$tmp"/ufw
        mount --bind "$tmp"/ufw /etc/ufw; ufw --force reset; ufw --force enable
        cd server && UFW_OKBOY_INTEGRATION=1 python -m unittest tests.test_ufw_integration -v'
"""

import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db import Database  # noqa: E402
from ufw_ops import UFWManager  # noqa: E402


def _ufw(*args: str) -> str:
    return subprocess.run(["ufw", *args], check=True, capture_output=True, text=True).stdout


@unittest.skipUnless(os.environ.get("UFW_OKBOY_INTEGRATION") == "1",
                     "changes the firewall: set UFW_OKBOY_INTEGRATION=1 in a sandbox")
class TestUfwIntegration(unittest.TestCase):

    def setUp(self) -> None:
        _ufw("--force", "reset")
        # enable can exit non-zero where kernel logging modules are missing (a
        # container) while the firewall itself is up: check the status instead.
        subprocess.run(["ufw", "--force", "enable"], capture_output=True)
        self.assertIn("Status: active", _ufw("status"))
        self.db = Database(os.path.join(tempfile.mkdtemp(prefix="ufw-okboy-it-"), "it.db"))
        self.db.init()
        self.ufw = UFWManager(rule_prefix="okboy-it", db=self.db)

    def tearDown(self) -> None:
        self.db.close()

    def _rules(self) -> list[str]:
        """Each rule as "<to> <action> <from> # <comment>", whitespace squeezed."""
        out = []
        for line in _ufw("status", "numbered").splitlines():
            if line.startswith("["):
                out.append(" ".join(line.split("]", 1)[1].split()))
        return out

    def test_moving_user_with_two_groups_keeps_host_rules(self) -> None:
        _ufw("allow", "22/tcp")
        self.ufw.add_rule("198.51.100.1", 8080, "alice", "tcp", "web")
        self.ufw.add_rule("198.51.100.1", 8443, "alice", "tcp", "api")
        _ufw("deny", "from", "192.0.2.66")
        self.ufw.reconcile_user_rules(
            "alice", "198.51.100.2", {"web": (8080, "tcp"), "api": (8443, "tcp")})
        self.assertEqual(self._rules(), [
            "22/tcp ALLOW IN Anywhere",
            "Anywhere DENY IN 192.0.2.66",
            "8080/tcp ALLOW IN 198.51.100.2 # okboy-it:alice:web",
            "8443/tcp ALLOW IN 198.51.100.2 # okboy-it:alice:api",
            "22/tcp (v6) ALLOW IN Anywhere (v6)",
        ])

    def test_ipv4_add_does_not_misdirect_an_ipv6_delete(self) -> None:
        _ufw("allow", "22/tcp")
        self.ufw.add_rule("2001:db8::5", 8080, "alice", "tcp", "web")
        _ufw("deny", "from", "2001:db8::66")
        self.ufw.reconcile_user_rules("alice", "198.51.100.2", {"web": (8080, "tcp")})
        self.assertEqual(self._rules(), [
            "22/tcp ALLOW IN Anywhere",
            "8080/tcp ALLOW IN 198.51.100.2 # okboy-it:alice:web",
            "22/tcp (v6) ALLOW IN Anywhere (v6)",
            "Anywhere (v6) DENY IN 2001:db8::66",
        ])

    def test_purge_and_remove_touch_only_the_owner(self) -> None:
        _ufw("allow", "22/tcp")
        self.ufw.add_rule("203.0.113.10", 8080, "alice", "tcp", "web")
        self.ufw.add_rule("198.51.100.99", 3306, "alice", "tcp", "db")   # a stale address
        _ufw("allow", "from", "any", "to", "any", "port", "9090", "proto", "tcp",
             "comment", "okboy-it:alice:web")  # an injected "any": an IPv4 and an IPv6 rule
        self.ufw.add_rule("203.0.113.11", 8080, "bob", "tcp", "web")     # behind the same NAT
        self.ufw.remove_rule("203.0.113.11", 8080, "alice", "tcp", "web")  # not alice's rule
        self.assertIn("8080/tcp ALLOW IN 203.0.113.11 # okboy-it:bob:web", self._rules())
        self.assertEqual(self.ufw.purge_rules(username="alice"), 4)
        self.assertEqual(self._rules(), [
            "22/tcp ALLOW IN Anywhere",
            "8080/tcp ALLOW IN 203.0.113.11 # okboy-it:bob:web",
            "22/tcp (v6) ALLOW IN Anywhere (v6)",
        ])


if __name__ == "__main__":
    unittest.main()
