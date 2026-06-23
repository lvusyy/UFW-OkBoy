"""Tests for the upgrade command and version logic (TASK-003/008).

Network calls are mocked; only --check (notify-only) and version comparison
logic are exercised. The destructive --force path is NOT tested end-to-end
(it restarts the service).
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as app_module


class TestVersionCompare(unittest.TestCase):
    def test_ge_basic(self) -> None:
        self.assertTrue(app_module._ver_ge("2.1.0", "2.0.0"))
        self.assertFalse(app_module._ver_ge("2.0.0", "2.1.0"))
        self.assertTrue(app_module._ver_ge("2.1.0", "2.1.0"))

    def test_ge_different_length(self) -> None:
        self.assertTrue(app_module._ver_ge("3.0", "2.9.9"))
        self.assertTrue(app_module._ver_ge("2.1", "2.1.0"))

    def test_ge_with_v_prefix(self) -> None:
        self.assertTrue(app_module._ver_ge("v2.1.0", "2.0.0"))


class TestHealthCheck(unittest.TestCase):
    def test_health_check_success(self) -> None:
        resp = MagicMock()
        resp.status = 200
        resp.__enter__ = MagicMock(return_value=resp)
        resp.__exit__ = MagicMock(return_value=False)
        with patch("app.urllib.request.urlopen", return_value=resp):
            self.assertTrue(app_module._health_check())

    def test_health_check_failure(self) -> None:
        with patch("app.urllib.request.urlopen", side_effect=Exception("conn refused")):
            self.assertFalse(app_module._health_check(retries=1))


class TestUpgradeCheck(unittest.TestCase):
    """upgrade --check queries GitHub; mock it to verify notify-only behavior."""

    def _mock_release(self, tag: str):
        m = MagicMock()
        m.read.return_value = f'{{"tag_name": "{tag}"}}'.encode("utf-8")
        m.__enter__ = MagicMock(return_value=m)
        m.__exit__ = MagicMock(return_value=False)
        return m

    def test_check_up_to_date(self) -> None:
        # latest == current -> up to date; cmd_upgrade returns without exit.
        ns = MagicMock(config=None, check=True, force=False, yes=False)
        with patch("app.urllib.request.urlopen",
                   return_value=self._mock_release(app_module.__version__)):
            app_module.cmd_upgrade(ns)  # should return without exit

    def test_check_network_failure_is_safe(self) -> None:
        """If GitHub is unreachable, --check must not raise (graceful degrade)."""
        import urllib.error
        ns = MagicMock(config=None, check=True, force=False, yes=False)
        with patch("app.urllib.request.urlopen",
                   side_effect=urllib.error.URLError("network")):
            app_module.cmd_upgrade(ns)  # graceful: no exception


if __name__ == "__main__":
    unittest.main()
