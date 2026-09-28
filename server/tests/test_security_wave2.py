"""Security wave 2: numbered deletes, client IP, TOTP caps, host lock, files.

Run from the server/ directory with:
    python -m unittest tests.test_security_wave2 -v
"""

import hashlib
import hmac
import os
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import auth  # noqa: E402
from app import create_app, open_database  # noqa: E402
from db import Database  # noqa: E402
from ufw_ops import HostLock, UFWManager, canonical_ip, fcntl  # noqa: E402


def build_auth_header(username: str, secret: str) -> str:
    """An HMAC-SHA256 Authorization header, as the clients build it."""
    ts = int(time.time())
    sig = hmac.new(secret.encode(), f"{username}:{ts}".encode(), hashlib.sha256).hexdigest()
    return f"HMAC-SHA256 {username}:{ts}:{sig}"


class FakeUfw:
    """A ufw rule table standing in for subprocess.run, faithful where the
    numbered deletes depend on it: IPv4 rules are listed before IPv6 ones (each
    family in the order added), `status numbered` numbers them from 1, and
    `--force delete N` removes the N-th, renumbering every rule after it. Adding
    a rule that differs from an existing one only in its comment rewrites that
    comment (ufw 0.36); a rule from "any" becomes two, listed as "Anywhere"
    and, in the IPv6 part, "PORT/PROTO (v6) ... Anywhere (v6)"."""

    def __init__(self) -> None:
        self.v4: list[tuple] = []
        self.v6: list[tuple] = []
        self.fail_deletes = False  # make every delete fail, as a wedged ufw would

    def add(self, to: str, action: str, frm: str, comment: str = "", v6: bool = False) -> None:
        table = self.v6 if v6 else self.v4
        for i, (t, a, f, _) in enumerate(table):
            if (t, a, f) == (to, action, frm):
                table[i] = (to, action, frm, comment)
                return
        table.append((to, action, frm, comment))

    def rules(self) -> list[tuple]:
        return self.v4 + self.v6

    def _render(self) -> str:
        lines = ["Status: active", "", "     To                         Action      From",
                 "     --                         ------      ----"]
        for i, (to, action, frm, comment) in enumerate(self.rules(), 1):
            line = f"[{i:2d}] {to:<26} {action:<11} {frm:<26}"
            lines.append(f"{line} # {comment}" if comment else line.rstrip())
        return "\n".join(lines) + "\n"

    def _delete_number(self, n: int) -> None:
        if n <= len(self.v4):
            del self.v4[n - 1]
        else:
            del self.v6[n - 1 - len(self.v4)]

    def __call__(self, cmd, **kwargs):
        args = list(cmd[1:])
        rc, out = 0, ""
        if args == ["status", "numbered"]:
            out = self._render()
        elif args[:2] == ["--force", "delete"] and len(args) == 3 and args[2].isdigit():
            if self.fail_deletes:
                rc = 1
            else:
                self._delete_number(int(args[2]))
        elif args[:3] == ["--force", "delete", "allow"]:
            # --force delete allow from IP to any port P proto X
            ip, port, proto = args[4], args[8], args[10]
            want = (f"{port}/{proto}", "ALLOW IN", "Anywhere" if ip == "any" else ip)
            for n, rule in enumerate(self.rules(), 1):
                if rule[:3] == want:
                    self._delete_number(n)
                    break
            else:
                rc = 1
        elif args[:2] == ["allow", "from"]:
            # allow from IP to any port P proto X comment C
            ip, port, proto, comment = args[2], args[6], args[8], args[10]
            if ip == "any":
                self.add(f"{port}/{proto}", "ALLOW IN", "Anywhere", comment)
                self.add(f"{port}/{proto} (v6)", "ALLOW IN", "Anywhere (v6)", comment, v6=True)
            else:
                self.add(f"{port}/{proto}", "ALLOW IN", ip, comment, v6=":" in ip)
        else:
            raise AssertionError(f"unexpected ufw call: {args}")
        return subprocess.CompletedProcess(cmd, rc, stdout=out, stderr="" if rc == 0 else "error")


class _Base(unittest.TestCase):
    """Temp DB + a real UFWManager whose ufw is a FakeUfw."""

    config: dict = {}

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="ufw-okboy-wave2-")
        self.db_path = os.path.join(self.tmpdir, "test.db")
        self.db = Database(self.db_path)
        self.db.init()
        self.ufw = UFWManager(rule_prefix="ufw-okboy", db=self.db)
        self.fake = FakeUfw()
        self._p = patch("ufw_ops.subprocess.run", self.fake)
        self._p.start()
        self.addCleanup(self._p.stop)
        self.config_path = os.path.join(self.tmpdir, "config.yaml")
        with open(self.config_path, "w", encoding="utf-8") as f:
            yaml.dump({"db_path": self.db_path, "signature_ttl": 300, **self.config}, f)
        self.app = create_app(self.config_path, db_override=self.db, ufw_override=self.ufw)
        self.client = self.app.test_client()

    def tearDown(self) -> None:
        self.db.close()


class TestNumberedDeletes(_Base):
    """reconcile deleted several stale rules by the numbers of ONE listing: each
    delete shifted the rules after it, so the next one hit a different rule."""

    def test_moving_user_keeps_neighbouring_rules(self) -> None:
        f = self.fake
        f.add("22/tcp", "ALLOW IN", "Anywhere")
        f.add("8080/tcp", "ALLOW IN", "198.51.100.1", "ufw-okboy:alice:web")
        f.add("8443/tcp", "ALLOW IN", "198.51.100.1", "ufw-okboy:alice:api")
        f.add("Anywhere", "DENY IN", "192.0.2.66")  # the host blocks an attacker
        f.add("22/tcp (v6)", "ALLOW IN", "Anywhere (v6)", v6=True)
        self.ufw.reconcile_user_rules(
            "alice", "198.51.100.2", {"web": (8080, "tcp"), "api": (8443, "tcp")})
        self.assertEqual(f.rules(), [
            ("22/tcp", "ALLOW IN", "Anywhere", ""),
            ("Anywhere", "DENY IN", "192.0.2.66", ""),
            ("8080/tcp", "ALLOW IN", "198.51.100.2", "ufw-okboy:alice:web"),
            ("8443/tcp", "ALLOW IN", "198.51.100.2", "ufw-okboy:alice:api"),
            ("22/tcp (v6)", "ALLOW IN", "Anywhere (v6)", ""),
        ])

    def test_ipv4_add_renumbering_ipv6_rules(self) -> None:
        # An added IPv4 rule goes before every IPv6 one: a stale IPv6 rule found
        # in the listing before the add is no longer at that number.
        f = self.fake
        f.add("22/tcp", "ALLOW IN", "Anywhere")
        f.add("22/tcp (v6)", "ALLOW IN", "Anywhere (v6)", v6=True)
        f.add("8080/tcp", "ALLOW IN", "2001:db8::5", "ufw-okboy:alice:web", v6=True)
        f.add("Anywhere (v6)", "DENY IN", "2001:db8::66", v6=True)
        self.ufw.reconcile_user_rules("alice", "198.51.100.2", {"web": (8080, "tcp")})
        self.assertEqual(f.rules(), [
            ("22/tcp", "ALLOW IN", "Anywhere", ""),
            ("8080/tcp", "ALLOW IN", "198.51.100.2", "ufw-okboy:alice:web"),
            ("22/tcp (v6)", "ALLOW IN", "Anywhere (v6)", ""),
            ("Anywhere (v6)", "DENY IN", "2001:db8::66", ""),
        ])

    def test_delete_by_number_checks_the_rule_is_still_there(self) -> None:
        f = self.fake
        f.add("22/tcp", "ALLOW IN", "Anywhere")
        f.add("8080/tcp", "ALLOW IN", "Anywhere")
        listed = self.ufw.list_all_rules()[1]  # 8080, number 2
        del f.v4[0]  # someone else deleted rule 1: 8080 is number 1 now
        f.add("Anywhere", "DENY IN", "192.0.2.66")  # and something else is number 2
        with self.assertRaises(LookupError):
            self.ufw.delete_rule(2, expect=listed)
        self.assertIn(("Anywhere", "DENY IN", "192.0.2.66", ""), f.rules())

    def test_legacy_delete_refuses_non_addresses(self) -> None:
        # A stale "any" in the database must not match the host's own open rule
        # ("allow 22/tcp" is "allow from any to any port 22 proto tcp").
        self.fake.add("22/tcp", "ALLOW IN", "Anywhere")
        self.ufw.remove_rule("any", 22, "alice", "tcp", "ssh")
        self.assertEqual(self.fake.rules(), [("22/tcp", "ALLOW IN", "Anywhere", "")])


class TestEnableGroupKeepsOthers(_Base):
    """Enabling one group reconciled only that group, and reconcile removes the
    rules of every group missing from its map: the user's other groups closed."""

    def test_enabling_a_group_keeps_the_other_groups(self) -> None:
        uid = self.db.create_user("alice", "secret-alice")
        web = self.db.create_group("web", 8080, "tcp")
        dbg = self.db.create_group("db", 3306, "tcp")
        self.db.add_membership(uid, web, enabled=1)
        self.db.add_membership(uid, dbg, enabled=0)
        hdr = {"Authorization": build_auth_header("alice", "secret-alice"),
               "X-Real-IP": "203.0.113.50"}
        self.assertEqual(self.client.post("/api/knock", headers=hdr).status_code, 200)
        resp = self.client.patch(f"/api/me/membership/{dbg}", headers=hdr, json={"enabled": True})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(sorted(r[0] for r in self.fake.rules()), ["3306/tcp", "8080/tcp"])


class TestClientIP(_Base):
    """Only one IP address may reach a rule: ufw reads "any" or a CIDR as
    everyone, and a trusted proxy's own address must never be allowlisted."""

    config = {"trusted_proxies": ["127.0.0.1", "10.0.0.5"]}

    def setUp(self) -> None:
        super().setUp()
        uid = self.db.create_user("alice", "secret-alice")
        self.db.add_membership(uid, self.db.create_group("ssh", 22, "tcp"), enabled=1)

    def _knock(self, peer: str, **headers):
        headers["Authorization"] = build_auth_header("alice", "secret-alice")
        return self.client.post("/api/knock", headers=headers,
                                environ_base={"REMOTE_ADDR": peer})

    def test_canonical_ip(self) -> None:
        self.assertEqual(canonical_ip(" 2001:DB8::1 "), "2001:db8::1")
        self.assertEqual(canonical_ip("::ffff:203.0.113.7"), "203.0.113.7")
        for bad in ("any", "0.0.0.0/0", "fe80::1%eth0", "example.com", "", None):
            self.assertEqual(canonical_ip(bad), "", bad)

    def test_bad_proxy_headers_are_refused(self) -> None:
        for hdrs in ({"X-Real-IP": "any"}, {"X-Real-IP": "0.0.0.0/0"},
                     {"X-Forwarded-For": "203.0.113.9, any"}, {}):
            resp = self._knock("127.0.0.1", **hdrs)
            self.assertEqual(resp.status_code, 400, hdrs)
        # A proxy off loopback that sends no header is not allowlisted itself.
        self.assertEqual(self._knock("10.0.0.5").status_code, 400)
        self.assertEqual(self.fake.rules(), [])

    def test_good_header_is_canonicalized(self) -> None:
        self.assertEqual(self._knock("127.0.0.1", **{"X-Real-IP": " 2001:DB8::7 "}).status_code, 200)
        self.assertEqual([r[2] for r in self.fake.rules()], ["2001:db8::7"])

    def test_failures_without_client_ip_are_still_throttled(self) -> None:
        # A bad proxy header used to key failures on "" — never throttled.
        for _ in range(12):
            self.client.post("/api/knock", headers={"Authorization": "HMAC-SHA256 x:1:y",
                                                    "X-Real-IP": "any"})
        resp = self.client.post("/api/knock", headers={"X-Real-IP": "any"})
        self.assertEqual(resp.status_code, 429)


class TestTOTPCap(_Base):
    """TOTP failures were not counted on disable/re-enroll (unbounded guessing
    with a stolen admin HMAC secret) and never capped per account."""

    config = {"throttle_max_failures": 3, "throttle_window": 300}

    def setUp(self) -> None:
        super().setUp()
        self.uid = self.db.create_user("root", "secret-root", is_admin=True)
        self.totp = auth.generate_totp_secret()
        self.db.set_totp_secret(self.uid, self.totp)
        self.db.enable_totp(self.uid)

    def _disable(self, code, ip):
        return self.client.delete(
            "/api/admin/totp", json={"totp_code": code},
            headers={"Authorization": build_auth_header("root", "secret-root"), "X-Real-IP": ip})

    def test_wrong_codes_are_capped_per_account_across_ips(self) -> None:
        good = auth.totp_now(self.totp)
        wrong = "000000" if good != "000000" else "111111"
        for i in range(3):
            self.assertEqual(self._disable(wrong, f"198.51.100.{i + 1}").status_code, 403)
        # Past the cap even the right code is refused, from yet another IP.
        self.assertEqual(self._disable(good, "198.51.100.9").status_code, 429)
        self.assertTrue(self.db.get_user(self.uid)["totp_enabled"])

    def test_missing_code_is_not_a_guess(self) -> None:
        for _ in range(5):
            self.assertEqual(self._disable("", "198.51.100.1").status_code, 403)
        self.assertEqual(self.db.count_recent_user_failures("root", "Invalid TOTP code", 300), 0)
        self.assertEqual(self._disable(auth.totp_now(self.totp), "198.51.100.1").status_code, 200)


class TestFilesAndSeeding(unittest.TestCase):

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="ufw-okboy-wave2-files-")
        self.db_path = os.path.join(self.tmpdir, "data", "ufw-okboy.db")

    @unittest.skipIf(os.name != "posix", "POSIX file modes")
    def test_database_and_backups_are_owner_only(self) -> None:
        db = Database(self.db_path)
        db.init()
        self.assertEqual(os.stat(os.path.dirname(self.db_path)).st_mode & 0o777, 0o700)
        self.assertEqual(os.stat(self.db_path).st_mode & 0o777, 0o600)
        dest = db.backup(os.path.join(self.tmpdir, "backups", "b.db"))
        self.assertEqual(os.stat(dest).st_mode & 0o777, 0o600)
        db.close()
        os.chmod(self.db_path, 0o644)  # as older versions left it
        Database(self.db_path).close()
        self.assertEqual(os.stat(self.db_path).st_mode & 0o777, 0o600)

    def test_config_users_seed_only_a_fresh_database(self) -> None:
        cfg = {"db_path": self.db_path, "users": {"bob": {"secret": "b" * 64}},
               "protected_ports": [22], "state_file": os.path.join(self.tmpdir, "none.json")}
        db = open_database(cfg)
        self.assertIsNotNone(db.get_user_by_username("bob"))
        db.delete_user(db.get_user_by_username("bob")["id"])
        db.close()
        db = open_database(cfg)  # restart: the deleted user must stay deleted
        self.assertIsNone(db.get_user_by_username("bob"))
        db.close()


class TestRemovals(_Base):
    """Removals delete only the user's own rules, at any address, and a removal
    ufw could not do keeps what is needed to retry it."""

    def setUp(self) -> None:
        super().setUp()
        self.admin = self.db.create_user("root", "secret-root", is_admin=True)
        self.alice = self.db.create_user("alice", "secret-alice")
        self.web = self.db.create_group("web", 8080, "tcp")
        self.dbg = self.db.create_group("db", 3306, "tcp")
        self.db.add_membership(self.alice, self.web, enabled=1)
        self.db.add_membership(self.alice, self.dbg, enabled=1)
        self.db.record_ip_change(self.alice, "alice", "203.0.113.10")
        f = self.fake
        f.add("8080/tcp", "ALLOW IN", "203.0.113.10", "ufw-okboy:alice:web")
        f.add("3306/tcp", "ALLOW IN", "198.51.100.99", "ufw-okboy:alice:db")  # a stale address
        f.add("9090/tcp", "ALLOW IN", "Anywhere", "ufw-okboy:alice:web")      # an injected "any" ...
        f.add("8080/tcp", "ALLOW IN", "203.0.113.11", "ufw-okboy:bob:web")    # behind the same NAT
        f.add("22/tcp", "ALLOW IN", "Anywhere")
        f.add("9090/tcp (v6)", "ALLOW IN", "Anywhere (v6)", "ufw-okboy:alice:web", v6=True)  # ... its v6 half

    def _admin(self, method, path, **kw):
        return self.client.open(path, method=method, headers={
            "Authorization": build_auth_header("root", "secret-root")}, **kw)

    def _left(self):
        return [r[3] for r in self.fake.rules()]

    def test_delete_user_removes_every_rule_of_the_user_only(self) -> None:
        self.assertEqual(self._admin("DELETE", f"/api/admin/users/{self.alice}").status_code, 200)
        self.assertEqual(self._left(), ["ufw-okboy:bob:web", ""])

    def test_delete_user_keeps_the_user_when_ufw_fails(self) -> None:
        self.fake.fail_deletes = True
        self.assertEqual(self._admin("DELETE", f"/api/admin/users/{self.alice}").status_code, 500)
        self.assertIsNotNone(self.db.get_user(self.alice))

    def test_revoke_keeps_the_state_when_ufw_fails(self) -> None:
        self.fake.fail_deletes = True
        r = self._admin("POST", f"/api/admin/users/{self.alice}/revoke", json={})
        self.assertEqual(r.status_code, 200)
        self.assertIn("warning", r.get_json())
        user = self.db.get_user(self.alice)
        self.assertEqual(user["current_ip"], "203.0.113.10")
        self.assertNotEqual(user["secret"], "secret-alice")  # rotated anyway

    def test_delete_group_removes_the_group_rules_only(self) -> None:
        self.assertEqual(self._admin("DELETE", f"/api/admin/groups/{self.web}").status_code, 200)
        self.assertEqual(self._left(), ["ufw-okboy:alice:db", ""])

    def test_disabling_a_membership_closes_the_port(self) -> None:
        r = self._admin("POST", f"/api/admin/users/{self.alice}/groups",
                        json={"group_id": self.dbg, "enabled": False})
        self.assertEqual(r.status_code, 201)
        self.assertNotIn("ufw-okboy:alice:db", self._left())

    def test_removal_never_touches_a_neighbours_rule(self) -> None:
        # alice has no rule of her own at this address: the NAT neighbour's stays.
        self.ufw.remove_rule("203.0.113.11", 8080, "alice", "tcp", "web")
        self.assertIn("ufw-okboy:bob:web", self._left())

    def test_cleanup_removes_every_rule_of_a_stale_user(self) -> None:
        self.db.conn.execute("UPDATE users SET last_knock=1 WHERE id=?", (self.alice,))
        self.db.conn.commit()
        self.db.set_membership_enabled(self.alice, self.dbg, 0)  # its rule must go too
        self.assertEqual(self.ufw.cleanup_stale(7 * 86400), ["alice"])
        self.assertEqual(self._left(), ["ufw-okboy:bob:web", ""])
        self.assertIsNone(self.db.get_user(self.alice)["current_ip"])

    def test_cleanup_keeps_the_state_when_ufw_fails(self) -> None:
        self.db.conn.execute("UPDATE users SET last_knock=1 WHERE id=?", (self.alice,))
        self.db.conn.commit()
        self.fake.fail_deletes = True
        self.assertEqual(self.ufw.cleanup_stale(7 * 86400), [])
        self.assertEqual(self.db.get_user(self.alice)["current_ip"], "203.0.113.10")


class TestSelfToggleNeedsMembership(_Base):
    """An admin could self-enable any group without TOTP: the admin endpoint's
    step-up was skipped, and with no membership row the port opened anyway."""

    def test_admin_cannot_self_enable_a_group_without_membership(self) -> None:
        uid = self.db.create_user("root", "secret-root", is_admin=True)
        gid = self.db.create_group("ssh", 22, "tcp")
        hdr = {"Authorization": build_auth_header("root", "secret-root"),
               "X-Real-IP": "203.0.113.5"}
        self.assertEqual(self.client.post("/api/knock", headers=hdr).status_code, 200)
        for path in (f"/api/me/membership/{gid}", f"/api/membership/{uid}/{gid}"):
            hdr["Authorization"] = build_auth_header("root", "secret-root")
            r = self.client.patch(path, headers=hdr, json={"enabled": True})
            self.assertEqual(r.status_code, 403, path)
        self.assertEqual(self.fake.rules(), [])


class TestTOTPReenroll(_Base):
    """Re-enrolling switched TOTP off until the new authenticator was confirmed
    (an abandoned re-enrollment left the account without it), and the
    activation code stayed valid for other operations."""

    def setUp(self) -> None:
        super().setUp()
        self.uid = self.db.create_user("root", "secret-root", is_admin=True)
        now = int(time.time())
        self.step = lambda secret, k: auth.totp_now(secret, t=now + 30 * k)
        self.old = self._post("/api/admin/totp/enroll").get_json()["secret"]
        self.assertEqual(self._post("/api/admin/totp/activate",
                                    totp_code=self.step(self.old, -1)).status_code, 200)

    def _post(self, path, **body):
        return self.client.post(path, json=body, headers={
            "Authorization": build_auth_header("root", "secret-root")})

    def _disable(self, code):
        return self.client.delete("/api/admin/totp", json={"totp_code": code}, headers={
            "Authorization": build_auth_header("root", "secret-root")})

    def test_activation_code_cannot_be_reused(self) -> None:
        self.assertEqual(self._disable(self.step(self.old, -1)).status_code, 403)

    def test_reenrollment_keeps_totp_on_until_confirmed(self) -> None:
        r = self._post("/api/admin/totp/enroll", totp_code=self.step(self.old, 0))
        self.assertEqual(r.status_code, 200)
        new = r.get_json()["secret"]
        user = self.db.get_user(self.uid)
        self.assertTrue(user["totp_enabled"])  # still protected meanwhile
        self.assertEqual(user["totp_secret"], self.old)
        # Confirm the new authenticator: from now on only it counts.
        self.assertEqual(self._post("/api/admin/totp/activate",
                                    totp_code=self.step(new, 0)).status_code, 200)
        self.assertEqual(self._disable(self.step(self.old, 1)).status_code, 403)
        self.assertEqual(self._disable(self.step(new, 1)).status_code, 200)


@unittest.skipIf(fcntl is None, "POSIX flock")
class TestHostLock(unittest.TestCase):

    def test_excludes_other_processes_and_is_reentrant(self) -> None:
        path = os.path.join(tempfile.mkdtemp(prefix="ufw-okboy-lock-"), "ufw.lock")
        probe = [sys.executable, "-c",
                 "import fcntl, os, sys\n"
                 "fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT)\n"
                 "fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)", path]
        lock = HostLock(path)
        with lock:
            with lock:  # re-entrant within the thread
                self.assertNotEqual(subprocess.run(probe, capture_output=True).returncode, 0)
            self.assertNotEqual(subprocess.run(probe, capture_output=True).returncode, 0)
        self.assertEqual(subprocess.run(probe, capture_output=True).returncode, 0)


if __name__ == "__main__":
    unittest.main()
