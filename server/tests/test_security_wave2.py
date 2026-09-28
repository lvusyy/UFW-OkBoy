"""Security wave 2: numbered deletes, client IP, TOTP, host lock, files, removals.

Run from the server/ directory with:
    python -m unittest tests.test_security_wave2 -v
"""

import argparse
import contextlib
import hashlib
import hmac
import io
import os
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as app_module  # noqa: E402
import auth  # noqa: E402
import ufw_ops  # noqa: E402
from app import create_app, open_database  # noqa: E402
from db import Database, DatabaseInUse, exclusive_claim  # noqa: E402
from ufw_ops import (  # noqa: E402
    DeadlineExceeded, HostLock, LockTimeout, UFWManager, canonical_ip, fcntl,
)


def build_auth_header(username: str, secret: str) -> str:
    """An HMAC-SHA256 Authorization header, as the clients build it."""
    ts = int(time.time())
    sig = hmac.new(secret.encode(), f"{username}:{ts}".encode(), hashlib.sha256).hexdigest()
    return f"HMAC-SHA256 {username}:{ts}:{sig}"


def _flock_held(path: str) -> bool:
    """Whether an flock on *path* is held — by this process too: a lock taken
    through another open file description conflicts with one taken here."""
    fd = os.open(path, os.O_RDWR | os.O_CREAT)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return False
    except BlockingIOError:
        return True
    finally:
        os.close(fd)


class FakeUfw:
    """A ufw rule table standing in for ufw_ops._run, faithful where the
    numbered deletes depend on it: IPv4 rules are listed before IPv6 ones (each
    family in the order added), `status numbered` numbers them from 1, and
    `--force delete N` removes the N-th, renumbering every rule after it. Adding
    a rule that differs from an existing one only in its action or comment
    replaces it (ufw 0.36: "Rule updated" — a DENY becomes an ALLOW); a rule
    from "any" becomes two, listed as "Anywhere" and, in the IPv6 part,
    "PORT/PROTO (v6) ... Anywhere (v6)"."""

    def __init__(self) -> None:
        self.v4: list[tuple] = []
        self.v6: list[tuple] = []
        self.fail_deletes = False  # make every delete fail, as a wedged ufw would
        self.fail_list = False  # make `status numbered` fail
        self.fail_list_after: int | None = None  # ... after this many listings
        self.listings = 0
        self.raise_on_delete = None  # an exception every delete raises (a timeout)
        self.inactive = False  # ufw disabled: `status numbered` lists nothing
        self.fail_adds_after_saving = False  # an add saves its rule, then fails to apply it
        self.calls: list[tuple] = []  # (args, kwargs) of every call

    def add(self, to: str, action: str, frm: str, comment: str = "", v6: bool = False) -> None:
        table = self.v6 if v6 else self.v4
        for i, (t, _, f, _) in enumerate(table):
            if (t, f) == (to, frm):
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
        self.calls.append((args, kwargs))
        rc, out = 0, ""
        if args == ["status", "numbered"]:
            self.listings += 1
            if self.fail_list or (self.fail_list_after is not None
                                  and self.listings > self.fail_list_after):
                rc = 1
            elif self.inactive:
                out = "Status: inactive\n"
            else:
                out = self._render()
        elif args[:2] == ["--force", "delete"] and len(args) == 3 and args[2].isdigit():
            if self.raise_on_delete is not None:
                raise self.raise_on_delete
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
            if self.fail_adds_after_saving:
                rc = 1
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
        self._p = patch("ufw_ops._run", self.fake)
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

    def test_a_failed_add_that_saved_its_rule_still_renumbers(self) -> None:
        # ufw saves a rule before applying it to the running firewall: an add
        # failing there still moves every IPv6 rule down one, and reconcile
        # deleted by the numbers listed before it — here the host's IPv6 SSH.
        f = self.fake
        f.add("22/tcp (v6)", "ALLOW IN", "Anywhere (v6)", v6=True)
        f.add("8080/tcp", "ALLOW IN", "2001:db8::5", "ufw-okboy:alice:web", v6=True)
        f.fail_adds_after_saving = True
        self.ufw.reconcile_user_rules("alice", "198.51.100.2", {"web": (8080, "tcp")})
        self.assertIn(("22/tcp (v6)", "ALLOW IN", "Anywhere (v6)", ""), f.rules())
        self.assertNotIn(("8080/tcp", "ALLOW IN", "2001:db8::5", "ufw-okboy:alice:web"),
                         f.rules())

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

    @unittest.skipIf(fcntl is None, "POSIX flock")
    def test_migrations_and_seeding_run_under_the_host_lock(self) -> None:
        # gunicorn starts its workers together: both ran a pending migration.
        held = []
        real = Database.init

        def spy(db):
            held.append(_flock_held(os.path.join(os.path.dirname(self.db_path), "ufw.lock")))
            return real(db)

        cfg = {"db_path": self.db_path, "users": {}, "protected_ports": [],
               "state_file": os.path.join(self.tmpdir, "none.json")}
        with patch.object(Database, "init", spy):
            open_database(cfg).close()
        self.assertEqual(held, [True])

    def test_a_failed_insert_releases_the_write_lock(self) -> None:
        # A duplicate user or group left its transaction open: every other
        # process then waited out busy_timeout and failed.
        db = Database(self.db_path)
        db.init()
        db.create_user("bob", "b" * 64)
        db.create_group("web", 8080, "tcp")
        with self.assertRaises(sqlite3.IntegrityError):
            db.create_user("bob", "c" * 64)
        self.assertFalse(db.conn.in_transaction)
        with self.assertRaises(sqlite3.IntegrityError):
            db.create_group("web", 8443, "tcp")
        self.assertFalse(db.conn.in_transaction)
        db.close()

    @unittest.skipIf(os.name != "posix", "POSIX file modes")
    def test_older_copies_are_made_owner_only(self) -> None:
        # Snapshots and backups of older versions, and a config holding seed
        # users' secrets, stayed world-readable.
        backup_dir = os.path.join(self.tmpdir, "backups")
        os.makedirs(backup_dir)
        os.makedirs(os.path.dirname(self.db_path))
        old = [self.db_path + ".pre-upgrade-2.3.1-1", self.db_path + ".pre-restore",
               os.path.join(backup_dir, "ufw-okboy-20260101-000000-000000.db")]
        for path in old:
            with open(path, "wb"):
                pass
            os.chmod(path, 0o644)
        cfg_path = os.path.join(self.tmpdir, "config.yaml")
        with open(cfg_path, "w", encoding="utf-8") as f:
            yaml.dump({"db_path": self.db_path, "backup_dir": backup_dir,
                       "state_file": os.path.join(self.tmpdir, "none.json"),
                       "users": {"bob": {"secret": "b" * 64}}}, f)
        os.chmod(cfg_path, 0o644)
        open_database(app_module.load_config(cfg_path)).close()
        for path in (*old, cfg_path):
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600, path)

    @unittest.skipIf(os.name != "posix", "POSIX file semantics")
    def test_restore_never_eats_its_own_input(self) -> None:
        # Restoring the live database truncated it; restoring the .pre-restore
        # snapshot first overwrote that snapshot; and the snapshot left out the
        # -wal, where commits after a crash may still be.
        cfg_path = os.path.join(self.tmpdir, "config.yaml")
        with open(cfg_path, "w", encoding="utf-8") as f:
            yaml.dump({"db_path": self.db_path,
                       "state_file": os.path.join(self.tmpdir, "none.json")}, f)
        cfg = app_module.load_config(cfg_path)
        db = open_database(cfg)
        db.create_user("bob", "b" * 64)
        backup = db.backup(os.path.join(self.tmpdir, "bob-only.db"))
        db.close()

        def restore(src):
            with contextlib.redirect_stdout(io.StringIO()):
                app_module.cmd_restore(argparse.Namespace(config=cfg_path, backup=src))

        def users(path):
            with contextlib.closing(sqlite3.connect(path)) as c:
                return sorted(r[0] for r in c.execute("SELECT username FROM users"))

        with self.assertRaises(SystemExit):
            restore(self.db_path)
        self.assertEqual(users(self.db_path), ["bob"])
        with self.assertRaises(ValueError):
            app_module._copy_private(self.db_path, self.db_path)

        # carol, committed but only in the -wal: written by a process that died
        # without closing its connection, so nothing checkpointed it.
        crash = ("import os, sqlite3, sys\n"
                 "c = sqlite3.connect(sys.argv[1])\n"
                 "c.execute('PRAGMA wal_autocheckpoint=0')\n"
                 "c.execute('INSERT INTO users (username, secret) VALUES (?, ?)', ('carol', 'c'))\n"
                 "c.commit()\n"
                 "os._exit(0)\n")
        subprocess.run([sys.executable, "-c", crash, self.db_path], check=True)
        self.assertGreater(os.path.getsize(self.db_path + "-wal"), 0)
        restore(backup)
        snaps = [p for p in os.listdir(os.path.dirname(self.db_path))
                 if p.startswith(os.path.basename(self.db_path) + ".pre-restore-")
                 and not p.endswith(("-wal", "-shm"))]
        self.assertEqual(len(snaps), 1)
        snap = os.path.join(os.path.dirname(self.db_path), snaps[0])
        self.assertTrue(os.path.exists(snap + "-wal"))  # carol: there, not in its file
        self.assertEqual(users(self.db_path), ["bob"])
        # Back to before the restore, through a link: the snapshot's -wal must
        # come along, and the snapshot itself survive.
        latest = os.path.join(self.tmpdir, "latest")
        os.symlink(snap, latest)
        time.sleep(0.01)  # a distinct snapshot name
        restore(latest)
        self.assertEqual(users(self.db_path), ["bob", "carol"])
        self.assertEqual(users(snap), ["bob", "carol"])

    @unittest.skipIf(fcntl is None, "POSIX flock")
    def test_restore_excludes_other_database_users(self) -> None:
        # The service, a cleanup run or a CLI command could use the database
        # while it was copied and replaced.
        cfg_path = os.path.join(self.tmpdir, "config.yaml")
        with open(cfg_path, "w", encoding="utf-8") as f:
            yaml.dump({"db_path": self.db_path,
                       "state_file": os.path.join(self.tmpdir, "none.json")}, f)
        db = open_database(app_module.load_config(cfg_path))
        backup = db.backup(os.path.join(self.tmpdir, "b.db"))
        db.close()
        ns = argparse.Namespace(config=cfg_path, backup=backup)
        # A oneshot cleanup, running, is "activating" — not "active".
        states = subprocess.CompletedProcess([], 3, stdout="inactive\nactivating\n")
        with patch("subprocess.run", return_value=states), self.assertRaises(SystemExit):
            app_module.cmd_restore(ns)
        other = Database(self.db_path)  # another process's, say: open until closed
        with self.assertRaises(SystemExit):
            app_module.cmd_restore(ns)
        other.close()
        with contextlib.redirect_stdout(io.StringIO()):
            app_module.cmd_restore(ns)
        # And while a restore holds it, the database does not open.
        with exclusive_claim(self.db_path):
            with self.assertRaises(DatabaseInUse):
                Database(self.db_path)

    @unittest.skipIf(os.name != "posix", "POSIX file modes")
    def test_snapshot_copies_are_owner_only(self) -> None:
        # copy2 wrote the secrets under the umask's mode before copying the
        # source's; an existing copy kept its own.
        src = os.path.join(self.tmpdir, "src.db")
        dest = os.path.join(self.tmpdir, "dest.db")
        with open(src, "wb") as f:
            f.write(b"secrets")
        with open(dest, "wb"):
            pass
        os.chmod(dest, 0o644)  # an older, world-readable snapshot
        old = os.umask(0)
        try:
            app_module._copy_private(src, dest)
        finally:
            os.umask(old)
        self.assertEqual(os.stat(dest).st_mode & 0o777, 0o600)
        with open(dest, "rb") as f:
            self.assertEqual(f.read(), b"secrets")


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
        f.add("8080/tcp", "ALLOW IN", "203.0.113.11", "ufw-okboy:bob:web")    # another user's
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
        # alice's state may still name bob's address (hers before, say): the
        # ip/port/proto match once used deleted bob's rule there.
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

    def test_a_listing_failure_is_not_a_removal(self) -> None:
        # A failing `ufw status numbered` listed nothing: "nothing to remove",
        # and the records went while the rules stayed.
        self.fake.fail_list = True
        self.assertEqual(self._admin("DELETE", f"/api/admin/users/{self.alice}").status_code, 500)
        self.assertIsNotNone(self.db.get_user(self.alice))
        r = self._admin("POST", "/api/admin/memberships/remove",
                        json={"username": "alice", "group_name": "web"})
        self.assertEqual(r.status_code, 500)
        self.assertTrue(self.db.membership_exists(self.alice, self.web))
        self.db.conn.execute("UPDATE users SET last_knock=1 WHERE id=?", (self.alice,))
        self.db.conn.commit()
        self.assertEqual(self.ufw.cleanup_stale(7 * 86400), [])
        self.assertEqual(self.db.get_user(self.alice)["current_ip"], "203.0.113.10")

    def test_a_failed_first_knock_leaves_nothing_behind(self) -> None:
        # A knock that added its rule and then failed records nothing, and the
        # cleanup skipped users who never knocked: the rule never expired.
        carol = self.db.create_user("carol", "secret-carol")
        self.db.add_membership(carol, self.web, enabled=1)
        self.fake.fail_list_after = 2  # the knock's second look fails, after its add
        r = self.client.post("/api/knock", headers={
            "Authorization": build_auth_header("carol", "secret-carol"),
            "X-Real-IP": "198.51.100.5"})
        self.assertEqual(r.status_code, 503)
        self.assertIsNone(self.db.get_user(carol)["last_knock"])
        self.assertIn("ufw-okboy:carol:web", self._left())
        self.fake.fail_list_after = None
        self.assertEqual(self.ufw.cleanup_stale(7 * 86400), ["carol"])
        self.assertNotIn("ufw-okboy:carol:web", self._left())
        self.assertIn("ufw-okboy:alice:web", self._left())  # a live user's stay

    def test_an_inactive_ufw_is_not_a_removal(self) -> None:
        # Inactive, ufw lists no rule though they stay saved: deleting the user
        # left rules that `ufw enable` brought back, with nobody to remove them.
        self.fake.inactive = True
        self.assertEqual(self._admin("DELETE", f"/api/admin/users/{self.alice}").status_code, 500)
        self.assertIsNotNone(self.db.get_user(self.alice))

    def test_revoke_rotates_before_touching_the_firewall(self) -> None:
        # Rotated last, a revoke whose worker died closing the ports left the
        # old credential working.
        seen = []
        real = UFWManager.purge_rules

        def spy(ufw, *args, **kwargs):
            seen.append(self.db.get_user(self.alice)["secret"])
            return real(ufw, *args, **kwargs)

        with patch.object(UFWManager, "purge_rules", spy):
            r = self._admin("POST", f"/api/admin/users/{self.alice}/revoke", json={})
            self.assertEqual(r.status_code, 200)
            with contextlib.redirect_stdout(io.StringIO()):
                app_module.cmd_revoke(argparse.Namespace(
                    config=self.config_path, username="alice", no_rotate=False))
        self.assertEqual(len(seen), 2)
        self.assertNotEqual(seen[0], "secret-alice")
        self.assertNotEqual(seen[1], seen[0])

    def test_cli_revoke_rotates_when_ufw_times_out(self) -> None:
        # A timeout was no RuntimeError: the CLI revoke died before rotating.
        self.fake.raise_on_delete = subprocess.TimeoutExpired(["ufw"], 30)
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
            app_module.cmd_revoke(argparse.Namespace(
                config=self.config_path, username="alice", no_rotate=False))
        user = self.db.get_user(self.alice)
        self.assertNotEqual(user["secret"], "secret-alice")
        self.assertEqual(user["current_ip"], "203.0.113.10")  # kept for the retry

    def test_disabling_a_membership_closes_it_at_every_address(self) -> None:
        # The toggles removed only the rule at the current address, and nothing
        # without one.
        r = self.client.patch(f"/api/me/membership/{self.web}", json={"enabled": False},
                              headers={"Authorization": build_auth_header("alice", "secret-alice")})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self._left(), ["ufw-okboy:alice:db", "ufw-okboy:bob:web", ""])
        r = self._admin("PATCH", f"/api/membership/{self.alice}/{self.dbg}", json={"enabled": False})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self._left(), ["ufw-okboy:bob:web", ""])

    def test_pre_group_rules_go_with_their_group(self) -> None:
        # Rules from before groups carry "<prefix>:<user>": removing a membership
        # or a group skipped them, and the port stayed open.
        f = self.fake
        f.add("8080/tcp", "ALLOW IN", "198.51.100.7", "ufw-okboy:alice")
        f.add("5432/tcp", "ALLOW IN", "198.51.100.7", "ufw-okboy:alice")  # not web's port
        f.add("8080/tcp", "ALLOW IN", "198.51.100.8", "ufw-okboy:carol")
        r = self._admin("POST", "/api/admin/memberships/remove",
                        json={"username": "alice", "group_name": "web"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self._left(), ["ufw-okboy:alice:db", "ufw-okboy:bob:web", "",
                                        "ufw-okboy:alice", "ufw-okboy:carol"])
        self.assertEqual(self._admin("DELETE", f"/api/admin/groups/{self.web}").status_code, 200)
        self.assertEqual(self._left(), ["ufw-okboy:alice:db", "", "ufw-okboy:alice"])

    def test_knock_supersedes_pre_group_rules(self) -> None:
        f = self.fake
        f.add("8080/tcp", "ALLOW IN", "203.0.113.10", "ufw-okboy:alice")  # her rule, relabelled
        f.add("8080/tcp", "ALLOW IN", "198.51.100.7", "ufw-okboy:alice")  # at an old address
        self.ufw.reconcile_user_rules(
            "alice", "203.0.113.10", {"web": (8080, "tcp"), "db": (3306, "tcp")})
        self.assertEqual(f.rules(), [
            ("8080/tcp", "ALLOW IN", "203.0.113.10", "ufw-okboy:alice:web"),
            ("8080/tcp", "ALLOW IN", "203.0.113.11", "ufw-okboy:bob:web"),
            ("22/tcp", "ALLOW IN", "Anywhere", ""),
            ("3306/tcp", "ALLOW IN", "203.0.113.10", "ufw-okboy:alice:db"),
        ])

    def test_sync_takes_addresses_not_anywhere(self) -> None:
        # sync read plain `ufw status` expecting "ALLOW IN" (it says "ALLOW"),
        # and would have taken "Anywhere" for an address.
        del self.fake.v4[1]  # alice's rule at a stale address: one address left
        self.db.clear_user_state(self.alice)  # the database lost it
        recovered = self.ufw.sync_state_from_ufw(
            [], user_group_ports=self.db.get_all_user_group_ports(only_enabled=True))
        self.assertEqual(recovered["alice"]["ip"], "203.0.113.10")
        self.assertEqual(self.db.get_user(self.alice)["current_ip"], "203.0.113.10")
        self.assertEqual(self._left(), ["ufw-okboy:alice:web", "ufw-okboy:bob:web", "",
                                        "ufw-okboy:alice:db"])

    @unittest.skipIf(fcntl is None, "POSIX flock")
    def test_cli_sync_reads_memberships_under_the_host_lock(self) -> None:
        # Read before the lock, the memberships could predate a deletion that
        # sync then undid.
        held = []
        real = Database.get_all_user_group_ports

        def spy(db, *args, **kwargs):
            held.append(_flock_held(os.path.join(self.tmpdir, "ufw.lock")))
            return real(db, *args, **kwargs)

        with patch.object(Database, "get_all_user_group_ports", spy), \
                contextlib.redirect_stdout(io.StringIO()):
            app_module.cmd_sync(argparse.Namespace(config=self.config_path))
        self.assertEqual(held, [True])


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

    def test_pending_seed_is_not_listed(self) -> None:
        # /api/admin/users stripped the active seed but returned the pending one.
        self._post("/api/admin/totp/enroll", totp_code=self.step(self.old, 0))
        self.assertIsNotNone(self.db.get_user(self.uid)["totp_pending_secret"])
        r = self.client.get("/api/admin/users", headers={
            "Authorization": build_auth_header("root", "secret-root")})
        for user in r.get_json()["users"]:
            self.assertNotIn("totp_pending_secret", user)
            self.assertNotIn("totp_secret", user)

    @unittest.skipIf(fcntl is None, "POSIX flock")
    def test_totp_state_is_read_and_changed_under_the_totp_lock(self) -> None:
        # A disable could read "off" while an activation completed, and two
        # activations could both accept one code for the same pending secret.
        lock = os.path.join(self.tmpdir, "totp.lock")
        held = []
        real = auth.require_admin

        def spy(*args, **kwargs):
            held.append(_flock_held(lock))
            return real(*args, **kwargs)

        with patch("auth.require_admin", spy):
            new = self._post("/api/admin/totp/enroll",
                             totp_code=self.step(self.old, 0)).get_json()["secret"]
            self.assertEqual(self._post("/api/admin/totp/activate",
                                        totp_code=self.step(new, 0)).status_code, 200)
            self.assertEqual(self._disable(self.step(new, 1)).status_code, 200)
        self.assertEqual(held, [True, True, True])


class TestHostRulesStayTheHosts(_Base):
    """ufw keeps one rule per source, port and protocol: a knock took over a host
    rule with the same ones — a DENY turned into an ALLOW — and the user's
    revoke or cleanup then deleted it."""

    def setUp(self) -> None:
        super().setUp()
        self.db.create_user("root", "secret-root", is_admin=True)
        self.alice = self.db.create_user("alice", "secret-alice")
        self.db.add_membership(self.alice, self.db.create_group("ssh", 22, "tcp"), enabled=1)

    def _knock(self):
        return self.client.post("/api/knock", headers={
            "Authorization": build_auth_header("alice", "secret-alice"),
            "X-Real-IP": "203.0.113.10"})

    def test_a_host_allow_is_not_taken_over(self) -> None:
        self.fake.add("22/tcp", "ALLOW IN", "203.0.113.10", "office")
        self.assertEqual(self._knock().status_code, 200)
        r = self.client.post(f"/api/admin/users/{self.alice}/revoke", json={},
                             headers={"Authorization": build_auth_header("root", "secret-root")})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.fake.rules(), [("22/tcp", "ALLOW IN", "203.0.113.10", "office")])

    def test_a_host_deny_stays_a_deny(self) -> None:
        self.fake.add("22/tcp", "DENY IN", "203.0.113.10")
        self.assertEqual(self._knock().status_code, 200)
        self.assertEqual(self.fake.rules(), [("22/tcp", "DENY IN", "203.0.113.10", "")])

    def test_a_logged_host_rule_is_seen(self) -> None:
        # ufw lists a logged rule's source as "203.0.113.10 (log)".
        self.fake.add("22/tcp", "DENY IN", "203.0.113.10 (log)")
        self.assertEqual(self._knock().status_code, 200)
        self.assertEqual(self.fake.rules(), [("22/tcp", "DENY IN", "203.0.113.10 (log)", "")])

    def test_an_ipv4_mapped_host_rule_is_another_rule(self) -> None:
        # ::ffff:203.0.113.10 is not 203.0.113.10 to ufw: its rule does not
        # stand in for the user's.
        self.fake.add("22/tcp", "ALLOW IN", "::ffff:203.0.113.10", v6=True)
        self.assertEqual(self._knock().status_code, 200)
        self.assertIn(("22/tcp", "ALLOW IN", "203.0.113.10", "ufw-okboy:alice:ssh"),
                      self.fake.rules())

    def test_a_knock_out_of_time_records_nothing(self) -> None:
        # Out of time, the listings read as empty and every add failed quietly:
        # the knock recorded the new address and answered "updated", while the
        # old address kept its rule.
        real = UFWManager.deadline
        self.ufw.deadline = lambda seconds: real(self.ufw, 0)
        self.assertEqual(self._knock().status_code, 503)
        self.assertIsNone(self.db.get_user(self.alice)["current_ip"])

    def test_deadlines_nest(self) -> None:
        with self.ufw.deadline(0):
            with self.ufw.deadline(100):  # a later inner deadline does not extend it
                with self.assertRaises(DeadlineExceeded):
                    self.ufw._timeout(30)
            with self.assertRaises(DeadlineExceeded):  # nor clears it on the way out
                self.ufw._timeout(30)
        self.assertEqual(self.ufw._timeout(30), 30)

    def test_request_commands_are_bounded(self) -> None:
        # Each ufw command could take 30 s after a 20 s wait for the lock:
        # gunicorn killed the worker, and the command ran on after the lock
        # was released.
        self.assertEqual(self._knock().status_code, 200)
        self.assertTrue(self.fake.calls)
        for args, kwargs in self.fake.calls:
            self.assertLessEqual(kwargs["timeout"], 25, args)
        with self.ufw.deadline(0):
            with self.assertRaises(DeadlineExceeded):
                self.ufw._run_ufw("status")

    @unittest.skipIf(fcntl is None, "POSIX flock")
    def test_privileged_changes_hold_the_host_lock(self) -> None:
        # Outside it, a request authenticated just before a deletion or a
        # demotion could create the account again, or promote it back.
        held = []
        real = auth.require_admin

        def spy(*args, **kwargs):
            held.append(_flock_held(os.path.join(self.tmpdir, "ufw.lock")))
            return real(*args, **kwargs)

        def admin():
            return {"Authorization": build_auth_header("root", "secret-root")}

        with patch("auth.require_admin", spy):
            bob = self.client.post("/api/admin/users", json={"username": "bob"},
                                   headers=admin()).get_json()["id"]
            self.client.post("/api/admin/groups", json={"name": "web", "port": 8080},
                             headers=admin())
            self.client.post(f"/api/admin/users/{bob}/admin", json={"is_admin": True},
                             headers=admin())
        self.assertEqual(held, [True, True, True])


class TestFwDeleteNamesTheRule(_Base):
    """The console sent only a number: after a deletion elsewhere renumbered the
    rules, the handler deleted whatever rule had that number by then."""

    def setUp(self) -> None:
        super().setUp()
        self.db.create_user("root", "secret-root", is_admin=True)

    def _delete(self, number, expect):
        return self.client.post("/api/admin/ufw/delete", json={"number": number, "expect": expect},
                                headers={"Authorization": build_auth_header("root", "secret-root")})

    def test_a_renumbered_rule_is_not_deleted(self) -> None:
        f = self.fake
        f.add("8080/tcp", "ALLOW IN", "Anywhere")
        f.add("9090/tcp", "ALLOW IN", "Anywhere")
        listed = self.ufw.list_all_rules()[1]  # 9090, number 2 as the admin saw it
        shown = {k: listed[k] for k in ("to", "action", "from", "comment")}
        del f.v4[0]  # a deletion elsewhere: 9090 is number 1 now ...
        f.add("Anywhere", "DENY IN", "192.0.2.66")  # ... and the host's DENY number 2
        r = self._delete(2, shown)
        self.assertEqual(r.status_code, 409)
        self.assertTrue(r.get_json()["stale"])
        self.assertIn(("Anywhere", "DENY IN", "192.0.2.66", ""), f.rules())
        self.assertEqual(self._delete(1, shown).status_code, 200)
        self.assertEqual(f.rules(), [("Anywhere", "DENY IN", "192.0.2.66", "")])


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

    def test_waits_are_bounded(self) -> None:
        # Unbounded, a request behind a long CLI or cleanup run waited until
        # gunicorn killed its worker.
        path = os.path.join(tempfile.mkdtemp(prefix="ufw-okboy-lock-"), "ufw.lock")
        fd = os.open(path, os.O_RDWR | os.O_CREAT)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX)  # another holder
        start = time.monotonic()
        with self.assertRaises(LockTimeout):
            with HostLock(path, timeout=0.2):
                pass
        self.assertLess(time.monotonic() - start, 5)


@unittest.skipIf(os.name != "posix", "POSIX processes")
class TestUfwProcess(unittest.TestCase):
    """How ufw is run: in the C locale (it translates the status line read
    here), and on timeout killed with all it started — its iptables-restore
    would otherwise go on applying rules after the lock is released."""

    def test_runs_in_the_c_locale(self) -> None:
        out = ufw_ops._run(["sh", "-c", 'echo "$LANGUAGE:$LC_ALL:$LANG"'], timeout=5).stdout
        self.assertEqual(out, "C:C:C\n")

    def test_a_timeout_kills_what_it_started(self) -> None:
        pidfile = os.path.join(tempfile.mkdtemp(prefix="ufw-okboy-run-"), "pid")
        with self.assertRaises(subprocess.TimeoutExpired):
            ufw_ops._run(["sh", "-c", f"sleep 30 & echo $! > {pidfile}; wait"], timeout=1)
        self._assert_gone(pidfile)

    def test_an_interrupt_kills_what_it_started(self) -> None:
        # Ctrl-C: in its own session, ufw never sees the terminal's SIGINT.
        pidfile = os.path.join(tempfile.mkdtemp(prefix="ufw-okboy-run-"), "pid")

        def interrupt(signum, frame):
            raise KeyboardInterrupt

        before = signal.signal(signal.SIGALRM, interrupt)
        signal.setitimer(signal.ITIMER_REAL, 1)
        try:
            with self.assertRaises(KeyboardInterrupt):
                ufw_ops._run(["sh", "-c", f"sleep 30 & echo $! > {pidfile}; wait"], timeout=30)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, before)
        self._assert_gone(pidfile)

    def _assert_gone(self, pidfile: str) -> None:
        with open(pidfile, encoding="utf-8") as f:
            pid = int(f.read())
        for _ in range(50):  # killed: gone, or a zombie not reaped yet
            try:
                with open(f"/proc/{pid}/stat", encoding="utf-8") as f:
                    if f.read().rsplit(")", 1)[1].split()[0] == "Z":
                        break
            except (FileNotFoundError, ProcessLookupError):  # gone (read can race the exit)
                break
            time.sleep(0.1)
        else:
            self.fail(f"what ufw started ({pid}) is still running")


@unittest.skipIf(fcntl is None, "POSIX flock")
class TestLockBusy(_Base):

    def test_a_request_behind_a_busy_lock_gets_503(self) -> None:
        self.db.create_user("alice", "secret-alice")
        self.ufw.lock.timeout = 0.2
        fd = os.open(os.path.join(self.tmpdir, "ufw.lock"), os.O_RDWR | os.O_CREAT)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX)  # a CLI command, or the cleanup timer
        r = self.client.post("/api/knock", headers={
            "Authorization": build_auth_header("alice", "secret-alice"),
            "X-Real-IP": "203.0.113.5"})
        self.assertEqual(r.status_code, 503)
        self.assertEqual(self.fake.rules(), [])


if __name__ == "__main__":
    unittest.main()
