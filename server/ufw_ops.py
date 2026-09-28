"""UFW firewall operations and state management.

Responsibilities:
- Add/remove UFW allow rules with user-identifying comments
- Track per-user state (current IP, last knock time) via the Database layer
- Cleanup stale rules that exceed a configurable max age
"""

import contextlib
import glob
import ipaddress
import logging
import os
import re
import signal
import subprocess
import threading
import time

try:
    import fcntl
except ImportError:  # not POSIX (a dev box running the unit tests): thread lock only
    fcntl = None

from db import Database

logger = logging.getLogger("ufw-okboy.ufw")


def _ufw_env() -> dict:
    """The environment ufw runs in: the C locale. ufw translates its status
    line ("Status: active" / "Status: inactive"), which is read here; the rule
    lines it prints untranslated either way."""
    return {**os.environ, "LANGUAGE": "C", "LC_ALL": "C", "LANG": "C"}


def _run(cmd: list[str], timeout: float) -> subprocess.CompletedProcess:
    """Run ufw like subprocess.run — in the C locale, and in its own process
    group, all of which is killed if the wait ends early (a timeout, Ctrl-C):
    ufw hands its changes to iptables-restore, and killing ufw alone — or, in
    its own session, ufw not seeing the terminal's Ctrl-C at all — would leave
    that applying them after the host lock is released, maybe an older rule
    set over a newer."""
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, env=_ufw_env(), start_new_session=True) as proc:
        try:
            out, err = proc.communicate(timeout=timeout)
        except BaseException:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.communicate()
            raise
    return subprocess.CompletedProcess(cmd, proc.returncode, out, err)


def _rule_source(column: str) -> str:
    """The source address of a rule as ``ufw status`` lists it ("203.0.113.7",
    "203.0.113.7 (log)", "::ffff:203.0.113.7", "Anywhere (v6)"), normalized;
    "" when it is not one address. Unlike canonical_ip, an IPv4-mapped IPv6
    address stays IPv6: ufw keeps a rule for it apart from the IPv4 one."""
    column = re.sub(r"\s+\((?:log|log-all)\)$", "", column.strip())
    try:
        return str(ipaddress.ip_address(column))
    except ValueError:
        return ""


def canonical_ip(value) -> str:
    """Return *value* as one canonical IP address ("203.0.113.7", "2001:db8::1";
    an IPv4-mapped IPv6 address becomes plain IPv4), or "" for anything else: a
    CIDR, a zone-scoped address, a hostname, or a ufw keyword like "any". Only a
    single address may reach a rule — ufw reads "any" or "0.0.0.0/0" as everyone.
    """
    if not isinstance(value, str):
        return ""
    s = value.strip()
    if not s or "%" in s:
        return ""
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return ""
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ip)


class LockTimeout(RuntimeError):
    """The host lock was not free within HostLock.timeout."""


class DeadlineExceeded(RuntimeError):
    """A request's time for ufw commands ran out (see UFWManager.deadline)."""


class HostLock:
    """An exclusive lock shared by every thread and process on the host (gunicorn
    workers, CLI commands, the cleanup timer): an flock on *path*, re-entrant
    within a thread.

    ufw rule numbers shift after every delete, so a list-then-delete sequence
    must not interleave with another one — the delete would remove whatever rule
    moved into place, possibly a host DENY or the SSH rule. The app also holds it
    across a whole knock or admin change, so its database and firewall updates
    never interleave with another's.
    """

    def __init__(self, path: str, timeout: float | None = None) -> None:
        self.path = path
        # Seconds to wait before giving up with LockTimeout (None: as long as it
        # takes). The server sets one below gunicorn's worker timeout, so a
        # request stuck behind a long CLI or cleanup run fails cleanly instead
        # of having its worker killed.
        self.timeout = timeout
        self._mu = threading.RLock()
        self._depth = 0
        self._fd = None

    def __enter__(self):
        deadline = None if self.timeout is None else time.monotonic() + self.timeout
        if not self._mu.acquire(timeout=-1 if deadline is None else self.timeout):
            raise LockTimeout(f"{self.path} is busy")
        if self._depth == 0 and fcntl is not None:
            try:
                fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
                try:
                    self._flock(fd, deadline)
                except BaseException:
                    os.close(fd)
                    raise
            except BaseException:
                self._mu.release()
                raise
            self._fd = fd
        self._depth += 1
        return self

    def _flock(self, fd: int, deadline: float | None) -> None:
        if deadline is None:
            fcntl.flock(fd, fcntl.LOCK_EX)
            return
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise LockTimeout(f"{self.path} is busy") from None
                time.sleep(0.05)

    def __exit__(self, *exc) -> bool:
        self._depth -= 1
        if self._depth == 0 and self._fd is not None:
            fd, self._fd = self._fd, None
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        self._mu.release()
        return False


class UFWManager:
    """Manages UFW firewall rules and delegates user-IP state to a Database."""

    def __init__(self, rule_prefix: str = "ufw-okboy", db: Database | None = None,
                 lock_path: str | None = None) -> None:
        self.rule_prefix = rule_prefix
        if db is None:
            raise RuntimeError("UFWManager requires a Database instance")
        self.db: Database = db
        # Next to the database: every process of this install (server workers,
        # CLI, cleanup timer) uses the same config, hence the same lock file.
        self.lock = HostLock(lock_path or os.path.join(
            os.path.dirname(os.path.abspath(db.db_path)), "ufw.lock"))
        self._limit = threading.local()  # see deadline()

    @contextlib.contextmanager
    def deadline(self, seconds: float):
        """Within the block, every ufw command must end *seconds* from now: one
        still running then is killed, and none starts after. A server request
        must end before gunicorn kills its worker — that would leave a ufw
        command running on after the host lock is released. Nested, the earlier
        deadline holds."""
        before = getattr(self._limit, "at", None)
        at = time.monotonic() + seconds
        self._limit.at = at if before is None else min(before, at)
        try:
            yield
        finally:
            self._limit.at = before

    def _timeout(self, cap: float) -> float:
        """Seconds a ufw command may take: *cap*, or less when the deadline (see
        :meth:`deadline`) is nearer; DeadlineExceeded once it has passed."""
        at = getattr(self._limit, "at", None)
        if at is None:
            return cap
        left = at - time.monotonic()
        if left <= 0:
            raise DeadlineExceeded("UFW command not run: out of time")
        return min(cap, left)

    # ------------------------------------------------------------------ #
    #  UFW commands
    # ------------------------------------------------------------------ #

    def _run_ufw(self, *args: str) -> str:
        """Execute a UFW command, return stdout.

        Note: ``--force`` is NOT added globally — callers must include it
        explicitly when needed (e.g. ``delete``).  Some UFW versions reject
        ``--force`` before ``allow``/``deny``, causing *Invalid syntax*.
        """
        cmd = ["ufw", *args]
        logger.info("Exec: %s", " ".join(cmd))
        # One exception type for every failure: callers keep their state on
        # RuntimeError, and a timeout used to escape that (a CLI revoke then
        # exited before rotating the secret).
        limit = self._timeout(30)
        try:
            result = _run(cmd, timeout=limit)
        except subprocess.TimeoutExpired as exc:
            if limit < 30:  # killed at the request's deadline, not ufw's own limit
                raise DeadlineExceeded(f"UFW command killed: out of time ({exc})") from exc
            raise RuntimeError(f"UFW command failed: {exc}") from exc
        except OSError as exc:
            raise RuntimeError(f"UFW command failed: {exc}") from exc
        if result.returncode != 0:
            logger.error(
                "UFW failed (rc=%d): cmd=%s | stderr=%s",
                result.returncode, " ".join(cmd), result.stderr.strip(),
            )
            raise RuntimeError(f"UFW command failed: {result.stderr.strip()}")
        return result.stdout

    def add_rule(self, ip: str, port: int, username: str, proto: str = "tcp",
                 group: str | None = None) -> None:
        """Add a UFW allow rule: allow <ip> to access <port> with identifying comment.

        When *group* is provided the comment becomes
        ``<prefix>:<username>:<group>`` for traceability; otherwise it stays
        ``<prefix>:<username>`` (backward compatible).
        """
        comment = f"{self.rule_prefix}:{username}"
        if group:
            comment = f"{comment}:{group}"
        src = canonical_ip(ip)
        if not src:
            raise RuntimeError(f"refusing to add a rule for {ip!r}: not a single IP address")
        if proto not in ("tcp", "udp") or not isinstance(port, int) or not 1 <= port <= 65535:
            raise RuntimeError(f"refusing to add a rule for port {port!r}/{proto!r}")
        with self.lock:
            # ufw keeps one rule per source, port and protocol: ours would
            # replace a host rule with the same ones — a DENY would become an
            # ALLOW, and this user's revoke or cleanup would then delete it.
            to = f"{port}/{proto}"
            for r in self.list_all_rules(strict=True):
                if (r["to"] == to and r["action"].endswith(" IN")
                        and _rule_source(r["from"]) == src
                        and not r["comment"].startswith(f"{self.rule_prefix}:")):
                    logger.warning("Not adding %s -> port %s/%s (%s): host rule [%d] %s %s "
                                   "stays as it is", src, port, proto, comment,
                                   r["number"], r["action"], r["from"])
                    return
            self._run_ufw(
                "allow", "from", src,
                "to", "any", "port", str(port), "proto", proto,
                "comment", comment,
            )
        logger.info("Added rule: %s -> port %s/%s (%s)", src, port, proto, comment)

    def list_rules_by_comment(self, comment_prefix: str, strict: bool = False) -> list[dict]:
        """Return UFW rules whose comment starts with *comment_prefix*.

        Parses ``ufw status numbered`` output. Each returned item is::

            {"number": int, "ip": str, "port": int, "proto": str, "comment": str}

        Rules without a number (very old UFW) or failing to parse are
        skipped. Returns an empty list if the numbered view is unavailable —
        unless *strict*: then that raises RuntimeError, as a removal must not
        take "could not list the rules" for "no rule to remove".
        """
        output = self._status_numbered(strict)

        # Lines look like:
        # [ 1] 22/tcp                     ALLOW IN    1.2.3.4        # ufw-okboy:alice:web
        # [ 9] 22/tcp (v6)                ALLOW IN    Anywhere (v6)  # ufw-okboy:alice:web
        # The second form is the IPv6 half ufw adds for a rule "from any" (one
        # injected before addresses were validated): it must be found to go.
        line_re = re.compile(
            r"^\s*\[\s*(?P<num>\d+)\s*\]\s+"
            r"(?P<port>\d+)/(?P<proto>\w+)(?:\s+\(v6\))?\s+ALLOW\s+IN?\s+"
            r"(?P<ip>\S+(?:\s+\(v6\))?)"
            r"(?:\s+#\s*(?P<comment>.*))?\s*$"
        )
        rules: list[dict] = []
        for line in output.splitlines():
            m = line_re.match(line)
            if not m:
                continue
            comment = (m.group("comment") or "").strip()
            if not comment.startswith(comment_prefix):
                continue
            rules.append({
                "number": int(m.group("num")),
                "ip": m.group("ip"),
                "port": int(m.group("port")),
                "proto": m.group("proto"),
                "comment": comment,
            })
        return rules

    @staticmethod
    def _detect_ssh_ports(paths: list[str] | None = None) -> set[str]:
        """Best-effort set of ports sshd actually listens on (from sshd_config).

        Reads ``/etc/ssh/sshd_config`` plus any ``sshd_config.d/*.conf`` drop-ins
        (the layout modern Debian/Ubuntu use). Multiple ``Port`` lines are allowed.
        Falls back to ``{"22"}`` — sshd's compiled-in default — when nothing is
        readable or declared, so the lock-out guard never silently goes blind.
        The ``paths`` arg exists for testing.
        """
        if paths is None:
            paths = ["/etc/ssh/sshd_config"]
            try:
                paths += sorted(glob.glob("/etc/ssh/sshd_config.d/*.conf"))
            except Exception:
                pass
        ports: set[str] = set()
        for path in paths:
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        s = line.strip()
                        if not s or s.startswith("#"):
                            continue
                        parts = s.split()
                        # "Port 2222" — ignore "Ports", "PortForwarding", etc.
                        if len(parts) >= 2 and parts[0].lower() == "port" and parts[1].isdigit():
                            ports.add(parts[1])
            except OSError:
                continue
        return ports or {"22"}

    def _status_numbered(self, strict: bool) -> str:
        """``ufw status numbered``. A failure reads as no rules — unless
        *strict*: then it raises RuntimeError, and so does an inactive ufw,
        which lists nothing although its rules stay saved (``ufw enable``
        brings them back): a removal must not take either for "no rule"."""
        if strict:
            output = self._run_ufw("status", "numbered")
            if output.lstrip().startswith("Status: inactive"):
                raise RuntimeError("ufw is inactive: its rules cannot be listed")
            return output
        try:
            return _run(["ufw", "status", "numbered"], timeout=self._timeout(15)).stdout
        except Exception:
            return ""

    def list_all_rules(self, strict: bool = False) -> list[dict]:
        """Return ALL UFW rules from ``ufw status numbered`` (not just managed ones).

        Lets the admin inspect / clean up pre-existing system rules. Each item::

            {number, to, action, from, comment, is_okboy, looks_like_ssh, is_open}

        UFW's columns are whitespace-aligned and vary (ports, app profiles like
        "OpenSSH", IPv6 "(v6)", "Anywhere"), so this splits on the action keyword
        rather than a rigid column regex. Returns [] when the numbered view is
        unavailable (e.g. UFW inactive) — *strict*, raises RuntimeError instead
        (see :meth:`_status_numbered`). ``looks_like_ssh`` flags rules that touch
        port 22 / SSH so the caller can guard against an accidental lock-out.
        """
        output = self._status_numbered(strict)

        ssh_ports = self._detect_ssh_ports()
        num_re = re.compile(r"^\s*\[\s*(\d+)\s*\]\s+(.*\S)\s*$")
        act_re = re.compile(r"\b(ALLOW|DENY|REJECT|LIMIT)\b")
        rules: list[dict] = []
        for line in output.splitlines():
            m = num_re.match(line)
            if not m:
                continue
            number = int(m.group(1))
            body = m.group(2)
            comment = ""
            if "#" in body:
                body, comment = body.split("#", 1)
                comment, body = comment.strip(), body.rstrip()
            am = act_re.search(body)
            if am:
                to = body[:am.start()].strip()
                rest = body[am.start():].split(None, 2)
                action = " ".join(rest[:2]) if len(rest) >= 2 else rest[0]
                frm = rest[2].strip() if len(rest) >= 3 else ""
            else:
                to, action, frm = body.strip(), "", ""
            blob = f"{to} {comment}".lower()
            to_ports = set(re.findall(r"\d+", to))
            looks_like_ssh = ("ssh" in blob) or bool(to_ports & ssh_ports)
            # "Open" = an ALLOW reachable from any source (no IP restriction).
            # Used to nudge the admin to lock down management ports (SSH) via a
            # group instead of leaving them world-open.
            is_open = ("ALLOW" in action.upper()) and ("anywhere" in frm.lower())
            rules.append({
                "number": number, "to": to, "action": action, "from": frm,
                "comment": comment,
                "is_okboy": comment.startswith(self.rule_prefix),
                "looks_like_ssh": looks_like_ssh,
                "is_open": is_open,
            })
        return rules

    def delete_rule(self, number: int, expect: dict | None = None) -> None:
        """Delete a UFW rule by its CURRENT number (``ufw --force delete N``).

        Rule numbers shift after each deletion. With *expect* (a rule as returned
        by :meth:`list_all_rules`), the rule now at *number* must still be that
        rule — checked under the host lock, so nothing can move another rule into
        its place in between; LookupError otherwise. Raises RuntimeError when ufw
        fails (propagated to the caller).
        """
        with self.lock:
            if expect is not None:
                now = next((r for r in self.list_all_rules() if r["number"] == int(number)), None)
                if now is None or any(now[k] != expect[k] for k in ("to", "action", "from", "comment")):
                    raise LookupError(f"rule {number} is no longer the one listed")
            self._run_ufw("--force", "delete", str(int(number)))

    def remove_rule(self, ip: str, port: int, username: str, proto: str = "tcp",
                    group: str | None = None) -> None:
        """Remove the user's rule for ip/port/proto: the one carrying their own
        comment (``<prefix>:<username>:<group>``, or ``<prefix>:<username>`` from
        versions before groups). A missing rule is not an error.

        Only a rule with this user's comment is ever deleted — matching on
        ip/port/proto alone could delete another user's rule behind the same NAT
        address, or a host rule. Raises RuntimeError when ufw fails to delete.
        """
        base = f"{self.rule_prefix}:{username}"
        wanted = {f"{base}:{group}", base} if group else {base}
        with self.lock:  # the number found must still be this rule's
            for rule in self.list_rules_by_comment(base, strict=True):
                if (rule["comment"] in wanted and rule["ip"] == ip
                        and rule["port"] == port and rule["proto"] == proto):
                    self._run_ufw("--force", "delete", str(rule["number"]))
                    logger.info("Removed rule: %s -> port %s/%s (%s)",
                                ip, port, proto, rule["comment"])
                    return
        logger.info("No rule to remove: %s -> port %s/%s (%s)", ip, port, proto, base)

    def purge_rules(self, username: str | None = None, group: str | None = None,
                    port: int | None = None, proto: str | None = None) -> int:
        """Delete every rule of *username* (any group), of *group* (any user), or
        of that user in that group — whatever the source address: a stale IP, or
        an "any" injected before addresses were validated, must go too. For when
        the user, group or membership is going away, or access is revoked.

        A rule from before groups (comment ``<prefix>:<user>``) names no group:
        with *group*, it counts as that group's when it is on the group's
        *port*/*proto*.

        Deletes from the highest number down, under the host lock. Returns how
        many were deleted; raises RuntimeError when ufw fails — listing the
        rules included — so the caller can keep what it would otherwise forget
        until the rule is really gone.
        """
        prefix = f"{self.rule_prefix}:"
        with self.lock:
            doomed = []
            for rule in self.list_rules_by_comment(prefix, strict=True):
                user, _, grp = rule["comment"][len(prefix):].partition(":")
                if username is not None and user != username:
                    continue
                pre_group = grp == "" and (rule["port"], rule["proto"]) == (port, proto)
                if group is not None and grp != group and not pre_group:
                    continue
                doomed.append(rule)
            for rule in sorted(doomed, key=lambda r: r["number"], reverse=True):
                self._run_ufw("--force", "delete", str(rule["number"]))
                logger.info("Removed rule: %s -> port %s/%s (%s)",
                            rule["ip"], rule["port"], rule["proto"], rule["comment"])
        return len(doomed)

    def reconcile_user_rules(self, username: str, client_ip: str,
                             enabled_groups: dict[str, tuple[int, str]]) -> dict:
        """Idempotently align UFW rules with the user's *enabled_groups*.

        *enabled_groups* maps ``group_name -> (port, proto)`` for the groups the
        user is currently authorized to access. For each, an allow rule is added
        if missing (comment ``<prefix>:<username>:<group>``). Then all current
        rules for this user are scanned in a SINGLE ``ufw status numbered`` pass
        (not per-group — avoids N+1 subprocess calls), and any rule is removed when
        EITHER its group is no longer enabled OR its recorded IP differs from
        *client_ip* — repairing cross-group collisions, stale memberships,
        concurrent membership changes, AND stale old-IP rules for enabled groups.

        Returns ``{"added": [...], "removed": [...]}`` (group names). Raises
        RuntimeError when the rules cannot be listed, DeadlineExceeded when out
        of time: then it is not done, and the caller must not act as if it were.
        A single rule that ufw fails to add or delete is only logged.
        """
        with self.lock:  # numbers from a listing are only valid under it
            return self._reconcile_locked(username, client_ip, enabled_groups)

    def _reconcile_locked(self, username: str, client_ip: str,
                          enabled_groups: dict[str, tuple[int, str]]) -> dict:
        added: list[str] = []
        removed: list[str] = []

        # Single pass: fetch all of this user's rules once (fixes N+1) — a rule
        # from before groups ("<prefix>:<user>") too: the per-group rules
        # supersede it, and nothing else would ever remove it.
        prefix = f"{self.rule_prefix}:{username}:"
        pre_group = prefix[:-1]

        def listing() -> list[dict]:
            return [r for r in self.list_rules_by_comment(pre_group, strict=True)
                    if r["comment"] == pre_group or r["comment"].startswith(prefix)]

        user_rules = listing()
        existing = {(r["ip"], r["port"], r["proto"], r["comment"]): r for r in user_rules}

        # Add missing rules for every enabled group (per-group proto preserved).
        tried = False
        for group_name, (port, proto) in enabled_groups.items():
            comment = f"{prefix}{group_name}"
            if (client_ip, port, proto, comment) not in existing:
                tried = True
                # Isolate per-group failures (transient UFW lock, bad port, ...)
                # so one failing add does not abort the whole reconcile and skip
                # the stale-rule cleanup below — symmetric with the removal loop.
                try:
                    self.add_rule(client_ip, port, username, proto, group_name)
                    added.append(group_name)
                except DeadlineExceeded:
                    raise
                except RuntimeError:
                    logger.warning(
                        "reconcile: failed to add rule for group %s (%s:%s)",
                        group_name, port, proto,
                    )

        # Remove rules that are stale: group no longer enabled, OR bound to an
        # old IP (stale old-IP rule for an enabled group also gets cleaned up).
        # An added IPv4 rule goes before every IPv6 one and renumbers them, and
        # so may an add that failed (ufw saves a rule before applying it to the
        # running firewall): after any add, look the stale rules up again.
        # Delete from the highest number down: each delete then leaves the
        # numbers of those still to go untouched (ascending, the second delete
        # would hit the rule that moved into the first one's place — another
        # user's, or a host DENY).
        if tried:
            user_rules = listing()
        enabled_names = set(enabled_groups.keys())
        for rule in sorted(user_rules, key=lambda r: r["number"], reverse=True):
            suffix = rule["comment"][len(prefix):]
            group_name = suffix.split(":", 1)[0] if suffix else ""
            stale = (group_name not in enabled_names) or (rule["ip"] != client_ip)
            if stale:
                try:
                    self._run_ufw("--force", "delete", str(rule["number"]))
                    removed.append(group_name or rule["comment"])
                except DeadlineExceeded:
                    raise
                except RuntimeError:
                    logger.warning(
                        "reconcile: failed to remove stale rule %s (%s)",
                        rule["number"], rule["comment"],
                    )

        if added or removed:
            logger.info(
                "Reconciled rules for %s@%s: added=%s removed=%s",
                username, client_ip, added, removed,
            )
        return {"added": added, "removed": removed}

    # ------------------------------------------------------------------ #
    #  User state queries
    # ------------------------------------------------------------------ #

    def get_user_ip(self, username: str) -> str | None:
        """Return the currently registered IP for a user, or None."""
        return self.db.get_user_ip(username)

    def get_user_state(self, username: str) -> dict:
        """Return full state dict for a user (API-safe view)."""
        user = self.db.get_user_by_username(username)
        if not user:
            return {"ip": None, "last_knock": None, "ip_changes_recent": 0}
        return {
            "ip": user["current_ip"],
            "last_knock": user["last_knock"],
            "ip_changes_recent": self.db.count_recent_ip_changes(username, 86400),
        }

    def update_state(self, username: str, ip: str) -> None:
        """Record a new IP and knock timestamp, logging the prior IP change."""
        user = self.db.get_user_by_username(username)
        if not user:
            logger.warning("update_state: unknown user %s", username)
            return
        old_ip = user["current_ip"]
        if old_ip and old_ip != ip:
            self.db.log_operation(username, "ip_change", ip=old_ip)
        self.db.set_user_ip(user["id"], ip)
        self.db.update_knock_time(user["id"], ip)

    def update_knock_time(self, username: str, ip: str) -> None:
        """Update only the last-knock timestamp (IP unchanged)."""
        user = self.db.get_user_by_username(username)
        if not user:
            logger.warning("update_knock_time: unknown user %s", username)
            return
        self.db.update_knock_time(user["id"], ip)

    def check_ip_anomaly(self, username: str, window_seconds: int = 3600,
                         max_changes: int = 5) -> dict | None:
        """Detect suspicious IP change patterns that suggest credential sharing.

        Returns:
            None if normal, or dict with anomaly details if suspicious.
        """
        user = self.db.get_user_by_username(username)
        if not user:
            return None
        changes = self.db.count_recent_ip_changes(username, window_seconds)
        if changes >= max_changes:
            ips = self.db.get_recent_ip_change_ips(username, window_seconds)
            unique = set(ips)
            if user["current_ip"]:
                unique.add(user["current_ip"])
            return {
                "changes": changes,
                "window": window_seconds,
                "unique_ips": len(unique),
                "ips": list(unique),
            }
        return None

    # ------------------------------------------------------------------ #
    #  Maintenance
    # ------------------------------------------------------------------ #

    def cleanup_stale(self, max_age_seconds: int,
                      user_group_ports: dict[str, list[tuple[str, int, str]]] | None = None,
                      ports: list[int] | None = None,
                      proto: str = "tcp") -> list[str]:
        """Remove firewall rules for users who haven't knocked within *max_age_seconds*.

        Every rule carrying a stale user's comment is removed, whatever its
        group or address (:meth:`purge_rules`) — also those of groups since
        disabled or left, which a per-group pass missed. *user_group_ports*,
        *ports* and *proto* are no longer needed; they are accepted so existing
        callers keep working.

        A user who never knocked successfully has no rule — unless a knock
        added one and then failed, recording nothing: such a rule would never
        expire, so it goes too.

        Returns list of removed usernames.
        """
        now = int(time.time())
        removed: list[str] = []
        prefix = f"{self.rule_prefix}:"
        try:
            ruled = {r["comment"][len(prefix):].partition(":")[0]
                     for r in self.list_rules_by_comment(prefix, strict=True)}
        except RuntimeError as exc:
            logger.warning("Cleanup could not list the rules: %s", exc)
            ruled = set()

        def due(user) -> bool:
            if user is None:
                return False
            if user["last_knock"] is None:
                return user["username"] in ruled
            return now - user["last_knock"] > max_age_seconds

        for listed in self.db.list_users():
            if not due(listed):
                continue
            with self.lock:
                # Re-read under the lock: a knock may have refreshed the user (new
                # IP, new rules) since the listing, and must not be undone.
                user = self.db.get_user(listed["id"])
                if not due(user):
                    continue
                last_knock = user["last_knock"]
                username = user["username"]
                # Every rule carrying the user's comment — also those of groups
                # since disabled or left, and at older addresses.
                try:
                    self.purge_rules(username=username)
                except RuntimeError as exc:
                    # Keep the state, so the next run tries again.
                    logger.warning("Cleanup of %s failed, retried next run: %s", username, exc)
                    continue
                self.db.clear_user_state(user["id"])
            removed.append(username)
            logger.info(
                "Cleaned up stale user: %s (%s)", username,
                f"last knock {now - last_knock}s ago" if last_knock is not None
                else "rules left by a knock that failed",
            )
        return removed

    def list_managed_rules(self) -> list[str]:
        """Parse ``ufw status`` output and return lines containing our rule prefix."""
        try:
            output = _run(["ufw", "status"], timeout=self._timeout(15)).stdout
        except Exception:
            return []

        return [
            line.strip()
            for line in output.splitlines()
            if self.rule_prefix in line
        ]

    def sync_state_from_ufw(self, ports: list[int],
                            user_group_ports: dict[str, list[tuple[str, int, str]]] | None = None,
                            proto: str = "tcp") -> dict:
        """Recover user IPs by parsing current UFW rules into the database.

        Useful if the DB state is lost but UFW rules still exist. Only
        users already present in the DB can be updated; unknown usernames
        are logged as warnings.

        When *user_group_ports* (``username -> [(group_name, port, proto), ...]`` of
        ENABLED groups) is provided, each recovered user's rules are reconciled
        against their currently-enabled groups: rules for disabled groups are
        removed, so UFW ends up consistent with DB enabled state (fixes ORPHAN-B).

        Hold :attr:`lock` from reading *user_group_ports* until this returns: a
        deletion completing in between would otherwise be undone from the
        stale map.
        """
        # The numbered listing: plain `ufw status` prints "ALLOW", not "ALLOW
        # IN", and the pattern once used on it never matched a rule.
        prefix = f"{self.rule_prefix}:"
        recovered: dict = {}
        now = int(time.time())
        # Group recovery by user so reconcile runs once per user.
        by_user: dict[str, str] = {}
        for rule in self.list_rules_by_comment(prefix):
            ip = canonical_ip(rule["ip"])
            if ip:  # not "Anywhere" (a rule injected before addresses were checked)
                by_user[rule["comment"][len(prefix):].split(":", 1)[0]] = ip

        for username, ip in by_user.items():
            user = self.db.get_user_by_username(username)
            if not user:
                logger.warning("sync: UFW rule references unknown user %s", username)
                continue
            self.db.set_user_ip(user["id"], ip)
            self.db.conn.execute(
                "UPDATE users SET last_knock=? WHERE id=?", (now, user["id"]),
            )
            self.db.conn.commit()
            recovered[username] = {"ip": ip, "last_knock": now}

            # Reconcile against enabled groups: drop rules for disabled groups.
            if user_group_ports is not None:
                enabled = {
                    gname: (gport, gproto)
                    for gname, gport, gproto in user_group_ports.get(username, [])
                }
                try:
                    self.reconcile_user_rules(username, ip, enabled)
                except RuntimeError as exc:  # the next knock reconciles
                    logger.warning("sync: could not reconcile %s: %s", username, exc)

        if recovered:
            logger.info("Recovered %d users from UFW rules", len(recovered))
        return recovered
