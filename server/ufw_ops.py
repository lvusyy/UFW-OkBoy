"""UFW firewall operations and state management.

Responsibilities:
- Add/remove UFW allow rules with user-identifying comments
- Track per-user state (current IP, last knock time) via the Database layer
- Cleanup stale rules that exceed a configurable max age
"""

import glob
import logging
import re
import subprocess
import time

from db import Database

logger = logging.getLogger("ufw-okboy.ufw")


class UFWManager:
    """Manages UFW firewall rules and delegates user-IP state to a Database."""

    def __init__(self, rule_prefix: str = "ufw-okboy", db: Database | None = None) -> None:
        self.rule_prefix = rule_prefix
        if db is None:
            raise RuntimeError("UFWManager requires a Database instance")
        self.db: Database = db

    # ------------------------------------------------------------------ #
    #  UFW commands
    # ------------------------------------------------------------------ #

    @staticmethod
    def _run_ufw(*args: str) -> str:
        """Execute a UFW command, return stdout.

        Note: ``--force`` is NOT added globally — callers must include it
        explicitly when needed (e.g. ``delete``).  Some UFW versions reject
        ``--force`` before ``allow``/``deny``, causing *Invalid syntax*.
        """
        cmd = ["ufw", *args]
        logger.info("Exec: %s", " ".join(cmd))
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30, check=False,
        )
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
        self._run_ufw(
            "allow", "from", ip,
            "to", "any", "port", str(port), "proto", proto,
            "comment", comment,
        )
        logger.info("Added rule: %s -> port %s/%s (%s)", ip, port, proto, comment)

    def list_rules_by_comment(self, comment_prefix: str) -> list[dict]:
        """Return UFW rules whose comment starts with *comment_prefix*.

        Parses ``ufw status numbered`` output. Each returned item is::

            {"number": int, "ip": str, "port": int, "proto": str, "comment": str}

        Rules without a number (very old UFW) or failing to parse are
        skipped. Returns an empty list if the numbered view is unavailable.
        """
        try:
            output = subprocess.run(
                ["ufw", "status", "numbered"], capture_output=True,
                text=True, timeout=15, check=False,
            ).stdout
        except Exception:
            return []

        # Lines look like:
        # [ 1] 22/tcp                     ALLOW IN    1.2.3.4        # ufw-okboy:alice:web
        line_re = re.compile(
            r"^\s*\[\s*(?P<num>\d+)\s*\]\s+"
            r"(?P<port>\d+)/(?P<proto>\w+)\s+ALLOW\s+IN?\s+(?P<ip>\S+)"
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

    def list_all_rules(self) -> list[dict]:
        """Return ALL UFW rules from ``ufw status numbered`` (not just managed ones).

        Lets the admin inspect / clean up pre-existing system rules. Each item::

            {number, to, action, from, comment, is_okboy, looks_like_ssh, is_open}

        UFW's columns are whitespace-aligned and vary (ports, app profiles like
        "OpenSSH", IPv6 "(v6)", "Anywhere"), so this splits on the action keyword
        rather than a rigid column regex. Returns [] when the numbered view is
        unavailable (e.g. UFW inactive). ``looks_like_ssh`` flags rules that touch
        port 22 / SSH so the caller can guard against an accidental lock-out.
        """
        try:
            output = subprocess.run(
                ["ufw", "status", "numbered"], capture_output=True,
                text=True, timeout=15, check=False,
            ).stdout
        except Exception:
            return []

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

    def delete_rule(self, number: int) -> None:
        """Delete a UFW rule by its CURRENT number (``ufw --force delete N``).

        Rule numbers shift after each deletion, so callers must re-list between
        deletes. Raises RuntimeError on failure (propagated to the caller).
        """
        self._run_ufw("--force", "delete", str(int(number)))

    def remove_rule(self, ip: str, port: int, username: str, proto: str = "tcp",
                    group: str | None = None) -> None:
        """Remove a specific UFW rule. Logs warning if rule doesn't exist.

        *group* is accepted for symmetry with :meth:`add_rule`. When provided,
        the full comment ``<prefix>:<username>:<group>`` is matched precisely
        via :meth:`list_rules_by_comment` so that rules of other groups sharing
        the same ip/port/proto are NOT removed (fixes cross-group collision).

        Falls back to the legacy ip/port/proto match when the numbered view is
        unavailable or no comment match is found — callers relying on
        :meth:`reconcile_user_rules` will re-add any needed rules afterwards.
        """
        comment = f"{self.rule_prefix}:{username}"
        if group:
            comment = f"{comment}:{group}"

        # Precise path: locate the numbered rule whose comment matches exactly.
        for rule in self.list_rules_by_comment(comment):
            if (rule["ip"] == ip and rule["port"] == port
                    and rule["proto"] == proto and rule["comment"] == comment):
                try:
                    self._run_ufw("--force", "delete", str(rule["number"]))
                    logger.info(
                        "Removed rule (precise): %s -> port %s/%s (%s)",
                        ip, port, proto, comment,
                    )
                    return
                except RuntimeError:
                    break  # fall through to legacy path

        # Legacy / fallback path: match by ip/port/proto only.
        try:
            self._run_ufw(
                "--force", "delete", "allow", "from", ip,
                "to", "any", "port", str(port), "proto", proto,
            )
            logger.info("Removed rule: %s -> port %s/%s (%s)", ip, port, proto, comment)
        except RuntimeError:
            logger.warning("Rule removal failed (may not exist): %s -> %s/%s", ip, port, proto)

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

        Returns ``{"added": [...], "removed": [...]}`` (group names).
        """
        added: list[str] = []
        removed: list[str] = []

        # Single pass: fetch all of this user's rules once (fixes N+1).
        prefix = f"{self.rule_prefix}:{username}:"
        user_rules = self.list_rules_by_comment(prefix)
        existing = {(r["ip"], r["port"], r["proto"], r["comment"]): r for r in user_rules}

        # Add missing rules for every enabled group (per-group proto preserved).
        for group_name, (port, proto) in enabled_groups.items():
            comment = f"{prefix}{group_name}"
            if (client_ip, port, proto, comment) not in existing:
                # Isolate per-group failures (transient UFW lock, bad port, ...)
                # so one failing add does not abort the whole reconcile and skip
                # the stale-rule cleanup below — symmetric with the removal loop.
                try:
                    self.add_rule(client_ip, port, username, proto, group_name)
                    added.append(group_name)
                except RuntimeError:
                    logger.warning(
                        "reconcile: failed to add rule for group %s (%s:%s)",
                        group_name, port, proto,
                    )

        # Remove rules that are stale: group no longer enabled, OR bound to an
        # old IP (stale old-IP rule for an enabled group also gets cleaned up).
        enabled_names = set(enabled_groups.keys())
        for rule in user_rules:
            suffix = rule["comment"][len(prefix):]
            group_name = suffix.split(":", 1)[0] if suffix else ""
            stale = (group_name not in enabled_names) or (rule["ip"] != client_ip)
            if group_name and stale:
                try:
                    self._run_ufw("--force", "delete", str(rule["number"]))
                    removed.append(group_name)
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

        *user_group_ports* maps ``username -> [(group_name, port, proto), ...]`` from
        each user's actual enabled groups (the caller — app.py — builds it from
        the DB). When provided, cleanup only removes rules for the ports the
        user is actually authorized for, avoiding orphaned rules on custom
        group ports that ``protected_ports`` would miss (fixes ORPHAN-A).

        Falls back to the flat *ports* list (legacy protected_ports) only when
        *user_group_ports* is not provided, preserving backward compatibility.

        Returns list of removed usernames.
        """
        now = int(time.time())
        removed: list[str] = []
        legacy_ports = ports or []

        for user in self.db.list_users():
            last_knock = user["last_knock"]
            if last_knock is None:
                continue
            if now - last_knock > max_age_seconds:
                ip = user["current_ip"]
                username = user["username"]
                if ip:
                    if user_group_ports is not None:
                        # Remove rules only for the user's actual group ports
                        # (per-group proto preserved, group passed for precise delete).
                        for group_name, port, gproto in user_group_ports.get(username, []):
                            self.remove_rule(ip, port, username, gproto, group_name)
                    else:
                        for port in legacy_ports:
                            self.remove_rule(ip, port, username, proto)
                self.db.clear_user_state(user["id"])
                removed.append(username)
                logger.info(
                    "Cleaned up stale user: %s (last knock %ds ago)",
                    username, now - last_knock,
                )
        return removed

    def list_managed_rules(self) -> list[str]:
        """Parse ``ufw status`` output and return lines containing our rule prefix."""
        try:
            output = subprocess.run(
                ["ufw", "status"], capture_output=True, text=True, timeout=15, check=False,
            ).stdout
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
        """
        pattern = re.compile(
            rf"ALLOW\s+IN?\s+(\S+)\s+.*#\s*{re.escape(self.rule_prefix)}:([^:\s]+)(?::([^:\s]+))?"
        )
        try:
            output = subprocess.run(
                ["ufw", "status"], capture_output=True, text=True, timeout=15, check=False,
            ).stdout
        except Exception:
            return {}

        recovered: dict = {}
        now = int(time.time())
        # Group recovery by user so reconcile runs once per user.
        by_user: dict[str, str] = {}
        for line in output.splitlines():
            m = pattern.search(line)
            if m:
                ip, username = m.group(1), m.group(2)
                by_user[username] = ip

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
                self.reconcile_user_rules(username, ip, enabled)

        if recovered:
            logger.info("Recovered %d users from UFW rules", len(recovered))
        return recovered
