"""UFW firewall operations and state management.

Responsibilities:
- Add/remove UFW allow rules with user-identifying comments
- Track per-user state (current IP, last knock time) via the Database layer
- Cleanup stale rules that exceed a configurable max age
"""

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

    def remove_rule(self, ip: str, port: int, username: str, proto: str = "tcp",
                    group: str | None = None) -> None:
        """Remove a specific UFW rule. Logs warning if rule doesn't exist.

        Uses ``--force`` to suppress the interactive confirmation prompt
        that ``ufw delete`` would otherwise display.  *group* is accepted
        for symmetry with :meth:`add_rule` and used only in the log line;
        UFW deletion matches on ip/port/proto, not on the comment.
        """
        try:
            self._run_ufw(
                "--force", "delete", "allow", "from", ip,
                "to", "any", "port", str(port), "proto", proto,
            )
            label = f"{self.rule_prefix}:{username}" + (f":{group}" if group else "")
            logger.info("Removed rule: %s -> port %s/%s (%s)", ip, port, proto, label)
        except RuntimeError:
            logger.warning("Rule removal failed (may not exist): %s -> %s/%s", ip, port, proto)

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

    def cleanup_stale(self, max_age_seconds: int, ports: list[int],
                      proto: str = "tcp") -> list[str]:
        """Remove firewall rules for users who haven't knocked within *max_age_seconds*.

        Returns list of removed usernames.
        """
        now = int(time.time())
        removed: list[str] = []

        for user in self.db.list_users():
            last_knock = user["last_knock"]
            if last_knock is None:
                continue
            if now - last_knock > max_age_seconds:
                ip = user["current_ip"]
                username = user["username"]
                if ip:
                    for port in ports:
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

    def sync_state_from_ufw(self, ports: list[int]) -> dict:
        """Recover user IPs by parsing current UFW rules into the database.

        Useful if the DB state is lost but UFW rules still exist. Only
        users already present in the DB can be updated; unknown usernames
        are logged as warnings.
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
        for line in output.splitlines():
            m = pattern.search(line)
            if m:
                ip, username = m.group(1), m.group(2)
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

        if recovered:
            logger.info("Recovered %d users from UFW rules", len(recovered))
        return recovered
