"""SQLite database layer for UFW OkBoy.

Wraps a single sqlite3.Connection with WAL journaling and foreign-key
enforcement. Provides the 6-table schema (users, groups,
user_group_membership, audit_log, operation_log, failed_attempts) plus
CRUD, logging helpers, state queries, and one-time JSON state migration.
"""

import json
import logging
import sqlite3
import time
from pathlib import Path

logger = logging.getLogger("ufw-okboy.db")


SCHEMA: dict[str, str] = {
    "users": """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            secret TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            current_ip TEXT,
            last_knock INTEGER,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """,
    "groups": """
        CREATE TABLE groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            port INTEGER NOT NULL,
            proto TEXT NOT NULL DEFAULT 'tcp',
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """,
    "user_group_membership": """
        CREATE TABLE user_group_membership (
            user_id INTEGER NOT NULL,
            group_id INTEGER NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            joined_at TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY (user_id, group_id),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
        )
    """,
    "audit_log": """
        CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT,
            detail TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """,
    "operation_log": """
        CREATE TABLE operation_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            ip TEXT,
            detail TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """,
    "failed_attempts": """
        CREATE TABLE failed_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            ip TEXT,
            reason TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """,
}


class Database:
    """SQLite-backed persistence for UFW OkBoy.

    The connection is opened with ``check_same_thread=False`` so it can be
    shared across Flask/gunicorn worker threads. Callers should keep
    transactions short.
    """

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn: sqlite3.Connection = sqlite3.connect(
            db_path, check_same_thread=False,
        )
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")

    # ------------------------------------------------------------------ #
    #  Schema
    # ------------------------------------------------------------------ #

    def init(self) -> None:
        """Create all tables if they do not already exist."""
        for name, ddl in SCHEMA.items():
            if self._table_exists(name):
                continue
            self.conn.execute(ddl)
        self.conn.commit()

    def _table_exists(self, name: str) -> bool:
        """Return True if a table named *name* already exists."""
        row = self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (name,),
        ).fetchone()
        return row is not None

    def close(self) -> None:
        """Close the underlying connection."""
        self.conn.close()

    # ------------------------------------------------------------------ #
    #  User CRUD
    # ------------------------------------------------------------------ #

    def create_user(self, username: str, secret: str, is_admin: bool = False) -> int:
        """Insert a new user and return its id."""
        cur = self.conn.execute(
            "INSERT INTO users (username, secret, is_admin) VALUES (?, ?, ?)",
            (username, secret, 1 if is_admin else 0),
        )
        self.conn.commit()
        return cur.lastrowid

    def get_user_by_username(self, username: str) -> sqlite3.Row | None:
        """Return the user row matching *username*, or None."""
        return self.conn.execute(
            "SELECT * FROM users WHERE username=?", (username,),
        ).fetchone()

    def get_user(self, user_id: int) -> sqlite3.Row | None:
        """Return the user row matching *user_id*, or None."""
        return self.conn.execute(
            "SELECT * FROM users WHERE id=?", (user_id,),
        ).fetchone()

    def list_users(self) -> list[sqlite3.Row]:
        """Return all user rows ordered by username."""
        return self.conn.execute(
            "SELECT * FROM users ORDER BY username",
        ).fetchall()

    def delete_user(self, user_id: int) -> None:
        """Delete a user by id (cascades to membership)."""
        self.conn.execute("DELETE FROM users WHERE id=?", (user_id,))
        self.conn.commit()

    def set_user_admin(self, user_id: int, is_admin: bool) -> None:
        """Set the admin flag for a user."""
        self.conn.execute(
            "UPDATE users SET is_admin=? WHERE id=?",
            (1 if is_admin else 0, user_id),
        )
        self.conn.commit()

    # ------------------------------------------------------------------ #
    #  Group CRUD
    # ------------------------------------------------------------------ #

    def create_group(self, name: str, port: int, proto: str = "tcp") -> int:
        """Insert a new group and return its id."""
        cur = self.conn.execute(
            "INSERT INTO groups (name, port, proto) VALUES (?, ?, ?)",
            (name, port, proto),
        )
        self.conn.commit()
        return cur.lastrowid

    def get_group(self, group_id: int) -> sqlite3.Row | None:
        """Return the group row matching *group_id*, or None."""
        return self.conn.execute(
            "SELECT * FROM groups WHERE id=?", (group_id,),
        ).fetchone()

    def get_group_by_name(self, name: str) -> sqlite3.Row | None:
        """Return the group row matching *name*, or None."""
        return self.conn.execute(
            "SELECT * FROM groups WHERE name=?", (name,),
        ).fetchone()

    def list_groups(self) -> list[sqlite3.Row]:
        """Return all group rows ordered by name."""
        return self.conn.execute(
            "SELECT * FROM groups ORDER BY name",
        ).fetchall()

    def delete_group(self, group_id: int) -> None:
        """Delete a group by id (cascades to membership)."""
        self.conn.execute("DELETE FROM groups WHERE id=?", (group_id,))
        self.conn.commit()

    # ------------------------------------------------------------------ #
    #  Membership CRUD
    # ------------------------------------------------------------------ #

    def add_membership(self, user_id: int, group_id: int, enabled: int = 1) -> None:
        """Add a user to a group, ignoring if already a member."""
        self.conn.execute(
            "INSERT OR IGNORE INTO user_group_membership (user_id, group_id, enabled) "
            "VALUES (?, ?, ?)",
            (user_id, group_id, enabled),
        )
        self.conn.commit()

    def remove_membership(self, user_id: int, group_id: int) -> None:
        """Remove a user from a group."""
        self.conn.execute(
            "DELETE FROM user_group_membership WHERE user_id=? AND group_id=?",
            (user_id, group_id),
        )
        self.conn.commit()

    def set_membership_enabled(self, user_id: int, group_id: int, enabled: int) -> None:
        """Toggle the enabled flag on an existing membership."""
        self.conn.execute(
            "UPDATE user_group_membership SET enabled=? WHERE user_id=? AND group_id=?",
            (enabled, user_id, group_id),
        )
        self.conn.commit()

    def get_user_groups(self, user_id: int, only_enabled: bool = False) -> list[sqlite3.Row]:
        """Return group rows for a user, optionally filtering to enabled memberships."""
        sql = (
            "SELECT g.* FROM groups g "
            "JOIN user_group_membership m ON m.group_id = g.id "
            "WHERE m.user_id=?"
        )
        if only_enabled:
            sql += " AND m.enabled=1"
        sql += " ORDER BY g.name"
        return self.conn.execute(sql, (user_id,)).fetchall()

    def get_group_members(self, group_id: int) -> list[sqlite3.Row]:
        """Return user rows for members of a group."""
        return self.conn.execute(
            "SELECT u.* FROM users u "
            "JOIN user_group_membership m ON m.user_id = u.id "
            "WHERE m.group_id=? ORDER BY u.username",
            (group_id,),
        ).fetchall()

    # ------------------------------------------------------------------ #
    #  Logging helpers
    # ------------------------------------------------------------------ #

    def log_audit(self, actor: str, action: str,
                  target: str | None = None, detail: str | None = None) -> None:
        """Record an administrative/audit event."""
        self.conn.execute(
            "INSERT INTO audit_log (actor, action, target, detail) VALUES (?, ?, ?, ?)",
            (actor, action, target, detail),
        )
        self.conn.commit()

    def log_operation(self, username: str, action: str,
                      ip: str | None = None, detail: str | None = None) -> None:
        """Record a user operation event (e.g. ip_change, knock)."""
        self.conn.execute(
            "INSERT INTO operation_log (username, action, ip, detail) VALUES (?, ?, ?, ?)",
            (username, action, ip, detail),
        )
        self.conn.commit()

    def record_failed_attempt(self, username: str | None, ip: str | None,
                              reason: str) -> None:
        """Record a failed authentication attempt."""
        self.conn.execute(
            "INSERT INTO failed_attempts (username, ip, reason) VALUES (?, ?, ?)",
            (username, ip, reason),
        )
        self.conn.commit()

    # ------------------------------------------------------------------ #
    #  State queries
    # ------------------------------------------------------------------ #

    def get_user_ip(self, username: str) -> str | None:
        """Return the currently registered IP for a user, or None."""
        row = self.conn.execute(
            "SELECT current_ip FROM users WHERE username=?", (username,),
        ).fetchone()
        return row["current_ip"] if row else None

    def set_user_ip(self, user_id: int, ip: str | None) -> None:
        """Update the current IP for a user."""
        self.conn.execute(
            "UPDATE users SET current_ip=? WHERE id=?", (ip, user_id),
        )
        self.conn.commit()

    def get_user_last_knock(self, username: str) -> int | None:
        """Return the last knock timestamp for a user, or None."""
        row = self.conn.execute(
            "SELECT last_knock FROM users WHERE username=?", (username,),
        ).fetchone()
        return row["last_knock"] if row else None

    def update_knock_time(self, user_id: int, ip: str) -> None:
        """Refresh the last-knock timestamp (and confirm IP) for a user."""
        now = int(time.time())
        self.conn.execute(
            "UPDATE users SET last_knock=?, current_ip=? WHERE id=?",
            (now, ip, user_id),
        )
        self.conn.commit()

    def count_recent_ip_changes(self, username: str, window_seconds: int) -> int:
        """Count ip_change operation_log rows for a user within the time window."""
        row = self.conn.execute(
            "SELECT COUNT(*) AS c FROM operation_log "
            "WHERE username=? AND action='ip_change' "
            "AND created_at >= datetime('now', ?)",
            (username, f"-{window_seconds} seconds"),
        ).fetchone()
        return row["c"]

    def get_recent_ip_change_ips(self, username: str, window_seconds: int) -> list[str]:
        """Return the IPs recorded in recent ip_change events for a user."""
        rows = self.conn.execute(
            "SELECT ip FROM operation_log "
            "WHERE username=? AND action='ip_change' "
            "AND created_at >= datetime('now', ?)",
            (username, f"-{window_seconds} seconds"),
        ).fetchall()
        return [r["ip"] for r in rows if r["ip"]]

    def clear_user_state(self, user_id: int) -> None:
        """Clear runtime state (current_ip, last_knock) for a user without deleting them."""
        self.conn.execute(
            "UPDATE users SET current_ip=NULL, last_knock=NULL WHERE id=?",
            (user_id,),
        )
        self.conn.commit()

    # ------------------------------------------------------------------ #
    #  Migration
    # ------------------------------------------------------------------ #

    def migrate_from_json(self, state_json_path: str, config_users: dict,
                          protected_ports: list[int], proto: str) -> None:
        """One-time migration from the legacy JSON state file into the DB.

        Seeds users from *config_users* (skipping any that already exist),
        copies current_ip/last_knock from *state_json_path* when present,
        and creates a ``default-<port>`` group per protected port with every
        seeded user enrolled.
        """
        for username, info in config_users.items():
            if not self.get_user_by_username(username):
                self.create_user(username, info.get("secret", ""))

        state_path = Path(state_json_path)
        if state_path.exists():
            try:
                with open(state_path, encoding="utf-8") as f:
                    state = json.load(f)
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("state.json corrupt, skipping migration: %s", exc)
                state = {}
            for username, data in state.items():
                user = self.get_user_by_username(username)
                if not user:
                    continue
                ip = data.get("ip")
                last_knock = data.get("last_knock")
                if ip:
                    self.set_user_ip(user["id"], ip)
                if last_knock:
                    self.conn.execute(
                        "UPDATE users SET last_knock=? WHERE id=?",
                        (last_knock, user["id"]),
                    )
            self.conn.commit()

        for port in protected_ports:
            group_name = f"default-{port}"
            if not self.get_group_by_name(group_name):
                self.create_group(group_name, port, proto)
            group = self.get_group_by_name(group_name)
            for username in config_users:
                user = self.get_user_by_username(username)
                if user and group:
                    self.add_membership(user["id"], group["id"], enabled=1)
