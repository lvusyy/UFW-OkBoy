"""SQLite database layer for UFW OkBoy.

Wraps a single sqlite3.Connection with WAL journaling and foreign-key
enforcement. Provides the 6-table schema (users, groups,
user_group_membership, audit_log, operation_log, failed_attempts) plus
CRUD, logging helpers, state queries, and one-time JSON state migration.
"""

import hashlib
import json
import logging
import sqlite3
import threading
import time
from pathlib import Path

logger = logging.getLogger("ufw-okboy.db")


SCHEMA: dict[str, str] = {
    "schema_version": """
        CREATE TABLE schema_version (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """,
    "users": """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            secret TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            current_ip TEXT,
            last_knock INTEGER,
            totp_secret TEXT,
            totp_enabled INTEGER NOT NULL DEFAULT 0,
            totp_last_counter INTEGER NOT NULL DEFAULT 0,
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


# ── Schema migration registry ─────────────────────────────────────── #
# Each entry: (version, description). The Database.run_migrations() method
# applies pending migrations in order, recording each in schema_version.
# Version 1 = the baseline 6-table schema (users/groups/membership/logs/...).
# The legacy JSON→SQLite import is migration v0→v1 (first-run only).
MIGRATIONS: list[tuple[int, str]] = [
    (1, "baseline 6-table schema + legacy JSON import"),
    (2, "add TOTP step-up columns (totp_secret, totp_enabled) to users"),
    (3, "add totp_last_counter to users (TOTP replay protection)"),
    (4, "add UNIQUE(port, proto) index on groups when data permits"),
]

CURRENT_SCHEMA_VERSION: int = MIGRATIONS[-1][0]


class Database:
    """SQLite-backed persistence for UFW OkBoy.

    Each thread gets its OWN sqlite3 connection (``threading.local``). A single
    shared connection is not safe under concurrent gunicorn worker threads —
    interleaved implicit transactions can commit each other's partial writes.
    WAL journaling + ``busy_timeout`` let the per-thread connections serialize
    writes cleanly instead. Callers should keep transactions short.
    """

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        # One connection per thread. The constructing thread's connection is
        # opened eagerly so init()/migrations/CLI/tests run without surprises.
        self._local = threading.local()
        self._connect()

    def _connect(self) -> sqlite3.Connection:
        """Open and configure a SQLite connection for the calling thread."""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        # Wait (up to 5s) for a competing writer instead of erroring out with
        # SQLITE_BUSY: under WAL multiple connections can attempt writes at once.
        conn.execute("PRAGMA busy_timeout = 5000")
        self._local.conn = conn
        return conn

    @property
    def conn(self) -> sqlite3.Connection:
        """The calling thread's SQLite connection (lazily created per thread)."""
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._connect()
        return conn

    # ------------------------------------------------------------------ #
    #  Schema
    # ------------------------------------------------------------------ #

    def init(self) -> None:
        """Create all tables if they do not already exist, then run migrations."""
        for name, ddl in SCHEMA.items():
            if self._table_exists(name):
                continue
            self.conn.execute(ddl)
        self.conn.commit()
        # Run any pending schema migrations (records baseline v1 for
        # pre-existing DBs, runs v0→v1 JSON import for fresh DBs).
        self.run_migrations()
        self._create_indexes()

    def _create_indexes(self) -> None:
        """Create performance indexes (idempotent).

        Cover the hot paths: count_recent_ip_changes scans operation_log by
        (username, action, created_at) on every knock; the IP throttle and
        failed_attempts lookups scan failed_attempts by username/ip. Without
        these the scans become full table scans that degrade as logs grow.
        """
        self.conn.executescript(
            "CREATE INDEX IF NOT EXISTS idx_oplog_user_action_time "
            "ON operation_log(username, action, created_at);"
            "CREATE INDEX IF NOT EXISTS idx_failed_attempts_username "
            "ON failed_attempts(username, created_at);"
            "CREATE INDEX IF NOT EXISTS idx_failed_attempts_ip "
            "ON failed_attempts(ip, created_at);"
        )
        self.conn.commit()

    def _table_exists(self, name: str) -> bool:
        """Return True if a table named *name* already exists."""
        row = self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (name,),
        ).fetchone()
        return row is not None

    def get_schema_version(self) -> int:
        """Return the highest applied schema version, or 0 if none recorded.

        Ensures the schema_version table exists first (a pre-v2.1 DB upgraded
        in place may have the 6 data tables but not this tracking table).
        """
        if not self._table_exists("schema_version"):
            self.conn.execute(SCHEMA["schema_version"])
            self.conn.commit()
        row = self.conn.execute(
            "SELECT MAX(version) AS v FROM schema_version",
        ).fetchone()
        return int(row["v"]) if row and row["v"] is not None else 0

    def _record_migration(self, version: int) -> None:
        """Record that *version* has been applied."""
        self.conn.execute(
            "INSERT OR IGNORE INTO schema_version (version) VALUES (?)",
            (version,),
        )
        self.conn.commit()

    def run_migrations(self) -> list[int]:
        """Apply pending schema migrations in order.

        Migration logic:
        - If the DB is empty (no users) AND no schema_version recorded: this is a
          fresh install. The legacy migrate_from_json (v0→v1) is expected to be
          called separately by open_database() for first-run seeding; here we
          just record baseline v1 so it is not re-run.
        - If the DB has the 6-table schema but no schema_version row (a pre-v2.1
          install upgraded in place): record baseline v1 WITHOUT re-running the
          JSON import, avoiding duplicate user/group seeding.
        - Apply each pending migration > current version.

        Returns the list of versions applied (empty if already current).
        """
        current = self.get_schema_version()
        applied: list[int] = []
        for version, _desc in MIGRATIONS:
            if version <= current:
                continue
            # v1 baseline: the 6 tables already exist (created by init() or
            # pre-existing). Just record it; do NOT re-seed from JSON here —
            # migrate_from_json is invoked by open_database() only on truly
            # empty DBs. This guard prevents duplicate seeding of existing DBs.
            if version == 1:
                self._record_migration(version)
                applied.append(version)
                continue
            if version == 2:
                self._migration_002_totp()
            elif version == 3:
                self._migration_003_totp_counter()
            elif version == 4:
                self._migration_004_groups_port_proto_unique()
            self._record_migration(version)
            applied.append(version)
        if applied:
            logger.info("DB migrations applied: %s (now at v%d)", applied, self.get_schema_version())
        return applied

    def _migration_002_totp(self) -> None:
        """v2: add the TOTP step-up columns to users (idempotent ALTER).

        Fresh installs already have the columns from SCHEMA; this brings a
        pre-v2.1 users table up to date without a destructive rebuild.
        """
        cols = {r["name"] for r in self.conn.execute("PRAGMA table_info(users)")}
        if "totp_secret" not in cols:
            self.conn.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT")
        if "totp_enabled" not in cols:
            self.conn.execute("ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0")
        self.conn.commit()

    def _migration_003_totp_counter(self) -> None:
        """v3: add totp_last_counter to users (idempotent ALTER).

        Tracks the last TOTP counter consumed by a step-up so a code cannot be
        replayed within its validity window (RFC 6238 §5.2). Fresh installs have
        it from SCHEMA; this brings an older users table up to date.
        """
        cols = {r["name"] for r in self.conn.execute("PRAGMA table_info(users)")}
        if "totp_last_counter" not in cols:
            self.conn.execute(
                "ALTER TABLE users ADD COLUMN totp_last_counter INTEGER NOT NULL DEFAULT 0"
            )
        self.conn.commit()

    def _migration_004_groups_port_proto_unique(self) -> None:
        """v4: add a UNIQUE(port, proto) index on groups — defensively.

        Closes the TOCTOU window where two concurrent admin creates both pass the
        app-level duplicate-port check and both insert. Applied only when SAFE: a
        legacy groups table without port/proto columns, or one that already holds
        duplicate (port, proto) rows (historical same-port groups), is left
        UNTOUCHED — the migration must never crash or drop data. Such installs
        keep relying on the app-level 409 check; once duplicates are removed a
        later run adds the index.
        """
        cols = {r["name"] for r in self.conn.execute("PRAGMA table_info(groups)")}
        if not {"port", "proto"} <= cols:
            logger.info("groups table predates port/proto; skipping unique index")
            return
        dups = self.conn.execute(
            "SELECT port, proto, COUNT(*) AS c FROM groups "
            "GROUP BY port, proto HAVING c > 1"
        ).fetchall()
        if dups:
            logger.warning(
                "groups: %d duplicate (port,proto) present; skipping UNIQUE index "
                "(app-level 409 check still blocks new duplicates)", len(dups),
            )
            return
        self.conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_port_proto "
            "ON groups(port, proto)"
        )
        self.conn.commit()

    def close(self) -> None:
        """Close the calling thread's connection (if one was opened)."""
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

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

    def rotate_secret(self, user_id: int, new_secret: str) -> None:
        """Replace a user's HMAC secret.

        Because authentication is stateless HMAC, changing the secret makes
        every previously-issued signature invalid immediately. This is how an
        admin "forces re-login": the old credential dies and the client must
        re-authenticate with the new secret (delivered out-of-band).
        """
        self.conn.execute(
            "UPDATE users SET secret=? WHERE id=?", (new_secret, user_id),
        )
        self.conn.commit()

    def set_totp_secret(self, user_id: int, secret: str) -> None:
        """Store a pending TOTP secret (enrollment); stays disabled until activated.

        Resets totp_last_counter so the fresh secret starts with a clean replay
        window.
        """
        self.conn.execute(
            "UPDATE users SET totp_secret=?, totp_enabled=0, totp_last_counter=0 WHERE id=?",
            (secret, user_id),
        )
        self.conn.commit()

    def enable_totp(self, user_id: int) -> None:
        """Activate TOTP for a user (after the enrollment code is verified)."""
        self.conn.execute(
            "UPDATE users SET totp_enabled=1 WHERE id=?", (user_id,),
        )
        self.conn.commit()

    def disable_totp(self, user_id: int) -> None:
        """Remove TOTP enrollment for a user (clears the secret and the flag)."""
        self.conn.execute(
            "UPDATE users SET totp_secret=NULL, totp_enabled=0 WHERE id=?", (user_id,),
        )
        self.conn.commit()

    def get_totp_last_counter(self, user_id: int) -> int:
        """Return the last TOTP counter consumed by this user (0 if never)."""
        row = self.conn.execute(
            "SELECT totp_last_counter FROM users WHERE id=?", (user_id,),
        ).fetchone()
        if not row or row["totp_last_counter"] is None:
            return 0
        return int(row["totp_last_counter"])

    def set_totp_last_counter(self, user_id: int, counter: int) -> None:
        """Record the latest TOTP counter consumed (step-up replay protection)."""
        self.conn.execute(
            "UPDATE users SET totp_last_counter=? WHERE id=?", (counter, user_id),
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

    def get_group_by_port_proto(self, port: int, proto: str) -> sqlite3.Row | None:
        """Return the group bound to (*port*, *proto*), or None.

        A port maps to a single access group; this lets the create paths reject
        a duplicate (port, proto) so the firewall model stays unambiguous.
        """
        return self.conn.execute(
            "SELECT * FROM groups WHERE port=? AND proto=?", (port, proto),
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
        """Add a user to a group, or re-enable a previously disabled membership.

        Uses UPSERT (ON CONFLICT) so that re-joining a group the user was
        previously disabled from resets ``enabled=1`` instead of being
        silently ignored by INSERT OR IGNORE (fixes ORPHAN-C).
        """
        self.conn.execute(
            "INSERT INTO user_group_membership (user_id, group_id, enabled) "
            "VALUES (?, ?, ?) "
            "ON CONFLICT(user_id, group_id) DO UPDATE SET enabled=excluded.enabled",
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

    def membership_exists(self, user_id: int, group_id: int) -> bool:
        """Return True if a membership row exists (enabled or disabled)."""
        row = self.conn.execute(
            "SELECT 1 FROM user_group_membership WHERE user_id=? AND group_id=?",
            (user_id, group_id),
        ).fetchone()
        return row is not None

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

    def get_user_enabled_groups_ports(self, user_id: int) -> dict:
        """Return ``{group_name: (port, proto)}`` for the user's enabled memberships.

        Used by the knock reconcile path to align UFW rules with the user's
        currently authorized (enabled) groups (per-group proto preserved).
        """
        rows = self.conn.execute(
            "SELECT g.name AS name, g.port AS port, g.proto AS proto FROM groups g "
            "JOIN user_group_membership m ON m.group_id = g.id "
            "WHERE m.user_id=? AND m.enabled=1",
            (user_id,),
        ).fetchall()
        return {row["name"]: (row["port"], row["proto"]) for row in rows}

    def get_all_user_group_ports(self, only_enabled: bool = True) -> dict:
        """Return ``{username: [(group_name, port, proto), ...]}`` for all users.

        Used by cleanup/sync to drive UFW reconciliation from each user's
        actual (enabled) group ports (with per-group proto) instead of the
        legacy protected_ports.
        """
        sql = (
            "SELECT u.username AS username, g.name AS group_name, "
            "g.port AS port, g.proto AS proto "
            "FROM users u "
            "JOIN user_group_membership m ON m.user_id = u.id "
            "JOIN groups g ON g.id = m.group_id"
        )
        if only_enabled:
            sql += " WHERE m.enabled=1"
        sql += " ORDER BY u.username, g.name"
        result: dict[str, list[tuple[str, int, str]]] = {}
        for row in self.conn.execute(sql).fetchall():
            result.setdefault(row["username"], []).append(
                (row["group_name"], row["port"], row["proto"])
            )
        return result

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

    def list_audit(self, limit: int = 100) -> list[sqlite3.Row]:
        """Return the most recent *limit* audit-log rows, newest first."""
        return self.conn.execute(
            "SELECT id, actor, action, target, detail, created_at "
            "FROM audit_log ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()

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

    def count_recent_failed_attempts(self, ip: str | None,
                                     window_seconds: int) -> int:
        """Count failed auth attempts from *ip* within the recent time window.

        Drives the per-IP abuse throttle (``auth.check_ip_throttle``). Uses the
        ``idx_failed_attempts_ip(ip, created_at)`` index. Returns 0 when *ip* is
        None/empty (an unidentifiable peer cannot be throttled).
        """
        if not ip:
            return 0
        row = self.conn.execute(
            "SELECT COUNT(*) AS c FROM failed_attempts "
            "WHERE ip=? AND created_at >= datetime('now', ?)",
            (ip, f"-{window_seconds} seconds"),
        ).fetchone()
        return row["c"]

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

    def record_ip_change(self, user_id: int, username: str, ip: str) -> str | None:
        """Atomically claim *ip* for the user and return the prior current_ip.

        Reads the user's current_ip and writes the new one in ONE transaction,
        together with the current_ip/last_knock update and — only when the IP
        actually changed — the ip_change operation-log row, so the stored IP, the
        audit/anomaly trail, and the returned prior value can never disagree
        (closes ORPHAN-D's torn-write window). The prior IP is read inside the
        same transaction, so the knock path logs the true superseded IP and
        decides heartbeat-vs-change from it rather than a separate stale read.
        UFW cleanup of the prior IP's rules is handled comprehensively by
        reconcile_user_rules on every knock.

        Returns the prior current_ip (None on a first knock; equal to *ip* on a
        heartbeat with no change).
        """
        now = int(time.time())
        with self.conn:
            row = self.conn.execute(
                "SELECT current_ip FROM users WHERE id=?", (user_id,),
            ).fetchone()
            prior = row["current_ip"] if row else None
            self.conn.execute(
                "UPDATE users SET current_ip=?, last_knock=? WHERE id=?",
                (ip, now, user_id),
            )
            if prior != ip:
                self.conn.execute(
                    "INSERT INTO operation_log (username, action, ip, detail) "
                    "VALUES (?, 'ip_change', ?, ?)",
                    (username, ip, f"old={prior}"),
                )
        return prior

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

    # ------------------------------------------------------------------ #
    #  Backup
    # ------------------------------------------------------------------ #

    def backup(self, dest_path: str) -> str:
        """Write a consistent snapshot of the DB to *dest_path*; return it.

        Uses SQLite's online backup API rather than a file copy: under WAL
        journaling a plain ``cp`` can capture a torn state (committed pages
        still in the -wal not yet checkpointed into the main file). The backup
        target is a self-contained, checkpointed database.
        """
        Path(dest_path).parent.mkdir(parents=True, exist_ok=True)
        dest = sqlite3.connect(dest_path)
        try:
            with dest:
                self.conn.backup(dest)
        finally:
            dest.close()
        return dest_path

    @staticmethod
    def checksum(path: str) -> str:
        """Return the SHA-256 hex digest of the file at *path* (for integrity)."""
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
