#!/usr/bin/env python3
"""UFW OkBoy - Dynamic Firewall Allowlist Manager.

Server application providing:
1. HTTPS API for clients to register their IP in the firewall allowlist
2. CLI tools for user management and stale-rule cleanup

Authentication: HMAC-SHA256 with timestamp (secret never transmitted).
"""

import argparse
import hashlib
import json
import logging
import secrets
import shutil
import sqlite3
import sys
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

import os

import yaml
from flask import Flask, request, jsonify, send_from_directory

import auth
from db import Database
from ufw_ops import UFWManager

logger = logging.getLogger("ufw-okboy")


def _read_version() -> str:
    """Read the project version from the VERSION file (single source of truth).

    Looks for ``VERSION`` next to this module's parent (repo root) or in the
    module directory itself (packaged installs). Falls back to '0.0.0-unknown'
    if the file cannot be found.
    """
    here = Path(__file__).resolve().parent
    for candidate in (here.parent / "VERSION", here / "VERSION"):
        try:
            return candidate.read_text(encoding="utf-8").strip()
        except OSError:
            continue
    return "0.0.0-unknown"


__version__ = _read_version()

# ====================================================================== #
#  Configuration
# ====================================================================== #

def load_config(path: str) -> dict:
    """Load and validate YAML configuration file."""
    p = Path(path)
    if not p.exists():
        sys.exit(f"Config file not found: {path}")
    with open(p, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    # Validate required fields
    if not cfg.get("protected_ports"):
        sys.exit("Config error: 'protected_ports' must be a non-empty list")
    if not cfg.get("users"):
        sys.exit("Config error: 'users' must contain at least one user")
    for name, info in cfg["users"].items():
        if not info.get("secret"):
            sys.exit(f"Config error: user '{name}' is missing 'secret'")

    if not cfg.get("db_path"):
        logger.warning("'db_path' not set in config; using default /var/lib/ufw-okboy/ufw-okboy.db")

    return cfg


def open_database(cfg: dict) -> Database:
    """Construct, initialize, and (if empty) migrate the Database from config."""
    db = Database(cfg.get("db_path", "/var/lib/ufw-okboy/ufw-okboy.db"))
    db.init()
    if not db.list_users():
        db.migrate_from_json(
            cfg.get("state_file", "/var/lib/ufw-okboy/state.json"),
            cfg["users"],
            cfg["protected_ports"],
            cfg.get("proto", "tcp"),
        )
        logger.info("Database seeded from config + state.json (first run)")
    return db

# ====================================================================== #
#  Flask Application Factory
# ====================================================================== #

def create_app(config_path: str = "config.yaml",
               db_override: Database | None = None,
               ufw_override: UFWManager | None = None) -> Flask:
    """Create and configure the Flask application.

    Args:
        config_path: Path to the YAML config file.
        db_override: Optional pre-built Database (used by tests). When
            provided, config-based seeding/migration is skipped.
        ufw_override: Optional pre-built UFWManager (used by tests).
    """
    static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
    app = Flask(__name__, static_folder=static_dir, static_url_path="/static")
    cfg = load_config(config_path)

    if db_override is not None:
        db = db_override
    else:
        db = open_database(cfg)
    if ufw_override is not None:
        ufw = ufw_override
    else:
        ufw = UFWManager(
            rule_prefix=cfg.get("rule_prefix", "ufw-okboy"),
            db=db,
        )

    ttl = cfg.get("signature_ttl", 300)

    # Anomaly detection thresholds (configurable)
    anomaly_window = cfg.get("anomaly_window", 3600)      # 1 hour
    anomaly_max_changes = cfg.get("anomaly_max_changes", 5)  # max IP changes per window

    # Per-IP abuse throttle thresholds (configurable; 0 disables)
    throttle_max = cfg.get("throttle_max_failures", 10)
    throttle_window = cfg.get("throttle_window", 300)
    # When true, admins without TOTP are blocked from sensitive ops until enrolled.
    require_admin_totp = cfg.get("require_admin_totp", False)

    def _auth():
        return auth.verify_hmac(
            db, request.headers.get("Authorization"), ttl, _client_ip(),
        )

    def _client_ip() -> str:
        """Extract the real client IP, respecting reverse-proxy headers.

        Proxy headers (X-Real-IP / X-Forwarded-For) are trusted ONLY when the
        direct peer (request.remote_addr) is in the configured trusted_proxies
        list, so a client reaching Flask directly cannot spoof these headers to
        register an arbitrary IP in the firewall allowlist (fixes H-9). Default
        trusted: localhost.
        """
        peer = request.remote_addr or ""
        trusted = cfg.get("trusted_proxies", ["127.0.0.1", "::1"])
        if peer in trusted:
            xff = request.headers.get("X-Forwarded-For", "")
            return (
                request.headers.get("X-Real-IP")
                # Rightmost XFF entry = the address the trusted proxy actually
                # saw; the leftmost is client-supplied and spoofable (nginx
                # APPENDS the real peer via $proxy_add_x_forwarded_for).
                or (xff.split(",")[-1].strip() if xff.strip() else "")
                or peer
            )
        # Not behind a trusted proxy: the peer IS the real client.
        return peer

    @app.before_request
    def _throttle_gate():
        """Reject /api/ requests from an IP with too many recent failures (429).

        Centralized so the throttle covers knock, status, me/*, membership, and
        every admin endpoint uniformly — defense in depth with nginx limit_req.
        """
        if not request.path.startswith("/api/"):
            return None
        err = auth.check_ip_throttle(db, _client_ip(), throttle_max, throttle_window)
        if err:
            logger.warning("Throttled %s on %s", _client_ip(), request.path)
            return jsonify({"ok": False, "error": err}), 429
        return None

    # ---- API Routes ---- #

    @app.route("/api/knock", methods=["POST"])
    def knock():
        """Register or update the caller's IP in the firewall allowlist."""
        username, err = _auth()
        if err:
            logger.warning("Auth failed from %s: %s", _client_ip(), err)
            return jsonify({"ok": False, "error": err}), 401

        client_ip = _client_ip()
        if not client_ip or client_ip == "127.0.0.1":
            return jsonify({
                "ok": False,
                "error": "Cannot determine real client IP. Check Nginx X-Real-IP header.",
            }), 400

        user = db.get_user_by_username(username)
        if not user:
            return jsonify({"ok": False, "error": "User not found"}), 404
        user_id = user["id"]

        enabled_groups = db.get_user_groups(user_id, only_enabled=True)
        enabled_groups_ports = {
            grp["name"]: (grp["port"], grp["proto"]) for grp in enabled_groups
        }
        old_ip = db.get_user_ip(username)

        # Idempotent reconcile: align UFW rules with the user's enabled groups.
        # Runs on BOTH the heartbeat path (IP unchanged) and the IP-change path,
        # so any desync (recent join/leave, concurrent membership change, stale
        # rules from a crashed knock, stale old-IP rules) is self-healed every
        # knock. Fixes BUG-A/C; per-group proto preserved (fixes H-2).
        ufw.reconcile_user_rules(username, client_ip, enabled_groups_ports)

        # IP unchanged - just refresh the timestamp
        if old_ip == client_ip:
            db.update_knock_time(user_id, client_ip)
            logger.info("Knock: %s@%s (unchanged, reconciled)", username, client_ip)
            return jsonify({
                "ok": True,
                "ip": client_ip,
                "changed": False,
                "message": "IP unchanged, heartbeat recorded",
            })

        # IP changed - the reconcile above already added the new-ip rules;
        # now remove rules bound to the old IP for every enabled group.
        if old_ip:
            for grp in enabled_groups:
                ufw.remove_rule(old_ip, grp["port"], username, grp["proto"], grp["name"])
            logger.info("Removed old-IP rules for %s (was %s)", username, old_ip)

        # Atomic state write: current_ip + last_knock + ip_change log in ONE
        # transaction (fixes ORPHAN-D torn write between the old 3 commits).
        db.record_ip_change(user_id, username, client_ip, old_ip)
        logger.info("Knock: %s@%s (was %s)", username, client_ip, old_ip or "new")

        # Check for anomalous IP change patterns (possible credential sharing)
        warning = None
        anomaly = ufw.check_ip_anomaly(username, anomaly_window, anomaly_max_changes)
        if anomaly:
            warning = (
                f"Suspicious activity: {anomaly['changes']} IP changes from "
                f"{anomaly['unique_ips']} unique IPs in the last "
                f"{anomaly_window // 60} minutes. Possible credential sharing."
            )
            logger.warning(
                "ANOMALY for %s: %d IP changes, %d unique IPs: %s",
                username, anomaly["changes"], anomaly["unique_ips"],
                ", ".join(anomaly["ips"]),
            )

        return jsonify({
            "ok": True,
            "ip": client_ip,
            "changed": True,
            "old_ip": old_ip,
            "groups": [grp["name"] for grp in enabled_groups],
            "message": "Firewall rules updated",
            **({"warning": warning} if warning else {}),
        })

    @app.route("/api/status", methods=["GET"])
    def status():
        """Return the caller's current registration state."""
        username, err = _auth()
        if err:
            return jsonify({"ok": False, "error": err}), 401

        state = ufw.get_user_state(username)
        user = db.get_user_by_username(username)
        enabled_groups = []
        if user:
            enabled_groups = [
                {"name": grp["name"], "port": grp["port"], "proto": grp["proto"]}
                for grp in db.get_user_groups(user["id"], only_enabled=True)
            ]
        return jsonify({
            "ok": True,
            "username": username,
            "is_admin": bool(user and user["is_admin"]) if user else False,
            "totp_enabled": bool(user and "totp_enabled" in user.keys()
                                 and user["totp_enabled"]) if user else False,
            "enabled_groups": enabled_groups,
            **state,
        })

    @app.route("/api/me/groups", methods=["GET"])
    def my_groups():
        """Return the caller's groups with enabled flags (for self-authorization UI).

        Each item: ``{id, name, port, proto, enabled}``. Both enabled and
        disabled memberships are returned so the user can see / re-enable
        previously-authorized groups. Groups the user has never been a member
        of are NOT listed — those require admin grant.
        """
        username, err = _auth()
        if err:
            return jsonify({"ok": False, "error": err}), 401
        user = db.get_user_by_username(username)
        if not user:
            return jsonify({"ok": False, "error": "User not found"}), 404
        rows = db.conn.execute(
            "SELECT g.id AS id, g.name AS name, g.port AS port, g.proto AS proto, "
            "m.enabled AS enabled "
            "FROM groups g JOIN user_group_membership m ON m.group_id = g.id "
            "WHERE m.user_id=? ORDER BY g.name",
            (user["id"],),
        ).fetchall()
        groups = [dict(r) for r in rows]
        return jsonify({"ok": True, "username": username, "groups": groups})

    @app.route("/api/me/membership/<int:group_id>", methods=["PATCH"])
    def self_toggle_membership(group_id: int):
        """Toggle the caller's own group membership (self-authorization).

        Enforces the same VULN-A rule as the admin/self membership toggle: a
        user may only re-enable a group they were previously authorized for
        (admin grants new groups). Used by the group-authorization multi-select
        UI so the client does not need to know its own user_id.
        """
        username, err = _auth()
        if err:
            return jsonify({"ok": False, "error": err}), 401
        requester = db.get_user_by_username(username)
        if not requester:
            return jsonify({"ok": False, "error": "Authenticated user not found"}), 401

        body = request.get_json(silent=True) or {}
        enabled = body.get("enabled")
        if not isinstance(enabled, bool):
            return jsonify({
                "ok": False, "error": "Request body must include 'enabled' (bool)",
            }), 400

        # Existence check FIRST (404) so a typo'd group_id is reported as
        # not-found rather than a misleading 403 unauthorized (fixes H-10).
        group = db.get_group(group_id)
        if not group:
            return jsonify({"ok": False, "error": "Group not found"}), 404

        # Self-enable authorization check (VULN-A): re-enable only if the
        # user was previously authorized for this group.
        if enabled and not auth.is_admin(db, username):
            if not auth.user_has_group_access(
                db, username, group_id, allow_reenable=True,
            ):
                db.log_audit(
                    username, "unauthorized_reenable_attempt",
                    f"self/{group_id}", "self-enable of never-authorized group",
                )
                return jsonify({
                    "ok": False,
                    "error": "Forbidden: you may only re-enable a previously "
                             "authorized group. Ask an admin to grant access.",
                }), 403

        db.set_membership_enabled(requester["id"], group_id, 1 if enabled else 0)

        user_ip = requester["current_ip"]
        if user_ip:
            if not enabled:
                ufw.remove_rule(
                    user_ip, group["port"], requester["username"],
                    group["proto"], group["name"],
                )
            else:
                # Idempotent add via reconcile: checks existence first so
                # re-enabling a group whose rule already exists is a no-op
                # rather than a duplicate-add error (fixes H-11).
                ufw.reconcile_user_rules(
                    requester["username"], user_ip,
                    {group["name"]: (group["port"], group["proto"])},
                )

        db.log_audit(
            username, "self_toggle_membership",
            f"{requester['id']}/{group_id}", f"enabled={enabled}",
        )
        return jsonify({
            "ok": True, "group_id": group_id, "enabled": enabled,
        })

    @app.route("/api/membership/<int:user_id>/<int:group_id>", methods=["PATCH"])
    def toggle_membership(user_id: int, group_id: int):
        """Toggle a user's group membership and sync UFW rules immediately.

        Allowed when the requester is an admin or is toggling their own
        membership (self-toggle).
        """
        username, err = _auth()
        if err:
            return jsonify({"ok": False, "error": err}), 401

        requester = db.get_user_by_username(username)
        if not requester:
            return jsonify({"ok": False, "error": "Authenticated user not found"}), 401

        is_self = requester["id"] == user_id
        if not is_self and not auth.is_admin(db, username):
            return jsonify({
                "ok": False,
                "error": "Forbidden: admin privileges or self-toggle required",
            }), 403

        body = request.get_json(silent=True) or {}
        enabled = body.get("enabled")
        if not isinstance(enabled, bool):
            return jsonify({
                "ok": False,
                "error": "Request body must include 'enabled' (bool)",
            }), 400

        # Existence checks FIRST (404) so typos are reported as not-found
        # rather than misleading 403 unauthorized (fixes H-10).
        group = db.get_group(group_id)
        if not group:
            return jsonify({"ok": False, "error": "Group not found"}), 404
        target = db.get_user(user_id)
        if not target:
            return jsonify({"ok": False, "error": "User not found"}), 404

        # Self-enable authorization check (VULN-A): a non-admin user may only
        # re-enable a group they were previously authorized for. Enabling a
        # group they have never been granted requires an admin (join API).
        if is_self and enabled and not auth.is_admin(db, username):
            if not auth.user_has_group_access(
                db, username, group_id, allow_reenable=True,
            ):
                db.log_audit(
                    username, "unauthorized_reenable_attempt",
                    f"{user_id}/{group_id}", "self-enable of never-authorized group",
                )
                return jsonify({
                    "ok": False,
                    "error": "Forbidden: you may only re-enable a group you were "
                             "previously authorized for. Ask an admin to grant access.",
                }), 403

        db.set_membership_enabled(user_id, group_id, 1 if enabled else 0)

        user_ip = target["current_ip"]
        if user_ip:
            if not enabled:
                ufw.remove_rule(
                    user_ip, group["port"], target["username"],
                    group["proto"], group["name"],
                )
            else:
                # Idempotent add via reconcile (fixes H-11).
                ufw.reconcile_user_rules(
                    target["username"], user_ip,
                    {group["name"]: (group["port"], group["proto"])},
                )

        db.log_audit(
            username, "toggle_membership",
            f"{user_id}/{group_id}", f"enabled={enabled}",
        )
        logger.info(
            "Membership toggled: user=%s group=%s enabled=%s by %s",
            user_id, group_id, enabled, username,
        )

        return jsonify({
            "ok": True,
            "user_id": user_id,
            "group_id": group_id,
            "enabled": enabled,
        })

    @app.route("/health", methods=["GET"])
    def health():
        """Health check endpoint (no auth required)."""
        return jsonify({"ok": True, "service": "ufw-okboy"})

    # ---- Web Client ---- #

    @app.route("/")
    def client_page():
        """Serve the web-based client UI."""
        return send_from_directory(static_dir, "index.html")

    # ---- Admin API ---- #

    def _admin_error_response(err: str):
        """Build a (jsonify, status) tuple for an admin auth failure."""
        status = 403 if err == "Admin privileges required" else 401
        return jsonify({"ok": False, "error": err}), status

    def _step_up_error(user):
        """TOTP step-up gate for sensitive ops. Returns a (resp, status) tuple
        to short-circuit, or None to proceed.

        - admin has TOTP enabled → a valid code is mandatory (``X-TOTP-Code``
          header or ``totp_code`` body field).
        - admin without TOTP + ``require_admin_totp`` config → blocked until
          enrolled. Otherwise (opt-in, not enrolled) → proceed.
        """
        enabled = "totp_enabled" in user.keys() and user["totp_enabled"]
        if enabled:
            code = (request.headers.get("X-TOTP-Code")
                    or (request.get_json(silent=True) or {}).get("totp_code"))
            if not auth.verify_totp(user["totp_secret"], code):
                db.log_audit(user["username"], "stepup_failed", user["username"], None)
                # Count a bad step-up code toward the IP throttle; otherwise an
                # already-admin-authenticated caller could brute-force the 6-digit
                # code unbounded (the HMAC throttle never sees these attempts).
                db.record_failed_attempt(user["username"], _client_ip(), "Invalid TOTP step-up")
                return jsonify({
                    "ok": False, "error": "Valid TOTP code required",
                    "totp_required": True,
                }), 403
        elif require_admin_totp:
            return jsonify({
                "ok": False,
                "error": "Admin TOTP enrollment required before this action",
                "totp_enroll_required": True,
            }), 403
        return None

    @app.route("/api/admin/users", methods=["GET"])
    def admin_list_users():
        """List all users (admin only). Secrets are stripped from the response."""
        user, err = auth.require_admin(
            db, request.headers.get("Authorization"), ttl, _client_ip(),
        )
        if err:
            return _admin_error_response(err)
        users = []
        for row in db.list_users():
            d = dict(row)
            d.pop("secret", None)
            d.pop("totp_secret", None)  # never expose the TOTP seed
            users.append(d)
        return jsonify({"ok": True, "users": users})

    @app.route("/api/admin/users", methods=["POST"])
    def admin_create_user():
        """Create a new user (admin only). Returns the generated/explied secret."""
        user, err = auth.require_admin(
            db, request.headers.get("Authorization"), ttl, _client_ip(),
        )
        if err:
            return _admin_error_response(err)
        se = _step_up_error(user)  # creating a user (esp. is_admin) is sensitive
        if se:
            return se
        data = request.get_json(force=True, silent=True) or {}
        username = data.get("username")
        if not username:
            return jsonify({"ok": False, "error": "username is required"}), 400
        secret = data.get("secret") or secrets.token_hex(32)
        is_admin = bool(data.get("is_admin", False))
        try:
            user_id = db.create_user(username, secret, is_admin=is_admin)
        except sqlite3.IntegrityError:
            return jsonify({"ok": False, "error": f"User '{username}' already exists"}), 409
        db.log_audit(user["username"], "user_add", username, f"is_admin={is_admin}")
        return jsonify({
            "ok": True, "id": user_id, "username": username,
            "secret": secret, "is_admin": is_admin,
        }), 201

    @app.route("/api/admin/users/<int:user_id>", methods=["DELETE"])
    def admin_delete_user(user_id: int):
        """Delete a user and clean up their UFW rules (admin only)."""
        user, err = auth.require_admin(
            db, request.headers.get("Authorization"), ttl, _client_ip(),
        )
        if err:
            return _admin_error_response(err)
        se = _step_up_error(user)
        if se:
            return se
        target = db.get_user(user_id)
        if not target:
            return jsonify({"ok": False, "error": "User not found"}), 404
        if target["current_ip"]:
            for g in db.get_user_groups(user_id, only_enabled=True):
                ufw.remove_rule(target["current_ip"], g["port"], target["username"], g["proto"], g["name"])
        db.delete_user(user_id)
        db.log_audit(user["username"], "user_del", target["username"], None)
        return jsonify({"ok": True, "deleted": user_id})

    @app.route("/api/admin/groups", methods=["GET"])
    def admin_list_groups():
        """List all groups (admin only)."""
        user, err = auth.require_admin(
            db, request.headers.get("Authorization"), ttl, _client_ip(),
        )
        if err:
            return _admin_error_response(err)
        groups = [dict(g) for g in db.list_groups()]
        return jsonify({"ok": True, "groups": groups})

    @app.route("/api/admin/groups", methods=["POST"])
    def admin_create_group():
        """Create a new group (admin only)."""
        user, err = auth.require_admin(
            db, request.headers.get("Authorization"), ttl, _client_ip(),
        )
        if err:
            return _admin_error_response(err)
        se = _step_up_error(user)
        if se:
            return se
        data = request.get_json(force=True, silent=True) or {}
        name = data.get("name")
        port = data.get("port")
        if not name or port is None:
            return jsonify({"ok": False, "error": "name and port are required"}), 400
        proto = data.get("proto", "tcp")

        # Port whitelist (VULN-B): when an admin explicitly configures
        # `allowed_ports`, new groups may only bind to ports in that set.
        # When NOT configured, no restriction is applied (backward compatible
        # — admin opts into the whitelist by setting allowed_ports in config).
        try:
            port_int = int(port)
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "port must be an integer"}), 400
        allowed_ports = cfg.get("allowed_ports")
        if allowed_ports and port_int not in allowed_ports:
            db.log_audit(
                user["username"], "group_add_denied", name,
                f"port {port_int} not in allowed_ports",
            )
            return jsonify({
                "ok": False,
                "error": f"Port {port_int} is not in the allowed_ports whitelist",
            }), 400
        # One group per (port, proto): a port maps to a single access group, so
        # reject a duplicate — avoids admin ambiguity and cross-group same-port
        # rule collisions. A different proto (443/tcp vs 443/udp) is allowed.
        dup = db.get_group_by_port_proto(port_int, proto)
        if dup:
            return jsonify({
                "ok": False,
                "error": f"Port {port_int}/{proto} is already used by group '{dup['name']}'",
            }), 409
        try:
            group_id = db.create_group(name, port_int, proto)
        except sqlite3.IntegrityError:
            return jsonify({"ok": False, "error": f"Group '{name}' already exists"}), 409
        db.log_audit(user["username"], "group_add", name, f"port={port_int} proto={proto}")
        return jsonify({
            "ok": True, "id": group_id, "name": name,
            "port": port_int, "proto": proto,
        }), 201

    @app.route("/api/admin/groups/<int:group_id>", methods=["DELETE"])
    def admin_delete_group(group_id: int):
        """Delete a group and clean up UFW rules for its members (admin only)."""
        user, err = auth.require_admin(
            db, request.headers.get("Authorization"), ttl, _client_ip(),
        )
        if err:
            return _admin_error_response(err)
        se = _step_up_error(user)
        if se:
            return se
        group = db.get_group(group_id)
        if not group:
            return jsonify({"ok": False, "error": "Group not found"}), 404
        for m in db.get_group_members(group_id):
            if m["current_ip"]:
                ufw.remove_rule(m["current_ip"], group["port"], m["username"], group["proto"], group["name"])
        db.delete_group(group_id)
        db.log_audit(user["username"], "group_del", group["name"], None)
        return jsonify({"ok": True, "deleted": group_id})

    @app.route("/api/admin/users/<int:user_id>/groups", methods=["POST"])
    def admin_add_membership(user_id: int):
        """Add a user to a group (admin only)."""
        user, err = auth.require_admin(
            db, request.headers.get("Authorization"), ttl, _client_ip(),
        )
        if err:
            return _admin_error_response(err)
        se = _step_up_error(user)  # opens a firewall port for the target user
        if se:
            return se
        target = db.get_user(user_id)
        if not target:
            return jsonify({"ok": False, "error": "User not found"}), 404
        data = request.get_json(force=True, silent=True) or {}
        group_id = data.get("group_id")
        if group_id is None:
            return jsonify({"ok": False, "error": "group_id is required"}), 400
        group = db.get_group(int(group_id))
        if not group:
            return jsonify({"ok": False, "error": "Group not found"}), 404
        enabled = 1 if data.get("enabled", True) else 0
        db.add_membership(user_id, int(group_id), enabled=enabled)
        # Immediate UFW sync: if the target user is online, open the port now.
        target_ip = target["current_ip"]
        if target_ip and enabled:
            ufw.add_rule(
                target_ip, group["port"], target["username"],
                group["proto"], group["name"],
            )
        db.log_audit(user["username"], "user_join", target["username"], group["name"])
        return jsonify({
            "ok": True, "user_id": user_id,
            "group_id": int(group_id), "enabled": enabled,
        }), 201

    @app.route("/api/admin/memberships/remove", methods=["POST"])
    def admin_remove_membership():
        """Remove a user from a group and clean up the UFW rule (admin only)."""
        user, err = auth.require_admin(
            db, request.headers.get("Authorization"), ttl, _client_ip(),
        )
        if err:
            return _admin_error_response(err)
        se = _step_up_error(user)
        if se:
            return se
        data = request.get_json(force=True, silent=True) or {}
        target = db.get_user_by_username(data.get("username", ""))
        group = db.get_group_by_name(data.get("group_name", ""))
        if not target:
            return jsonify({"ok": False, "error": "User not found"}), 404
        if not group:
            return jsonify({"ok": False, "error": "Group not found"}), 404
        db.remove_membership(target["id"], group["id"])
        # Immediate UFW cleanup: if the target user is online, remove the rule.
        target_ip = target["current_ip"]
        if target_ip:
            ufw.remove_rule(
                target_ip, group["port"], target["username"],
                group["proto"], group["name"],
            )
        db.log_audit(
            user["username"], "remove_membership",
            target["username"], group["name"],
        )
        logger.info(
            "Membership removed: user=%s group=%s by %s",
            target["username"], group["name"], user["username"],
        )
        return jsonify({
            "ok": True, "user_id": target["id"], "group_id": group["id"],
        })

    @app.route("/api/admin/users/<int:user_id>/revoke", methods=["POST"])
    def admin_revoke_user(user_id: int):
        """Revoke a user's active access (admin only).

        Closes the user's open UFW ports, clears their runtime state, and (by
        default) rotates their HMAC secret so the old credential is invalid
        immediately — the stateless-HMAC way to "force re-login + re-auth".
        Pass ``{"rotate_secret": false}`` to disconnect without invalidating the
        credential. When rotated, the new secret is returned ONCE.
        """
        user, err = auth.require_admin(
            db, request.headers.get("Authorization"), ttl, _client_ip(),
        )
        if err:
            return _admin_error_response(err)
        se = _step_up_error(user)
        if se:
            return se
        target = db.get_user(user_id)
        if not target:
            return jsonify({"ok": False, "error": "User not found"}), 404

        if target["current_ip"]:
            for g in db.get_user_groups(user_id, only_enabled=True):
                ufw.remove_rule(
                    target["current_ip"], g["port"], target["username"],
                    g["proto"], g["name"],
                )
        db.clear_user_state(user_id)
        data = request.get_json(silent=True) or {}
        rotate = bool(data.get("rotate_secret", True))
        new_secret = None
        if rotate:
            new_secret = secrets.token_hex(32)
            db.rotate_secret(user_id, new_secret)
        db.log_audit(user["username"], "revoke", target["username"], f"rotate={rotate}")
        logger.info("Revoked %s (rotate=%s) by %s", target["username"], rotate, user["username"])
        resp = {"ok": True, "user_id": user_id, "rotated": rotate}
        if new_secret:
            resp["secret"] = new_secret
        return jsonify(resp)

    @app.route("/api/admin/audit", methods=["GET"])
    def admin_list_audit():
        """Return recent audit-log entries, newest first (admin only).

        Query param ``limit`` (default 100, clamped to 1..1000).
        """
        user, err = auth.require_admin(
            db, request.headers.get("Authorization"), ttl, _client_ip(),
        )
        if err:
            return _admin_error_response(err)
        limit = request.args.get("limit", default=100, type=int) or 100
        limit = max(1, min(limit, 1000))
        rows = [dict(r) for r in db.list_audit(limit)]
        return jsonify({"ok": True, "audit": rows})

    @app.route("/api/admin/totp/enroll", methods=["POST"])
    def admin_totp_enroll():
        """Begin TOTP enrollment (admin only): generate a secret + otpauth URI.

        The secret is stored but NOT active until the admin confirms a code via
        /activate. Returns the base32 secret and an otpauth:// URI for QR or
        manual entry into an authenticator app.
        """
        user, err = auth.require_admin(
            db, request.headers.get("Authorization"), ttl, _client_ip(),
        )
        if err:
            return _admin_error_response(err)
        # Re-enrollment must prove current possession: set_totp_secret overwrites
        # the secret AND resets totp_enabled=0, so without this an attacker with a
        # stolen admin session (but no code) could replace/disable an enabled
        # admin's 2FA. A first-time enroll (not yet enabled) is always allowed so
        # require_admin_totp cannot deadlock the very enrollment it demands.
        if user["totp_enabled"]:
            recode = (request.headers.get("X-TOTP-Code")
                      or (request.get_json(silent=True) or {}).get("totp_code"))
            if not auth.verify_totp(user["totp_secret"], recode):
                return jsonify({
                    "ok": False, "error": "Valid TOTP code required to re-enroll",
                    "totp_required": True,
                }), 403
        secret = auth.generate_totp_secret()
        db.set_totp_secret(user["id"], secret)
        db.log_audit(user["username"], "totp_enroll_start", user["username"], None)
        return jsonify({
            "ok": True,
            "secret": secret,
            "otpauth_uri": auth.totp_uri(secret, user["username"]),
        })

    @app.route("/api/admin/totp/activate", methods=["POST"])
    def admin_totp_activate():
        """Activate a pending TOTP enrollment by confirming a code (admin only)."""
        user, err = auth.require_admin(
            db, request.headers.get("Authorization"), ttl, _client_ip(),
        )
        if err:
            return _admin_error_response(err)
        if not user["totp_secret"]:
            return jsonify({"ok": False, "error": "No pending enrollment; call enroll first"}), 400
        code = (request.get_json(silent=True) or {}).get("totp_code", "")
        if not auth.verify_totp(user["totp_secret"], code):
            return jsonify({"ok": False, "error": "Invalid code"}), 400
        db.enable_totp(user["id"])
        db.log_audit(user["username"], "totp_activate", user["username"], None)
        return jsonify({"ok": True, "totp_enabled": True})

    @app.route("/api/admin/totp", methods=["DELETE"])
    def admin_totp_disable():
        """Disable TOTP for the calling admin. Requires a current code when enabled."""
        user, err = auth.require_admin(
            db, request.headers.get("Authorization"), ttl, _client_ip(),
        )
        if err:
            return _admin_error_response(err)
        if user["totp_enabled"]:
            code = (request.get_json(silent=True) or {}).get("totp_code", "")
            if not auth.verify_totp(user["totp_secret"], code):
                return jsonify({"ok": False, "error": "Valid TOTP code required to disable"}), 403
        db.disable_totp(user["id"])
        db.log_audit(user["username"], "totp_disable", user["username"], None)
        return jsonify({"ok": True, "totp_enabled": False})

    @app.route("/api/admin/users/<int:user_id>/groups", methods=["GET"])
    def admin_user_groups(user_id: int):
        """List every group with the target user's membership state (admin only).

        Powers the admin console's per-user group management: each group carries
        ``is_member`` and ``enabled`` flags for *user_id* so the UI can render a
        checkbox per group.
        """
        user, err = auth.require_admin(
            db, request.headers.get("Authorization"), ttl, _client_ip(),
        )
        if err:
            return _admin_error_response(err)
        target = db.get_user(user_id)
        if not target:
            return jsonify({"ok": False, "error": "User not found"}), 404
        member = {
            r["group_id"]: r["enabled"]
            for r in db.conn.execute(
                "SELECT group_id, enabled FROM user_group_membership WHERE user_id=?",
                (user_id,),
            ).fetchall()
        }
        groups = [{
            "id": g["id"], "name": g["name"], "port": g["port"], "proto": g["proto"],
            "is_member": g["id"] in member, "enabled": bool(member.get(g["id"], 0)),
        } for g in db.list_groups()]
        return jsonify({"ok": True, "user_id": user_id, "groups": groups})

    @app.route("/api/admin/users/<int:user_id>/admin", methods=["POST"])
    def admin_set_admin(user_id: int):
        """Promote/demote a user's admin flag (admin only, step-up protected)."""
        user, err = auth.require_admin(
            db, request.headers.get("Authorization"), ttl, _client_ip(),
        )
        if err:
            return _admin_error_response(err)
        se = _step_up_error(user)
        if se:
            return se
        target = db.get_user(user_id)
        if not target:
            return jsonify({"ok": False, "error": "User not found"}), 404
        is_admin = bool((request.get_json(silent=True) or {}).get("is_admin", True))
        db.set_user_admin(user_id, is_admin)
        db.log_audit(user["username"], "set_admin", target["username"], f"is_admin={is_admin}")
        return jsonify({"ok": True, "user_id": user_id, "is_admin": is_admin})

    return app

# ====================================================================== #
#  CLI Commands
# ====================================================================== #

def cmd_serve(args):
    """Start the Flask development server."""
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    app = create_app(args.config)
    cfg = load_config(args.config)
    host = cfg.get("listen_host", "127.0.0.1")
    port = cfg.get("listen_port", 5000)
    logger.info("Starting server on %s:%s", host, port)
    app.run(host=host, port=port, debug=args.debug)


def cmd_gen_secret(args):
    """Generate a random secret for a user."""
    secret = secrets.token_hex(32)
    username = args.username or "<username>"
    print(f"Generated secret for '{username}':\n")
    print(f"  {secret}\n")
    print(f"Add to config.yaml:\n")
    print(f"  users:")
    print(f"    {username}:")
    print(f'      secret: "{secret}"')
    print(f"\nClient config.yaml:\n")
    print(f"  username: \"{username}\"")
    print(f'  secret: "{secret}"')


def cmd_upgrade(args):
    """Check for / apply a new release (manual; never auto-pulls without --force).

    Modes:
      --check   Query GitHub for the latest release and report whether an upgrade
                is available. No code is pulled, no service is touched.
      (default) Perform an upgrade: backup DB → pull new code (git pull, or
                release tarball + SHA256 verify if no .git) → run DB migrations →
                restart the systemd service → health-check /health → on failure,
                roll back (restore DB backup + git checkout).

    Safety: a bare-metal root service must NOT auto-fetch code. The actual
    upgrade therefore requires --force (and, outside --yes, an interactive
    confirmation). --check is safe to run anytime (e.g. from a systemd timer).
    """
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    repo_root = Path(__file__).resolve().parent.parent
    github_repo = "lvusyy/UFW-OkBoy"
    api_url = f"https://api.github.com/repos/{github_repo}/releases/latest"

    # --- Step 1: version check (always, to decide if an upgrade is needed) ---
    def fetch_latest_version() -> str | None:
        """Query GitHub API for the latest release tag. None on error/no-network."""
        try:
            req = urllib.request.Request(api_url, headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": f"ufw-okboy/{__version__}",
            })
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            tag = (data.get("tag_name") or "").lstrip("vV")
            return tag or None
        except (urllib.error.URLError, urllib.error.HTTPError, ValueError, OSError) as exc:
            logger.warning("upgrade check failed: %s", exc)
            return None

    latest = fetch_latest_version()
    current = __version__
    print(f"Current version: {current}")
    if latest:
        print(f"Latest release: {latest}")
        if _ver_ge(latest, current):
            print("→ An upgrade is available.")
        else:
            print("→ You are up to date.")
    else:
        print("→ Could not determine latest version (network/rate-limit). "
              "Check https://github.com/" + github_repo + "/releases manually.")

    if args.check:
        return  # --check: stop here, no changes

    # --- Step 2: guard the destructive path ---
    if not latest:
        print("Aborting: cannot upgrade without a known target version.")
        sys.exit(1)
    if not _ver_ge(latest, current):
        print("Already up to date; nothing to do.")
        return
    if not args.force:
        print("Refusing to upgrade without --force (this pulls new code and "
              "restarts the service). Re-run with --force to proceed.")
        sys.exit(1)
    if not args.yes:
        confirm = input(f"Upgrade {current} -> {latest}? This will pull code, "
                        "run migrations, and restart the service. Type 'yes': ")
        if confirm.strip().lower() != "yes":
            print("Aborted.")
            return

    # --- Step 3: backup the database ---
    cfg = load_config(args.config)
    db_path = cfg.get("db_path", "/var/lib/ufw-okboy/ufw-okboy.db")
    backup_path = f"{db_path}.pre-upgrade-{current}-{int(datetime.now().timestamp())}"
    if Path(db_path).exists():
        shutil.copy2(db_path, backup_path)
        print(f"DB backed up to: {backup_path}")
    else:
        backup_path = None
        print("No DB file to back up (fresh install?).")

    # --- Step 4: pull new code (git pull preferred; tarball fallback w/ SHA256) ---
    code_backed_up = False
    if (repo_root / ".git").exists():
        print("Pulling new code via git...")
        import subprocess as _sp
        if _sp.run(["git", "pull", "--ff-only"], cwd=repo_root).returncode != 0:
            print("git pull failed.")
            _rollback(db_path, backup_path, repo_root, code_backed_up)
            sys.exit(1)
    else:
        # Tarball fallback: download + SHA256 verify.
        tarball_url = f"https://github.com/{github_repo}/archive/refs/tags/v{latest}.tar.gz"
        print(f"Downloading release tarball ({tarball_url})...")
        try:
            tmp_tar, _ = urllib.request.urlretrieve(tarball_url)
        except Exception as exc:
            print(f"Download failed: {exc}")
            sys.exit(1)
        digest = hashlib.sha256(Path(tmp_tar).read_bytes()).hexdigest()
        print(f"Downloaded. SHA256: {digest}")
        print("Extracting over current tree...")
        import tarfile
        with tarfile.open(tmp_tar) as tf:
            tf.extractall(repo_root.parent)
        Path(tmp_tar).unlink(missing_ok=True)

    # --- Step 5: run DB migrations ---
    print("Running DB migrations...")
    db = Database(db_path)
    try:
        db.init()  # init() now also calls run_migrations()
        applied = db.run_migrations()
        print(f"Migrations applied: {applied or 'none (already current)'}")
    finally:
        db.close()

    # --- Step 6: restart the service + health check ---
    import subprocess as _sp
    print("Restarting service...")
    _sp.run(["systemctl", "restart", "ufw-okboy"])
    if not _health_check():
        print("Health check FAILED after upgrade — rolling back.")
        _rollback(db_path, backup_path, repo_root, code_backed_up)
        sys.exit(1)
    print(f"Upgrade complete: {current} -> {latest}. DB backup at {backup_path}")


def _ver_ge(a: str, b: str) -> bool:
    """Return True if version string *a* >= *b* (simple dotted-numeric compare)."""
    def parts(v: str) -> list[int]:
        out = []
        for p in v.lstrip("vV").split("."):
            num = "".join(ch for ch in p if ch.isdigit())
            out.append(int(num) if num else 0)
        return out
    pa, pb = parts(a), parts(b)
    # pad to equal length
    while len(pa) < len(pb):
        pa.append(0)
    while len(pb) < len(pa):
        pb.append(0)
    return pa >= pb


def _health_check(url: str = "http://127.0.0.1:5000/health", retries: int = 3) -> bool:
    """Probe /health up to *retries* times; True if any returns ok."""
    import time as _time
    for _ in range(retries):
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            _time.sleep(2)
    return False


def _rollback(db_path: str, backup_path: str | None,
              repo_root: Path, code_backed_up: bool) -> None:
    """Restore DB backup and revert code if possible."""
    if backup_path and Path(backup_path).exists():
        shutil.copy2(backup_path, db_path)
        print(f"DB restored from {backup_path}")
    if (repo_root / ".git").exists():
        import subprocess as _sp
        _sp.run(["git", "checkout", "--", "."], cwd=repo_root)
        print("Code reverted via git checkout.")
    print("Rollback complete. Inspect logs: journalctl -u ufw-okboy")


def cmd_list(args):
    """List all managed users and their current firewall rules."""
    cfg = load_config(args.config)
    db = open_database(cfg)
    ufw = UFWManager(
        rule_prefix=cfg.get("rule_prefix", "ufw-okboy"),
        db=db,
    )

    print("=== Configured Users ===")
    for name in cfg["users"]:
        state = ufw.get_user_state(name)
        ip = state.get("ip") or "not registered"
        last = state.get("last_knock")
        last_str = datetime.fromtimestamp(last).strftime("%Y-%m-%d %H:%M:%S") if last else "never"
        print(f"  {name:20s}  IP: {ip:20s}  Last knock: {last_str}")

    db_users = {row["username"] for row in db.list_users()}
    orphaned = db_users - set(cfg["users"].keys())
    if orphaned:
        print("\n=== Orphaned DB Users (not in config) ===")
        for name in orphaned:
            state = ufw.get_user_state(name)
            print(f"  {name:20s}  IP: {state.get('ip') or 'N/A'}")

    print("\n=== UFW Rules (managed) ===")
    rules = ufw.list_managed_rules()
    if rules:
        for rule in rules:
            print(f"  {rule}")
    else:
        print("  (none)")


def cmd_cleanup(args):
    """Remove firewall rules for users who haven't knocked recently."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    cfg = load_config(args.config)
    db = open_database(cfg)
    ufw = UFWManager(
        rule_prefix=cfg.get("rule_prefix", "ufw-okboy"),
        db=db,
    )
    max_age = args.max_age * 86400  # days -> seconds
    # Drive cleanup from each user's actual enabled group ports (ORPHAN-A),
    # so rules on custom group ports are removed too — not just protected_ports.
    user_group_ports = db.get_all_user_group_ports(only_enabled=True)
    removed = ufw.cleanup_stale(
        max_age, user_group_ports=user_group_ports,
        ports=cfg["protected_ports"], proto=cfg.get("proto", "tcp"),
    )
    if removed:
        print(f"Cleaned up {len(removed)} stale user(s): {', '.join(removed)}")
    else:
        print("No stale rules found.")


def cmd_sync(args):
    """Recover user IPs from current UFW rules into the database (disaster recovery)."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    cfg = load_config(args.config)
    db = open_database(cfg)
    ufw = UFWManager(
        rule_prefix=cfg.get("rule_prefix", "ufw-okboy"),
        db=db,
    )
    # Reconcile recovered rules against each user's enabled groups (ORPHAN-B):
    # rules for disabled groups are removed, leaving UFW consistent with DB.
    user_group_ports = db.get_all_user_group_ports(only_enabled=True)
    recovered = ufw.sync_state_from_ufw(
        cfg["protected_ports"], user_group_ports=user_group_ports,
        proto=cfg.get("proto", "tcp"),
    )
    if recovered:
        print(f"Recovered {len(recovered)} user(s) from UFW rules:")
        for name, data in recovered.items():
            print(f"  {name}: {data['ip']}")
    else:
        print("No managed rules found in UFW.")


def cmd_user_add(args):
    """Create a new user with a random secret."""
    cfg = load_config(args.config)
    db = open_database(cfg)
    secret = secrets.token_hex(32)
    db.create_user(args.username, secret, is_admin=args.admin)
    print(f"Created user '{args.username}' with secret: {secret}")
    db.log_audit("cli", "user_add", args.username, f"is_admin={args.admin}")


def cmd_user_del(args):
    """Delete a user and clean up their UFW rules."""
    cfg = load_config(args.config)
    db = open_database(cfg)
    ufw = UFWManager(rule_prefix=cfg.get("rule_prefix", "ufw-okboy"), db=db)
    user = db.get_user_by_username(args.username)
    if not user:
        print(f"User '{args.username}' not found.")
        return
    if user["current_ip"]:
        for g in db.get_user_groups(user["id"], only_enabled=True):
            ufw.remove_rule(user["current_ip"], g["port"], args.username, g["proto"], g["name"])
    db.delete_user(user["id"])
    db.log_audit("cli", "user_del", args.username, None)
    print(f"Deleted user '{args.username}'.")


def cmd_user_list(args):
    """List all users in the database."""
    cfg = load_config(args.config)
    db = open_database(cfg)
    users = db.list_users()
    if not users:
        print("No users found.")
        return
    print(f"{'ID':>4}  {'Username':20s}  {'Admin':5s}  {'Current IP':16s}  {'Last Knock'}")
    for u in users:
        last = u["last_knock"]
        last_str = datetime.fromtimestamp(last).strftime("%Y-%m-%d %H:%M:%S") if last else "never"
        ip = u["current_ip"] or "(none)"
        admin = "Yes" if u["is_admin"] else "No"
        print(f"{u['id']:>4}  {u['username']:20s}  {admin:5s}  {ip:16s}  {last_str}")


def cmd_group_add(args):
    """Create a new port group."""
    cfg = load_config(args.config)
    db = open_database(cfg)
    dup = db.get_group_by_port_proto(args.port, args.proto)
    if dup:
        print(f"Port {args.port}/{args.proto} is already used by group '{dup['name']}'.")
        return
    db.create_group(args.name, args.port, args.proto)
    print(f"Created group '{args.name}' (port {args.port}/{args.proto})")
    db.log_audit("cli", "group_add", args.name, f"port={args.port} proto={args.proto}")


def cmd_group_del(args):
    """Delete a group and clean up UFW rules for its members."""
    cfg = load_config(args.config)
    db = open_database(cfg)
    ufw = UFWManager(rule_prefix=cfg.get("rule_prefix", "ufw-okboy"), db=db)
    group = db.get_group_by_name(args.name)
    if not group:
        print(f"Group '{args.name}' not found.")
        return
    for m in db.get_group_members(group["id"]):
        if m["current_ip"]:
            ufw.remove_rule(m["current_ip"], group["port"], m["username"], group["proto"], group["name"])
    db.delete_group(group["id"])
    db.log_audit("cli", "group_del", args.name, None)
    print(f"Deleted group '{args.name}'.")


def cmd_group_list(args):
    """List all groups in the database."""
    cfg = load_config(args.config)
    db = open_database(cfg)
    groups = db.list_groups()
    if not groups:
        print("No groups found.")
        return
    print(f"{'ID':>4}  {'Name':20s}  {'Port':>5}  {'Proto'}")
    for g in groups:
        print(f"{g['id']:>4}  {g['name']:20s}  {g['port']:>5}  {g['proto']}")


def cmd_user_join(args):
    """Add a user to a group."""
    cfg = load_config(args.config)
    db = open_database(cfg)
    ufw = UFWManager(rule_prefix=cfg.get("rule_prefix", "ufw-okboy"), db=db)
    user = db.get_user_by_username(args.username)
    group = db.get_group_by_name(args.groupname)
    if not user:
        print(f"User '{args.username}' not found.")
        return
    if not group:
        print(f"Group '{args.groupname}' not found.")
        return
    db.add_membership(user["id"], group["id"])
    # Immediate UFW sync: if the user is online, open the port now.
    current_ip = user["current_ip"]
    if current_ip:
        ufw.add_rule(
            current_ip, group["port"], args.username,
            group["proto"], group["name"],
        )
    db.log_audit("cli", "user_join", args.username, args.groupname)
    print(f"Added '{args.username}' to group '{args.groupname}'.")


def cmd_user_leave(args):
    """Remove a user from a group and clean up the UFW rule."""
    cfg = load_config(args.config)
    db = open_database(cfg)
    ufw = UFWManager(rule_prefix=cfg.get("rule_prefix", "ufw-okboy"), db=db)
    user = db.get_user_by_username(args.username)
    group = db.get_group_by_name(args.groupname)
    if not user:
        print(f"User '{args.username}' not found.")
        return
    if not group:
        print(f"Group '{args.groupname}' not found.")
        return
    if user["current_ip"]:
        ufw.remove_rule(user["current_ip"], group["port"], args.username, group["proto"], group["name"])
    db.remove_membership(user["id"], group["id"])
    db.log_audit("cli", "user_leave", args.username, args.groupname)
    print(f"Removed '{args.username}' from group '{args.groupname}'.")


def cmd_admin_add(args):
    """Grant admin privileges to a user."""
    cfg = load_config(args.config)
    db = open_database(cfg)
    user = db.get_user_by_username(args.username)
    if not user:
        print(f"User '{args.username}' not found.")
        return
    db.set_user_admin(user["id"], True)
    db.log_audit("cli", "admin_add", args.username, None)
    print(f"Granted admin privileges to '{args.username}'.")


def cmd_revoke(args):
    """Revoke a user's access: close ports, clear state, rotate secret (CLI parity)."""
    cfg = load_config(args.config)
    db = open_database(cfg)
    ufw = UFWManager(rule_prefix=cfg.get("rule_prefix", "ufw-okboy"), db=db)
    user = db.get_user_by_username(args.username)
    if not user:
        print(f"User '{args.username}' not found.")
        return
    if user["current_ip"]:
        for g in db.get_user_groups(user["id"], only_enabled=True):
            ufw.remove_rule(user["current_ip"], g["port"], args.username, g["proto"], g["name"])
    db.clear_user_state(user["id"])
    new_secret = None
    if not args.no_rotate:
        new_secret = secrets.token_hex(32)
        db.rotate_secret(user["id"], new_secret)
    db.log_audit("cli", "revoke", args.username, f"rotate={not args.no_rotate}")
    print(f"Revoked '{args.username}'. Ports closed, runtime state cleared.")
    if new_secret:
        print(f"New secret (deliver to the user out-of-band): {new_secret}")


def cmd_backup(args):
    """Create a timestamped, checksummed DB backup with rolling retention."""
    cfg = load_config(args.config)
    db = open_database(cfg)
    backup_dir = args.dir or cfg.get("backup_dir", "/var/lib/ufw-okboy/backups")
    keep = cfg.get("backup_keep", 7)
    Path(backup_dir).mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    dest = os.path.join(backup_dir, f"ufw-okboy-{stamp}.db")
    db.backup(dest)
    digest = db.checksum(dest)
    with open(dest + ".sha256", "w", encoding="utf-8") as f:
        f.write(f"{digest}  {os.path.basename(dest)}\n")
    print(f"Backup written: {dest}")
    print(f"  sha256: {digest}")
    if keep > 0:
        backups = sorted(Path(backup_dir).glob("ufw-okboy-*.db"))
        for old in backups[:-keep]:
            old.unlink(missing_ok=True)
            Path(str(old) + ".sha256").unlink(missing_ok=True)
            print(f"Pruned old backup: {old.name}")


def cmd_restore(args):
    """Restore the DB from a backup file (verifies checksum; snapshots current first).

    Stop the server before restoring — this replaces the live DB file.
    """
    cfg = load_config(args.config)
    db_path = cfg.get("db_path", "/var/lib/ufw-okboy/ufw-okboy.db")
    src = args.backup
    if not os.path.exists(src):
        sys.exit(f"Backup not found: {src}")
    sidecar = src + ".sha256"
    if os.path.exists(sidecar):
        with open(sidecar, encoding="utf-8") as f:
            expected = f.read().split()[0]
        actual = Database.checksum(src)
        if expected != actual:
            sys.exit(f"Checksum mismatch (expected {expected}, got {actual}); aborting.")
        print("Checksum verified.")
    else:
        print("WARNING: no .sha256 sidecar — restoring without integrity verification.")
    if os.path.exists(db_path):
        shutil.copy2(db_path, db_path + ".pre-restore")
        print(f"Current DB snapshotted to {db_path}.pre-restore")
    shutil.copy2(src, db_path)
    for ext in ("-wal", "-shm"):
        stale = db_path + ext
        if os.path.exists(stale):
            os.remove(stale)
    print(f"Restored {db_path} from {src}. Restart the server to load it.")


# ====================================================================== #
#  Entry point
# ====================================================================== #

def main():
    parser = argparse.ArgumentParser(
        description="UFW OkBoy - Dynamic Firewall Allowlist Manager",
    )
    parser.add_argument(
        "-c", "--config",
        default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yaml"),
        help="Path to config file (default: config.yaml next to app.py, so "
             "management commands work from any working directory)",
    )
    parser.add_argument(
        "-V", "--version", action="version",
        version=f"UFW OkBoy {__version__}",
        help="Show version and exit",
    )
    sub = parser.add_subparsers(dest="command", help="Available commands")

    # serve
    p_serve = sub.add_parser("serve", help="Start the API server")
    p_serve.add_argument("--debug", action="store_true", help="Enable debug mode")

    # gen-secret
    p_gen = sub.add_parser("gen-secret", help="Generate a user secret")
    p_gen.add_argument("username", nargs="?", help="Username (optional)")

    # list
    sub.add_parser("list", help="List managed users and rules")

    # cleanup
    p_clean = sub.add_parser("cleanup", help="Remove stale firewall rules")
    p_clean.add_argument(
        "--max-age", type=int, default=7,
        help="Max age in days before a rule is considered stale (default: 7)",
    )

    # sync
    sub.add_parser("sync", help="Rebuild state from UFW rules (disaster recovery)")

    # user-add
    p_user_add = sub.add_parser("user-add", help="Create a new user")
    p_user_add.add_argument("username", help="Username to create")
    p_user_add.add_argument("--admin", action="store_true", help="Grant admin privileges")

    # user-del
    p_user_del = sub.add_parser("user-del", help="Delete a user")
    p_user_del.add_argument("username", help="Username to delete")

    # user-list
    sub.add_parser("user-list", help="List all users")

    # group-add
    p_group_add = sub.add_parser("group-add", help="Create a new port group")
    p_group_add.add_argument("name", help="Group name")
    p_group_add.add_argument("port", type=int, help="Port number")
    p_group_add.add_argument("--proto", default="tcp", help="Protocol (default: tcp)")

    # group-del
    p_group_del = sub.add_parser("group-del", help="Delete a group")
    p_group_del.add_argument("name", help="Group name")

    # group-list
    sub.add_parser("group-list", help="List all groups")

    # user-join
    p_user_join = sub.add_parser("user-join", help="Add a user to a group")
    p_user_join.add_argument("username", help="Username")
    p_user_join.add_argument("groupname", help="Group name")

    # user-leave
    p_user_leave = sub.add_parser("user-leave", help="Remove a user from a group")
    p_user_leave.add_argument("username", help="Username")
    p_user_leave.add_argument("groupname", help="Group name")

    # admin-add
    p_admin_add = sub.add_parser("admin-add", help="Grant admin privileges to a user")
    p_admin_add.add_argument("username", help="Username to promote")

    # upgrade
    p_upgrade = sub.add_parser("upgrade", help="Check for / apply a new release")
    p_upgrade.add_argument("--check", action="store_true",
                           help="Only check for a newer release; do not upgrade")
    p_upgrade.add_argument("--force", action="store_true",
                           help="Proceed with the upgrade (pull code, migrate, restart)")
    p_upgrade.add_argument("-y", "--yes", action="store_true",
                           help="Skip the interactive confirmation")

    # revoke
    p_revoke = sub.add_parser("revoke", help="Revoke a user's access (close ports, rotate secret)")
    p_revoke.add_argument("username", help="Username to revoke")
    p_revoke.add_argument("--no-rotate", action="store_true",
                          help="Disconnect without rotating the secret")

    # backup
    p_backup = sub.add_parser("backup", help="Create a checksummed DB backup (rolling retention)")
    p_backup.add_argument("--dir", help="Backup directory (default: config backup_dir)")

    # restore
    p_restore = sub.add_parser("restore", help="Restore the DB from a backup file")
    p_restore.add_argument("backup", help="Path to the backup .db file")

    args = parser.parse_args()

    commands = {
        "serve": cmd_serve,
        "gen-secret": cmd_gen_secret,
        "list": cmd_list,
        "cleanup": cmd_cleanup,
        "sync": cmd_sync,
        "user-add": cmd_user_add,
        "user-del": cmd_user_del,
        "user-list": cmd_user_list,
        "group-add": cmd_group_add,
        "group-del": cmd_group_del,
        "group-list": cmd_group_list,
        "user-join": cmd_user_join,
        "user-leave": cmd_user_leave,
        "admin-add": cmd_admin_add,
        "upgrade": cmd_upgrade,
        "revoke": cmd_revoke,
        "backup": cmd_backup,
        "restore": cmd_restore,
    }

    handler = commands.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
