#!/usr/bin/env python3
"""UFW OkBoy - Dynamic Firewall Allowlist Manager.

Server application providing:
1. HTTPS API for clients to register their IP in the firewall allowlist
2. CLI tools for user management and stale-rule cleanup

Authentication: HMAC-SHA256 with timestamp (secret never transmitted).
"""

import argparse
import logging
import secrets
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

import os

import yaml
from flask import Flask, request, jsonify, send_from_directory

import auth
from db import Database
from ufw_ops import UFWManager

logger = logging.getLogger("ufw-okboy")

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

    def _auth():
        return auth.verify_hmac(
            db, request.headers.get("Authorization"), ttl, _client_ip(),
        )

    def _client_ip() -> str:
        """Extract real client IP, respecting reverse-proxy headers."""
        return (
            request.headers.get("X-Real-IP")
            or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or request.remote_addr
        )

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
        old_ip = db.get_user_ip(username)

        # IP unchanged - just refresh the timestamp
        if old_ip == client_ip:
            db.update_knock_time(user_id, client_ip)
            logger.info("Knock: %s@%s (unchanged)", username, client_ip)
            return jsonify({
                "ok": True,
                "ip": client_ip,
                "changed": False,
                "message": "IP unchanged, heartbeat recorded",
            })

        # IP changed - swap firewall rules for every enabled group
        if old_ip:
            for grp in enabled_groups:
                ufw.remove_rule(old_ip, grp["port"], username, grp["proto"], grp["name"])
            logger.info("Removed old rules for %s (was %s)", username, old_ip)

        for grp in enabled_groups:
            ufw.add_rule(client_ip, grp["port"], username, grp["proto"], grp["name"])

        db.set_user_ip(user_id, client_ip)
        db.update_knock_time(user_id, client_ip)
        db.log_operation(username, "ip_change", client_ip, f"old={old_ip}")
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
            "enabled_groups": enabled_groups,
            **state,
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

        group = db.get_group(group_id)
        if not group:
            return jsonify({"ok": False, "error": "Group not found"}), 404
        target = db.get_user(user_id)
        if not target:
            return jsonify({"ok": False, "error": "User not found"}), 404

        db.set_membership_enabled(user_id, group_id, 1 if enabled else 0)

        user_ip = target["current_ip"]
        if user_ip:
            if not enabled:
                ufw.remove_rule(
                    user_ip, group["port"], target["username"],
                    group["proto"], group["name"],
                )
            else:
                ufw.add_rule(
                    user_ip, group["port"], target["username"],
                    group["proto"], group["name"],
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
        target = db.get_user(user_id)
        if not target:
            return jsonify({"ok": False, "error": "User not found"}), 404
        if target["current_ip"]:
            for g in db.get_user_groups(user_id, only_enabled=True):
                ufw.remove_rule(target["current_ip"], g["port"], target["username"], g["proto"])
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
        data = request.get_json(force=True, silent=True) or {}
        name = data.get("name")
        port = data.get("port")
        if not name or port is None:
            return jsonify({"ok": False, "error": "name and port are required"}), 400
        proto = data.get("proto", "tcp")
        try:
            group_id = db.create_group(name, int(port), proto)
        except sqlite3.IntegrityError:
            return jsonify({"ok": False, "error": f"Group '{name}' already exists"}), 409
        db.log_audit(user["username"], "group_add", name, f"port={port} proto={proto}")
        return jsonify({
            "ok": True, "id": group_id, "name": name,
            "port": int(port), "proto": proto,
        }), 201

    @app.route("/api/admin/groups/<int:group_id>", methods=["DELETE"])
    def admin_delete_group(group_id: int):
        """Delete a group and clean up UFW rules for its members (admin only)."""
        user, err = auth.require_admin(
            db, request.headers.get("Authorization"), ttl, _client_ip(),
        )
        if err:
            return _admin_error_response(err)
        group = db.get_group(group_id)
        if not group:
            return jsonify({"ok": False, "error": "Group not found"}), 404
        for m in db.get_group_members(group_id):
            if m["current_ip"]:
                ufw.remove_rule(m["current_ip"], group["port"], m["username"], group["proto"])
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
        db.log_audit(user["username"], "user_join", target["username"], group["name"])
        return jsonify({
            "ok": True, "user_id": user_id,
            "group_id": int(group_id), "enabled": enabled,
        }), 201

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
    removed = ufw.cleanup_stale(max_age, cfg["protected_ports"], cfg.get("proto", "tcp"))
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
    recovered = ufw.sync_state_from_ufw(cfg["protected_ports"])
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
            ufw.remove_rule(user["current_ip"], g["port"], args.username, g["proto"])
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
            ufw.remove_rule(m["current_ip"], group["port"], m["username"], group["proto"])
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
    user = db.get_user_by_username(args.username)
    group = db.get_group_by_name(args.groupname)
    if not user:
        print(f"User '{args.username}' not found.")
        return
    if not group:
        print(f"Group '{args.groupname}' not found.")
        return
    db.add_membership(user["id"], group["id"])
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
        ufw.remove_rule(user["current_ip"], group["port"], args.username, group["proto"])
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


# ====================================================================== #
#  Entry point
# ====================================================================== #

def main():
    parser = argparse.ArgumentParser(
        description="UFW OkBoy - Dynamic Firewall Allowlist Manager",
    )
    parser.add_argument(
        "-c", "--config", default="config.yaml",
        help="Path to config file (default: config.yaml)",
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
    }

    handler = commands.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
