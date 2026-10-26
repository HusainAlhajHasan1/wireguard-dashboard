"""Flask web UI + JSON API."""
from __future__ import annotations

import functools
import hmac
import html
import io
import json
import os
import re
import time
from datetime import timedelta

from flask import (Flask, Response, abort, g, jsonify, make_response, redirect,
                   render_template, request, send_file, session)
from werkzeug.middleware.proxy_fix import ProxyFix

from . import crypto
from .core import VERSION
from .wireguard import WgError

LOGIN_WINDOW = 300
LOGIN_MAX = 6
LOGIN_BAN = 900
_failed = {}


def _client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "?").split(",")[0].strip()


def _rate_ok(ip):
    now = time.time()
    entry = _failed.get(ip, {"times": [], "ban": 0})
    if entry["ban"] > now:
        return False
    entry["times"] = [t for t in entry["times"] if now - t < LOGIN_WINDOW]
    return len(entry["times"]) < LOGIN_MAX


def _rate_fail(ip):
    now = time.time()
    entry = _failed.setdefault(ip, {"times": [], "ban": 0})
    entry["times"].append(now)
    if len(entry["times"]) >= LOGIN_MAX:
        entry["ban"] = now + LOGIN_BAN
    _failed[ip] = entry


def _rate_reset(ip):
    _failed.pop(ip, None)


def create_app(core):
    app = Flask(__name__, static_folder="static", template_folder="templates")
    cfg = core.config
    app.secret_key = cfg.get("secret_key") or crypto.new_token(32)
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=bool((cfg.get("public_url") or "").startswith("https")),
        PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
        MAX_CONTENT_LENGTH=2 * 1024 * 1024,
        JSON_SORT_KEYS=False,
    )
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    def json_error(message, status=400):
        return jsonify({"ok": False, "error": str(message)}), status

    def actor():
        return getattr(g, "actor", "unknown")

    def current_admin():
        admin_id = session.get("admin_id")
        return core.db.admin_by_id(admin_id) if admin_id else None

    def api_auth():
        header = request.headers.get("Authorization", "")
        token = request.headers.get("X-API-Key") or (header[7:] if header.startswith("Bearer ") else "")
        if token:
            row = core.db.verify_api_token(token)
            if row:
                g.actor = "api:{}".format(row["name"])
                g.api_token = True
                return True
        if current_admin():
            g.actor = current_admin()["username"]
            g.api_token = False
            return True
        return False

    def protected(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            if not api_auth():
                return json_error("Authentication required", 401)
            return fn(*args, **kwargs)
        return wrapper

    @app.before_request
    def before():
        g.actor = "anonymous"
        g.api_token = False
        # CSRF for session-authenticated state changes (API tokens are exempt).
        if request.method in ("POST", "PUT", "PATCH", "DELETE") and request.path.startswith("/api/"):
            if request.path == "/api/login":
                return None
            if not api_auth():
                return json_error("Authentication required", 401)
            if not g.api_token:
                expected = session.get("csrf") or ""
                provided = request.headers.get("X-CSRF-Token", "")
                if not expected or not provided or not hmac.compare_digest(expected, provided):
                    return json_error("Invalid CSRF token; refresh the page", 403)
        return None

    @app.after_request
    def after(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "SAMEORIGIN"
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["Cache-Control"] = resp.headers.get("Cache-Control", "no-store")
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; "
            "frame-ancestors 'self'; base-uri 'self'")
        return resp

    # ------------------------------- pages -------------------------------
    @app.get("/")
    def index():
        if not current_admin():
            return redirect("/login")
        admin = current_admin()
        if not session.get("csrf"):
            session["csrf"] = crypto.new_token(24)
        return render_template("index.html", version=VERSION, csrf=session["csrf"],
                               username=admin["username"], demo=bool(cfg.get("demo")),
                               public_url=cfg.get("public_url") or "")

    @app.get("/login")
    def login_page():
        if current_admin():
            return redirect("/")
        return render_template("login.html", version=VERSION, demo=bool(cfg.get("demo")),
                               demo_user="admin" if cfg.get("demo") else "")

    @app.get("/health")
    def health():
        return jsonify({"ok": True, "version": VERSION, "demo": bool(cfg.get("demo"))})

    # ------------------------------- auth -------------------------------
    @app.post("/api/login")
    def login():
        ip = _client_ip()
        if not _rate_ok(ip):
            return json_error("Too many failed attempts. Try again in 15 minutes.", 429)
        body = request.get_json(silent=True) or {}
        admin = core.db.admin(str(body.get("username") or "").strip())
        password = str(body.get("password") or "")
        if not admin or not crypto.verify_password(password, admin["password_hash"]):
            _rate_fail(ip)
            core.db.add_audit("anonymous", "login.failed", "user={}".format(body.get("username")), ip)
            return json_error("Invalid username or password", 401)
        settings = core.db.settings()
        secret = admin["totp_secret"]
        if secret or settings.get("require_2fa"):
            if not secret:
                return json_error("2FA is enforced but not configured for this account", 400)
            if not crypto.verify_totp(secret, str(body.get("totp") or "")):
                _rate_fail(ip)
                return json_error("Invalid authenticator code", 401)
        _rate_reset(ip)
        session.clear()
        session.permanent = True
        session["admin_id"] = admin["id"]
        session["csrf"] = crypto.new_token(24)
        core.db.update_admin(admin["id"], {"last_login": int(time.time())})
        core.db.add_audit(admin["username"], "login.success", "", ip)
        return jsonify({"ok": True, "csrf": session["csrf"],
                        "username": admin["username"], "version": VERSION})

    @app.post("/api/logout")
    def logout():
        core.db.add_audit(actor(), "logout", "", _client_ip())
        session.clear()
        return jsonify({"ok": True})

    @app.get("/api/session")
    def api_session():
        admin = current_admin()
        return jsonify({"authenticated": bool(admin), "username": admin["username"] if admin else "",
                        "csrf": session.get("csrf", ""), "demo": bool(cfg.get("demo")),
                        "version": VERSION})

    # ------------------------------- state -------------------------------
    @app.get("/api/state")
    @protected
    def api_state():
        try:
            state = core.state()
            state["instance"] = cfg.as_public()
            return jsonify(state)
        except Exception as exc:
            return json_error(exc, 500)

    @app.get("/api/traffic")
    @protected
    def api_traffic():
        hours = min(168, max(1, int(request.args.get("hours", 24))))
        peer_id = request.args.get("peer_id") or None
        bucket = 300 if hours <= 6 else (3600 if hours <= 48 else 21600)
        return jsonify({"series": core.db.traffic_series(int(time.time()) - hours * 3600,
                                                         bucket=bucket, peer_id=peer_id),
                        "bucket": bucket})

    @app.get("/api/events")
    @protected
    def api_events():
        return jsonify({"events": core.db.events(min(500, int(request.args.get("limit", 100))),
                                                request.args.get("peer_id") or None)})

    @app.get("/api/audit")
    @protected
    def api_audit():
        return jsonify({"audit": core.db.audit(min(500, int(request.args.get("limit", 200))))})

    # ------------------------------- peers -------------------------------
    @app.post("/api/peers")
    @protected
    def api_add_peer():
        try:
            peer = core.add_peer(request.get_json(silent=True) or {}, actor())
            return jsonify({"ok": True, "peer": core.peer_view(peer)})
        except (WgError, ValueError, TypeError) as exc:
            return json_error(exc)

    @app.patch("/api/peers/<peer_id>")
    @protected
    def api_update_peer(peer_id):
        try:
            peer = core.update_peer(peer_id, request.get_json(silent=True) or {}, actor())
            return jsonify({"ok": True, "peer": core.peer_view(peer)})
        except (WgError, ValueError) as exc:
            return json_error(exc)

    @app.delete("/api/peers/<peer_id>")
    @protected
    def api_delete_peer(peer_id):
        try:
            peer = core.revoke_peer(peer_id, actor())
            return jsonify({"ok": True, "removed": peer["name"]})
        except WgError as exc:
            return json_error(exc)

    @app.post("/api/peers/<peer_id>/<action>")
    @protected
    def api_peer_action(peer_id, action):
        try:
            if action == "enable":
                peer = core.set_enabled(peer_id, True, actor())
            elif action == "disable":
                peer = core.set_enabled(peer_id, False, actor())
            elif action == "rekey":
                peer = core.regenerate_keys(peer_id, actor())
            elif action == "share":
                body = request.get_json(silent=True) or {}
                return jsonify({"ok": True, "share": core.create_share(
                    peer_id, actor(), int(body.get("hours") or 0))})
            elif action == "telegram":
                return send_peer_telegram(peer_id)
            elif action == "conf":
                return jsonify({"ok": True, "conf": core.client_config(peer_id)[1]})
            else:
                return json_error("Unknown action", 404)
            return jsonify({"ok": True, "peer": core.peer_view(peer)})
        except (WgError, ValueError) as exc:
            return json_error(exc)

    def send_peer_telegram(peer_id):
        peer = core.db.peer(peer_id)
        if not peer:
            return json_error("Peer not found", 404)
        body = request.get_json(silent=True) or {}
        chat_id = str(body.get("chat_id") or peer["telegram_chat_id"] or "").strip()
        if not chat_id:
            return json_error("No Telegram chat ID supplied", 400)
        if not core.bot or not core.bot.token:
            return json_error("Telegram bot is not configured", 400)
        filename, text = core.client_config(peer_id)
        caption = "WireGuard config for {}\nIP: {}\nEndpoint: {}".format(
            peer["name"], peer["vpn_ip"], core.wg.endpoint())
        ok = core.bot.send_document(chat_id, filename, text.encode(), caption)
        if not ok.get("ok"):
            return json_error("Telegram: {}".format(ok.get("description", "send failed")))
        try:
            png, _ = core.qr_png(peer_id)
            core.bot.send_photo(chat_id, "wg-{}-qr.png".format(peer["name"]), png,
                                "Scan to connect: {}".format(peer["name"]))
        except Exception:
            pass
        core.db.add_audit(actor(), "peer.telegram", "{} -> {}".format(peer["name"], chat_id))
        return jsonify({"ok": True, "sent_to": chat_id})

    @app.get("/api/peers/<peer_id>/details")
    @protected
    def api_peer_details(peer_id):
        peer = core.db.peer(peer_id)
        if not peer:
            return json_error("Peer not found", 404)
        return jsonify({
            "peer": core.peer_view(peer),
            "events": core.db.events(50, peer_id),
            "samples": core.db.peer_samples(peer_id, int(time.time()) - 7 * 86400, 400),
            "shares": core.db.shares(peer_id),
        })

    @app.get("/api/peers/<peer_id>/config")
    @protected
    def api_peer_config(peer_id):
        try:
            filename, text = core.client_config(peer_id)
            return Response(text, mimetype="text/plain", headers={
                "Content-Disposition": 'attachment; filename="{}"'.format(filename),
                "Content-Type": "text/plain; charset=utf-8"})
        except WgError as exc:
            return json_error(exc)

    @app.get("/api/peers/<peer_id>/qr.svg")
    @protected
    def api_peer_qr_svg(peer_id):
        try:
            return Response(core.wg.qr_svg(core.client_config(peer_id)[1]),
                            mimetype="image/svg+xml")
        except WgError as exc:
            return json_error(exc)

    @app.get("/api/peers/<peer_id>/qr.png")
    @protected
    def api_peer_qr_png(peer_id):
        try:
            png, _ = core.qr_png(peer_id)
            return send_file(io.BytesIO(png), mimetype="image/png",
                             download_name="wg-{}.png".format(core.db.peer(peer_id)["name"]))
        except WgError as exc:
            return json_error(exc)

    # ------------------------------- server -------------------------------
    @app.get("/api/server")
    @protected
    def api_server():
        try:
            # The server private key never leaves the host: it is redacted here,
            # not in the browser.
            config = re.sub(r"(?mi)^(\s*PrivateKey\s*=\s*).*$", r"\1<redacted for security>",
                            core.wg.read_conf())
            interface = {k: v for k, v in core.wg.interface().items() if k != "private_key"}
            return jsonify({"info": core.wg.server_info(), "interface": interface,
                            "config": config, "backups": core.wg.backups()})
        except WgError as exc:
            return json_error(exc)

    @app.post("/api/server/interface")
    @protected
    def api_server_interface():
        body = request.get_json(silent=True) or {}
        mapping = {
            "address": "Address", "listen_port": "ListenPort", "dns": "DNS",
            "mtu": "MTU", "postup": "PostUp", "postdown": "PostDown",
            "saveconfig": "SaveConfig", "table": "Table",
        }
        patch = {}
        for key, wg_key in mapping.items():
            if key in body:
                patch[wg_key] = str(body[key]).strip()
        try:
            core.wg.write_conf(interface_patch=patch)
            core.db.add_audit(actor(), "server.interface", json.dumps(body))
            return jsonify({"ok": True, "interface": core.wg.interface(),
                            "note": "Changes to ListenPort/Address require an interface restart."})
        except WgError as exc:
            return json_error(exc)

    @app.post("/api/server/restart")
    @protected
    def api_server_restart():
        ok, output = core.wg.restart()
        core.db.add_audit(actor(), "server.restart", output[:200])
        core.db.add_event("server_restart", "WireGuard interface restarted by {}".format(actor()))
        return jsonify({"ok": ok, "output": output})

    @app.post("/api/server/rotate-keys")
    @protected
    def api_server_rotate():
        pub = core.wg.rotate_server_keys()
        core.db.add_audit(actor(), "server.rotate-keys", pub[:16])
        core.db.add_event("keys_rotated", "Server keypair rotated by {} — all clients must re-download config".format(actor()))
        core.notify("\u26A0 Server WireGuard keys were rotated by <b>{}</b>. "
                    "All clients must download a fresh config.".format(html.escape(actor())), "warning")
        return jsonify({"ok": True, "public_key": pub})

    @app.post("/api/server/sync")
    @protected
    def api_server_sync():
        imported = core.wg.sync_from_conf()
        core.wg.apply_conf()
        core.db.add_audit(actor(), "server.sync", "imported {}".format(len(imported)))
        return jsonify({"ok": True, "imported": imported})

    @app.post("/api/server/backup")
    @protected
    def api_server_backup():
        try:
            name = core.wg.backup("manual")
            return jsonify({"ok": True, "name": name, "backups": core.wg.backups()})
        except WgError as exc:
            return json_error(exc)

    @app.get("/api/server/backup.zip")
    @protected
    def api_server_backup_zip():
        return send_file(io.BytesIO(core.backup_zip()), mimetype="application/zip",
                         download_name="wireguard-backup-{}.zip".format(time.strftime("%Y%m%d")))

    @app.post("/api/server/restore")
    @protected
    def api_server_restore():
        body = request.get_json(silent=True) or {}
        try:
            result = core.wg.restore(str(body.get("name") or ""))
            core.db.add_audit(actor(), "server.restore", str(body.get("name")))
            return jsonify({"ok": True, "message": result})
        except WgError as exc:
            return json_error(exc)

    # ------------------------------- settings -------------------------------
    @app.get("/api/settings")
    @protected
    def api_get_settings():
        return jsonify({"settings": core.db.settings(), "admins": core.db.admins(),
                        "tokens": core.db.api_tokens(), "shares": core.db.shares()})

    @app.post("/api/settings")
    @protected
    def api_set_settings():
        body = request.get_json(silent=True) or {}
        if body.get("require_2fa"):
            admins = core.db.admins()
            if any(not a["has_2fa"] for a in admins):
                return json_error("Set up 2FA on every admin account before enforcing it", 400)
        core.db.set_settings(body)
        core.db.add_audit(actor(), "settings.update", json.dumps(list(body.keys())))
        if core.bot:
            core.bot.reload()
        if core.monitor:
            core.monitor.last_tick = 0
        return jsonify({"ok": True, "settings": core.db.settings()})

    @app.post("/api/settings/password")
    @protected
    def api_password():
        body = request.get_json(silent=True) or {}
        admin = current_admin()
        if not admin:
            return json_error("Session login required", 403)
        if not crypto.verify_password(str(body.get("current") or ""), admin["password_hash"]):
            return json_error("Current password is incorrect", 403)
        new = str(body.get("new") or "")
        if len(new) < 10:
            return json_error("Use at least 10 characters", 400)
        core.db.update_admin(admin["id"], {"password_hash": crypto.hash_password(new)})
        core.db.add_audit(actor(), "settings.password", "changed")
        return jsonify({"ok": True})

    @app.post("/api/settings/telegram/test")
    @protected
    def api_telegram_test():
        body = request.get_json(silent=True) or {}
        if not core.bot:
            return json_error("Bot not running", 500)
        ok, message = core.bot.test(body.get("chat_id") or None)
        core.db.add_audit(actor(), "telegram.test", message)
        return jsonify({"ok": ok, "message": message})

    @app.get("/api/settings/2fa")
    @protected
    def api_2fa_setup():
        admin = current_admin()
        if not admin:
            return json_error("Session login required", 403)
        secret = crypto.new_totp_secret()
        core.db.set_meta("2fa_pending_{}".format(admin["id"]), secret)
        uri = "otpauth://totp/WireGuard%20Dashboard:{}?secret={}&issuer=WireGuard%20Dashboard".format(
            admin["username"], secret)
        return jsonify({"secret": secret, "uri": uri,
                        "qr": core.wg.qr_svg(uri, size=5)})

    @app.post("/api/settings/2fa")
    @protected
    def api_2fa_enable():
        admin = current_admin()
        pending = core.db.meta("2fa_pending_{}".format(admin["id"])) if admin else None
        if not admin or not pending:
            return json_error("Request setup first", 400)
        body = request.get_json(silent=True) or {}
        if not crypto.verify_totp(pending, str(body.get("code") or "")):
            return json_error("Invalid code", 400)
        core.db.update_admin(admin["id"], {"totp_secret": pending})
        core.db.set_meta("2fa_pending_{}".format(admin["id"]), None)
        core.db.add_audit(actor(), "settings.2fa", "enabled")
        return jsonify({"ok": True})

    @app.delete("/api/settings/2fa")
    @protected
    def api_2fa_disable():
        admin = current_admin()
        if not admin:
            return json_error("Session login required", 403)
        core.db.update_admin(admin["id"], {"totp_secret": ""})
        core.db.add_audit(actor(), "settings.2fa", "disabled")
        return jsonify({"ok": True})

    @app.post("/api/tokens")
    @protected
    def api_create_token():
        name = (request.get_json(silent=True) or {}).get("name") or "automation"
        tid, token = core.db.create_api_token(str(name)[:40])
        core.db.add_audit(actor(), "token.create", name)
        return jsonify({"ok": True, "id": tid, "token": token})

    @app.delete("/api/tokens/<token_id>")
    @protected
    def api_delete_token(token_id):
        core.db.delete_api_token(token_id)
        core.db.add_audit(actor(), "token.delete", token_id)
        return jsonify({"ok": True})

    @app.delete("/api/shares/<token>")
    @protected
    def api_delete_share(token):
        core.db.revoke_share(token)
        return jsonify({"ok": True})

    # ------------------------------- public share -------------------------------
    @app.get("/s/<token>")
    def share_page(token):
        peer = core.db.consume_share(token)
        if not peer:
            return render_template("share.html", error="This link has expired or reached its limit.",
                                   version=VERSION), 410
        try:
            filename, text = core.client_config(peer["id"])
            svg = core.wg.qr_svg(text, size=7)
        except WgError as exc:
            return render_template("share.html", error=str(exc), version=VERSION), 400
        return render_template("share.html", peer=core.peer_view(peer), token=token,
                               filename=filename, config=text, svg=svg,
                               endpoint=core.wg.endpoint(), version=VERSION)

    @app.get("/s/<token>/config")
    def share_config(token):
        row = core.db.share(token)
        if not row or row["expires_at"] < time.time() or row["uses"] > row["max_uses"]:
            abort(410)
        try:
            filename, text = core.client_config(row["peer_id"])
            return Response(text, mimetype="text/plain", headers={
                "Content-Disposition": 'attachment; filename="{}"'.format(filename)})
        except WgError:
            abort(404)

    @app.get("/s/<token>/qr.png")
    def share_qr(token):
        row = core.db.share(token)
        if not row or row["expires_at"] < time.time() or row["uses"] > row["max_uses"]:
            abort(410)
        try:
            png, _ = core.qr_png(row["peer_id"])
            return send_file(io.BytesIO(png), mimetype="image/png")
        except WgError:
            abort(404)

    return app
