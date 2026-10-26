"""Application core shared by the web UI, CLI, Telegram bot and monitor."""
from __future__ import annotations

import hashlib
import html
import io
import json
import os
import re
import secrets
import socket
import time
import zipfile

from . import crypto
from .wireguard import WgError, flag_emoji, parse_endpoint

VERSION = "1.0.0"


def human_bytes(num) -> str:
    num = float(num or 0)
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if abs(num) < 1024 or unit == "PB":
            return "{:.0f} {}".format(num, unit) if unit == "B" else "{:.2f} {}".format(num, unit)
        num /= 1024
    return "0 B"


def human_duration(seconds) -> str:
    seconds = int(seconds or 0)
    if seconds <= 0:
        return "just now"
    if seconds < 60:
        return "{}s ago".format(seconds)
    if seconds < 3600:
        return "{}m ago".format(seconds // 60)
    if seconds < 86400:
        return "{}h {}m ago".format(seconds // 3600, (seconds % 3600) // 60)
    return "{}d {}h ago".format(seconds // 86400, (seconds % 86400) // 3600)


class Core:
    def __init__(self, config, db, wg):
        self.config = config
        self.db = db
        self.wg = wg
        self.bot = None
        self.monitor = None
        self.started_at = int(time.time())
        self._server_cache = None
        self._server_cache_ts = 0

    def server_info(self):
        now = time.time()
        if self._server_cache and now - self._server_cache_ts < 20:
            return self._server_cache
        self._server_cache = self.wg.server_info()
        self._server_cache_ts = now
        return self._server_cache

    # ---------------- bootstrap ----------------
    def bootstrap(self):
        """Create the initial admin and import existing wg0.conf peers."""
        from . import crypto as _crypto
        boot = self.config.get("bootstrap_admin")
        if boot and not self.db.admins():
            self.db.create_admin(boot["username"], boot["password_hash"])
            self.config.save({"bootstrap_admin": None})
        if not self.db.admins() and self.config.get("demo"):
            # Demo-only convenience account; production installs always run
            # `wgdash init-admin` from install.sh.
            self.db.create_admin("admin", _crypto.hash_password("DemoAdmin123!"))
        if not self.db.meta("initialized"):
            imported = []
            try:
                imported = self.wg.sync_from_conf()
            except Exception as exc:
                self.db.add_event("warning", "Could not import wg0.conf: {}".format(exc))
            self.db.set_meta("initialized", True)
            self.db.set_meta("installed_at", int(time.time()))
            if imported:
                self.db.add_event("info", "Imported existing peers: " + ", ".join(imported))
            self.db.add_audit("system", "install", "Dashboard initialized")
        if not self.db.meta("instance_id"):
            self.db.set_meta("instance_id", secrets.token_hex(8))

    def start_services(self):
        from .monitor import Monitor
        from .telegram import TelegramBot
        self.monitor = Monitor(self)
        self.bot = TelegramBot(self)
        self.monitor.start()
        self.bot.start()

    def stop_services(self):
        if self.monitor:
            self.monitor.stop()
        if self.bot:
            self.bot.stop()

    # ---------------- notifications ----------------
    def notify(self, text: str, level: str = "info"):
        if self.bot:
            try:
                self.bot.notify(text, level)
            except Exception:
                pass

    # ---------------- peer operations ----------------
    def _validate_name(self, name: str) -> str:
        name = re.sub(r"[^A-Za-z0-9 _.\-]", "", (name or "").strip())[:48]
        if not name:
            raise WgError("A peer name is required (letters, numbers, space, . _ -).")
        return name

    def add_peer(self, data: dict, actor: str = "admin") -> dict:
        settings = self.db.settings(include_secrets=False)
        name = self._validate_name(data.get("name"))
        if self.db.peer(name):
            raise WgError("A peer named '{}' already exists".format(name))
        vpn_ip = (data.get("vpn_ip") or "").strip() or self.wg.next_ip()
        wanted_ip = vpn_ip.split("/")[0]
        if any(x["vpn_ip"].split("/")[0] == wanted_ip for x in self.db.peers()):
            raise WgError("VPN IP {} is already in use".format(vpn_ip))
        material = self.wg.generate_material(bool(data.get("use_psk", settings["use_psk"])))
        expiry_days = int(data.get("expiry_days", settings["default_expiry_days"]) or 0)
        quota_gb = float(data.get("quota_gb", settings["default_quota_gb"]) or 0)
        allowed = (data.get("allowed_ips") or "").strip()
        if not allowed:
            if data.get("full_tunnel", settings["default_full_tunnel"]):
                allowed = settings["default_allowed_ips"]
            else:
                allowed = str(self.wg.network())  # split tunnel: VPN LAN only
        peer = {
            "id": "p-" + secrets.token_hex(6),
            "pubkey": material["pubkey"],
            "name": name,
            "vpn_ip": vpn_ip,
            "privkey": material["privkey"],
            "psk": material["psk"],
            "created_at": int(time.time()),
            "expires_at": int(time.time()) + expiry_days * 86400 if expiry_days > 0 else 0,
            "quota_bytes": int(quota_gb * 1024 ** 3),
            "enabled": 1,
            "notes": (data.get("notes") or "")[:1000],
            "telegram_chat_id": str(data.get("telegram_chat_id") or "").strip(),
            "dns": (data.get("dns") or "").strip(),
            "allowed_ips": allowed,
            "mtu": int(data.get("mtu") or settings["default_mtu"] or 0),
            "keepalive": int(data.get("keepalive") or settings["default_keepalive"] or 0),
        }
        self.db.add_peer(peer)
        self.wg.write_conf()
        self.wg.apply_conf()
        self.db.add_event("peer_added", "Peer '{}' created ({})".format(name, vpn_ip),
                          peer["id"], name, {"endpoint": self.wg.endpoint()})
        self.db.add_audit(actor, "peer.add", "{} / {}".format(name, vpn_ip))
        if settings.get("notify_peer_changes"):
            self.notify("\u2795 New peer <b>{}</b>\nIP: <code>{}</code>\nExpires: {}".format(
                html.escape(name), html.escape(vpn_ip),
                time.strftime("%Y-%m-%d", time.localtime(peer["expires_at"])) if peer["expires_at"] else "never"),
                "info")
        return self.db.peer(peer["id"])

    def update_peer(self, ident: str, patch: dict, actor: str = "admin") -> dict:
        peer = self.db.peer(ident)
        if not peer:
            raise WgError("Peer not found")
        allowed = ("name", "vpn_ip", "notes", "telegram_chat_id", "dns",
                   "allowed_ips", "mtu", "keepalive", "quota_bytes", "expires_at", "enabled")
        clean = {}
        for key in allowed:
            if key not in patch:
                continue
            value = patch[key]
            if key == "name":
                value = self._validate_name(value)
                exists = self.db.peer(value)
                if exists and exists["id"] != peer["id"]:
                    raise WgError("Name already used")
            elif key in ("mtu", "keepalive", "quota_bytes", "expires_at", "enabled"):
                try:
                    value = int(value or 0)
                except (ValueError, TypeError):
                    raise WgError("{} must be a number".format(key))
            elif key == "vpn_ip":
                value = str(value).strip()
                clash = self.db.q1("SELECT id FROM peers WHERE vpn_ip=? AND id<>?",
                                   (value, peer["id"]))
                if clash:
                    raise WgError("VPN IP already in use")
            else:
                value = str(value or "")[:1000]
            clean[key] = value
        if "enabled" in clean and int(peer["enabled"]) != int(clean["enabled"]):
            return self.set_enabled(peer["id"], bool(clean["enabled"]), actor, clean)
        self.db.update_peer(peer["id"], clean)
        if any(k in clean for k in ("name", "vpn_ip")):
            self.wg.write_conf()
            self.wg.apply_conf()
        self.db.add_audit(actor, "peer.update", "{}: {}".format(peer["name"], json.dumps(clean)))
        return self.db.peer(peer["id"])

    def set_enabled(self, ident: str, enabled: bool, actor: str = "admin", extra: dict | None = None) -> dict:
        peer = self.db.peer(ident)
        if not peer:
            raise WgError("Peer not found")
        patch = {"enabled": 1 if enabled else 0,
                 "disabled_reason": "" if enabled else "disabled by {}".format(actor)}
        if extra:
            patch.update({k: v for k, v in extra.items() if k != "enabled"})
        self.db.update_peer(peer["id"], patch)
        self.wg.write_conf()
        self.wg.apply_conf()
        self.db.add_event("peer_enabled" if enabled else "peer_disabled",
                          "Peer '{}' {}".format(peer["name"], "enabled" if enabled else "disabled"),
                          peer["id"], peer["name"])
        self.db.add_audit(actor, "peer.enable" if enabled else "peer.disable", peer["name"])
        if self.db.settings().get("notify_peer_changes"):
            self.notify("{} Peer <b>{}</b> {}".format("\u2705" if enabled else "\u26D4",
                        html.escape(peer["name"]), "enabled" if enabled else "disabled"))
        return self.db.peer(peer["id"])

    def revoke_peer(self, ident: str, actor: str = "admin") -> dict:
        peer = self.db.peer(ident)
        if not peer:
            raise WgError("Peer not found")
        self.db.delete_peer(peer["id"])
        self.wg.write_conf()
        self.wg.apply_conf()
        self.db.add_event("peer_removed", "Peer '{}' removed".format(peer["name"]),
                          peer["id"], peer["name"])
        self.db.add_audit(actor, "peer.remove", "{} / {}".format(peer["name"], peer["vpn_ip"]))
        if self.db.settings().get("notify_peer_changes"):
            self.notify("\U0001F5D1 Peer <b>{}</b> removed".format(html.escape(peer["name"])))
        return peer

    def regenerate_keys(self, ident: str, actor: str = "admin") -> dict:
        peer = self.wg.regenerate_keys(ident)
        self.db.add_event("keys_rotated", "Keys regenerated for '{}'".format(peer["name"]),
                          peer["id"], peer["name"])
        self.db.add_audit(actor, "peer.rekey", peer["name"])
        return peer

    # ---------------- configs / sharing ----------------
    def client_config(self, ident: str) -> tuple:
        peer = self.db.peer(ident)
        if not peer:
            raise WgError("Peer not found")
        text = self.wg.client_config(peer)
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", peer["name"])
        return "{}.conf".format(safe), text

    def qr_png(self, ident: str) -> tuple:
        _, text = self.client_config(ident)
        return self.wg.qr_png(text), text

    def create_share(self, ident: str, actor: str = "admin", hours: int | None = None) -> dict:
        peer = self.db.peer(ident)
        if not peer:
            raise WgError("Peer not found")
        settings = self.db.settings()
        hours = int(hours or settings["share_link_hours"] or 24)
        token = self.db.create_share(peer["id"], hours=hours, max_uses=25, created_by=actor)
        self.db.add_audit(actor, "peer.share", "{} ({}h)".format(peer["name"], hours))
        url = (self.config.get("public_url") or "").rstrip("/") + "/s/" + token
        return {"token": token, "path": "/s/" + token, "url": url,
                "expires_at": int(time.time()) + hours * 3600}

    def backup_zip(self) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            try:
                zf.writestr("wg0.conf", self.wg.read_conf())
            except Exception:
                pass
            zf.writestr("settings.json", json.dumps(self.db.settings(include_secrets=False), indent=2))
            zf.writestr("peers.json", json.dumps(
                [{k: v for k, v in p.items() if k not in ("privkey", "psk")}
                 for p in self.db.peers()], indent=2))
            zf.writestr("events.json", json.dumps(self.db.events(1000), indent=2))
            for backup in self.wg.backups()[:5]:
                folder = self.config.get("backup_dir")
                try:
                    zf.write(os.path.join(folder, backup["name"]), "backups/" + backup["name"])
                except Exception:
                    pass
        return buf.getvalue()

    # ---------------- views ----------------
    def peer_view(self, p: dict) -> dict:
        now = int(time.time())
        settings = self.db.settings()
        timeout = int(settings["online_timeout"] or 180)
        online = bool(p["online"]) and p["last_handshake"] and (now - p["last_handshake"]) <= timeout * 2
        total = (p["total_rx"] or 0) + (p["total_tx"] or 0)
        status = "online" if online else "offline"
        if not p["enabled"]:
            status = "disabled"
        elif p["expires_at"] and p["expires_at"] < now:
            status = "expired"
        elif p["quota_bytes"] and total >= p["quota_bytes"]:
            status = "quota"
        days_left = max(0, (p["expires_at"] - now) // 86400) if p["expires_at"] else None
        return {
            **p,
            "online": online,
            "status": status,
            "rx": p["total_rx"] or 0, "tx": p["total_tx"] or 0, "total": total,
            "rx_h": human_bytes(p["total_rx"]), "tx_h": human_bytes(p["total_tx"]),
            "total_h": human_bytes(total),
            "quota_h": human_bytes(p["quota_bytes"]) if p["quota_bytes"] else "Unlimited",
            "quota_pct": min(100, round(total / p["quota_bytes"] * 100, 1)) if p["quota_bytes"] else 0,
            "days_left": days_left,
            "expires_h": time.strftime("%Y-%m-%d", time.localtime(p["expires_at"])) if p["expires_at"] else "Never",
            "created_h": time.strftime("%Y-%m-%d %H:%M", time.localtime(p["created_at"])),
            "last_seen_h": human_duration(now - p["last_seen"]) if p["last_seen"] else "Never",
            "handshake_h": human_duration(now - p["last_handshake"]) if p["last_handshake"] else "Never",
            "flag": flag_emoji(p["country_code"]),
            "has_key": bool(p["privkey"]),
            "country_display": p["country"] or "Unknown",
        }

    def state(self) -> dict:
        if self.monitor:
            self.monitor.tick()
        now = int(time.time())
        settings = self.db.settings()
        peers = [self.peer_view(p) for p in self.db.peers()]
        online = [p for p in peers if p["online"]]
        midnight = int(time.mktime(time.strptime(time.strftime("%Y-%m-%d"), "%Y-%m-%d")))
        today = self.db.q1("SELECT COALESCE(SUM(rx),0) AS rx, COALESCE(SUM(tx),0) AS tx "
                           "FROM samples WHERE ts>=?", (midnight,)) or {"rx": 0, "tx": 0}
        total_rx = sum(p["rx"] for p in peers)
        total_tx = sum(p["tx"] for p in peers)
        series = self.db.traffic_series(now - 86400, bucket=3600)
        return {
            "version": VERSION,
            "time": now,
            "uptime": now - self.started_at,
            "demo": bool(self.config.get("demo")),
            "server": self.server_info(),
            "peers": peers,
            "stats": {
                "total_peers": len(peers),
                "online": len(online),
                "offline": len(peers) - len(online),
                "disabled": len([p for p in peers if not p["enabled"]]),
                "total_rx": total_rx, "total_tx": total_tx,
                "total_traffic": total_rx + total_tx,
                "total_traffic_h": human_bytes(total_rx + total_tx),
                "today_rx": today["rx"] or 0, "today_tx": today["tx"] or 0,
                "today_traffic": (today["rx"] or 0) + (today["tx"] or 0),
                "today_traffic_h": human_bytes((today["rx"] or 0) + (today["tx"] or 0)),
                "countries": len(set(p["country_code"] for p in online if p["country_code"])),
            },
            "traffic": series,
            "events": self.db.events(25),
            "settings": settings,
            "bot": self.bot.status() if self.bot else {"enabled": False, "running": False},
            "backups": self.wg.backups()[:12],
            "audit": self.db.audit(25),
            "network": str(self.wg.network()),
            "endpoint": self.wg.endpoint(),
            "services_running": {
                "monitor": bool(self.monitor and self.monitor.is_alive()),
                "telegram": bool(self.bot and self.bot.is_alive()),
            },
        }
