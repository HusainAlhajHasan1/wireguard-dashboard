"""Telegram control bot (long polling, no extra dependencies).

Commands: /start /help /status /peers /add /remove /conf /qr /usage /link
/send /backup /restart /whoami /settings.  Inline buttons provide the same
actions.  Connect/disconnect, quota, expiry and daily reports are pushed to
all whitelisted admin chats.
"""
from __future__ import annotations

import html
import threading
import time
from urllib.parse import urlencode

from . import net
from .core import human_bytes, human_duration

HELP = (
    "\U0001F6E1 <b>WireGuard Dashboard bot</b>\n\n"
    "/status \u2014 server + live peers\n"
    "/peers \u2014 list peers with action buttons\n"
    "/add &lt;name&gt; [days] [quotaGB] \u2014 create a peer\n"
    "/conf &lt;name&gt; \u2014 send .conf file\n"
    "/qr &lt;name&gt; \u2014 send QR code\n"
    "/usage &lt;name&gt; \u2014 traffic and connection info\n"
    "/link &lt;name&gt; \u2014 one-time share link\n"
    "/send &lt;name&gt; &lt;chat_id&gt; \u2014 send config to a user\n"
    "/remove &lt;name&gt; \u2014 revoke a peer\n"
    "/backup \u2014 download config backup\n"
    "/restart \u2014 restart the WireGuard interface\n"
    "/settings /whoami /help"
)


class TelegramBot(threading.Thread):
    def __init__(self, core):
        super().__init__(name="wgdash-telegram", daemon=True)
        self.core = core
        self.db = core.db
        self.stop_event = threading.Event()
        self.offset = self.db.meta("telegram_offset", 0)
        self.username = ""
        self.last_error = ""
        self.last_update = 0
        self.backoff = 1

    # ---------------- transport ----------------
    @property
    def token(self):
        return self.db.get_secret("telegram_token")

    @property
    def admins(self):
        raw = self.db.settings().get("telegram_admins") or []
        return [str(x).strip() for x in raw if str(x).strip()]

    def _url(self, method):
        return "https://api.telegram.org/bot{}/{}".format(self.token, method)

    def api(self, method, fields=None, files=(), timeout=35):
        if not self.token:
            return {"ok": False, "description": "no token"}
        fields = {k: v for k, v in (fields or {}).items() if v is not None}
        try:
            if files:
                return net.post_form(self._url(method), fields, files, timeout=timeout)
            if method in ("getUpdates", "getMe"):
                query = urlencode({k: str(v) for k, v in fields.items()})
                return net.get_json(self._url(method) + ("?" + query if query else ""), timeout=timeout)
            return net.post_json(self._url(method), fields, timeout=timeout)
        except Exception as exc:
            self.last_error = str(exc)[:200]
            return {"ok": False, "description": self.last_error}

    def send(self, chat_id, text, markup=None, parse_html=True):
        fields = {"chat_id": chat_id, "text": text, "disable_web_page_preview": True}
        if parse_html:
            fields["parse_mode"] = "HTML"
        if markup:
            fields["reply_markup"] = markup
        return self.api("sendMessage", fields)

    def send_document(self, chat_id, filename, content, caption="", markup=None, mime="text/plain"):
        fields = {"chat_id": chat_id, "caption": caption[:1000], "parse_mode": "HTML"}
        if markup:
            fields["reply_markup"] = markup
        return self.api("sendDocument", fields,
                        files=[("document", filename, content, mime)])

    def send_photo(self, chat_id, filename, content, caption="", markup=None):
        fields = {"chat_id": chat_id, "caption": caption[:1000], "parse_mode": "HTML"}
        if markup:
            fields["reply_markup"] = markup
        return self.api("sendPhoto", fields, files=[("photo", filename, content, "image/png")])

    def notify(self, text, level="info"):
        if not self.token or not self.admins:
            return
        prefix = {"warning": "\u26A0 ", "error": "\u2757 ", "report": "\U0001F4CA "}.get(level, "")
        for chat_id in self.admins:
            self.send(chat_id, prefix + text)

    def status(self):
        return {
            "enabled": bool(self.token),
            "running": self.is_alive(),
            "username": self.username,
            "admins": self.admins,
            "last_error": self.last_error,
            "last_update": self.last_update,
        }

    def test(self, chat_id=None):
        if not self.token:
            return False, "No bot token configured"
        targets = [str(chat_id)] if chat_id else self.admins
        if not targets:
            return False, "No admin chat ID configured"
        ok = self.send(targets[0], "\u2705 <b>WireGuard Dashboard</b>\nBot connection works. "
                       "Server: <code>{}</code>".format(html.escape(self.core.wg.server_info()["hostname"])))
        return bool(ok.get("ok")), (ok.get("description") if not ok.get("ok") else "Message sent")

    # ---------------- loop ----------------
    def run(self):
        while not self.stop_event.is_set():
            if not self.token:
                self.stop_event.wait(5)
                continue
            if not self.username:
                me = self.api("getMe", timeout=10)
                if me.get("ok"):
                    self.username = (me.get("result") or {}).get("username", "")
            try:
                result = self.api("getUpdates", {"offset": self.offset + 1, "timeout": 20,
                                                 "allowed_updates": '["message","callback_query"]'})
                if not result.get("ok"):
                    self.last_error = str(result.get("description", "unknown error"))[:200]
                    self.stop_event.wait(min(30, self.backoff))
                    self.backoff = min(30, self.backoff * 2)
                    continue
                self.backoff = 1
                for update in result.get("result", []):
                    self.offset = max(self.offset, int(update.get("update_id", 0)))
                    self.db.set_meta("telegram_offset", self.offset)
                    try:
                        if "callback_query" in update:
                            self.handle_callback(update["callback_query"])
                        elif "message" in update:
                            self.handle_message(update["message"])
                    except Exception as exc:
                        self.last_error = "handler: {}".format(exc)[:200]
                self.last_update = int(time.time())
            except Exception as exc:
                self.last_error = str(exc)[:200]
                self.stop_event.wait(5)
        # fallthrough

    def stop(self):
        self.stop_event.set()

    def reload(self):
        """Called after the token/admin list changes in the UI."""
        self.username = ""
        self.backoff = 1

    # ---------------- helpers ----------------
    def _chat_id(self, msg):
        return str(msg["chat"]["id"])

    def _authorized(self, chat_id) -> bool:
        if str(chat_id) in self.admins:
            return True
        self.send(chat_id,
                  "\U0001F512 This bot is restricted.\nYour chat ID: <code>{}</code>\n"
                  "Add it under <b>Dashboard \u2192 Telegram \u2192 Admin chat IDs</b>.".format(chat_id))
        return False

    def _find_peer(self, name):
        return self.db.peer((name or "").strip())

    def _peer_buttons(self, peer):
        return {"inline_keyboard": [[
            {"text": "\U0001F4C4 Config", "callback_data": "conf:" + peer["id"]},
            {"text": "\U0001F4F1 QR", "callback_data": "qr:" + peer["id"]},
            {"text": "\U0001F4CA Usage", "callback_data": "usage:" + peer["id"]},
        ], [
            {"text": "\u23F8 Disable" if peer["enabled"] else "\u25B6 Enable",
             "callback_data": "toggle:" + peer["id"]},
            {"text": "\U0001F517 Link", "callback_data": "link:" + peer["id"]},
            {"text": "\U0001F5D1 Remove", "callback_data": "del:" + peer["id"]},
        ]]}

    def _send_config(self, chat_id, peer):
        try:
            filename, text = self.core.client_config(peer["id"])
            png, _ = self.core.qr_png(peer["id"])
            caption = ("\U0001F4C4 <b>{}</b>\n<code>{}</code>\nEndpoint: <code>{}</code>".format(
                html.escape(peer["name"]), html.escape(peer["vpn_ip"]),
                html.escape(self.core.wg.endpoint())))
            self.send_document(chat_id, filename, text.encode(), caption)
            self.send_photo(chat_id, "wg-{}-qr.png".format(peer["name"]), png,
                            "Scan with the WireGuard app \u2192 <b>{}</b>".format(html.escape(peer["name"])))
            self.db.add_audit("telegram", "peer.send", "{} -> {}".format(peer["name"], chat_id))
            return True
        except Exception as exc:
            self.send(chat_id, "\u274C {}".format(html.escape(str(exc))))
            return False

    # ---------------- commands ----------------
    def handle_message(self, msg):
        chat_id = self._chat_id(msg)
        text = (msg.get("text") or "").strip()
        if not text.startswith("/"):
            return
        parts = text.split()
        command = parts[0].split("@")[0].lower()
        args = parts[1:]
        if command in ("/start", "/help"):
            if self._authorized(chat_id):
                self.send(chat_id, HELP)
            return
        if command == "/whoami":
            self.send(chat_id, "Your chat ID: <code>{}</code>\nAdmin: {}".format(
                chat_id, "yes" if str(chat_id) in self.admins else "no"))
            return
        if not self._authorized(chat_id):
            return
        user = (msg.get("from") or {}).get("username") or chat_id
        actor = "telegram:{}".format(user)
        try:
            self.dispatch(chat_id, command, args, actor)
        except Exception as exc:
            self.send(chat_id, "\u274C <b>Error:</b> {}".format(html.escape(str(exc))))

    def dispatch(self, chat_id, command, args, actor):
        if command in ("/status", "/s"):
            s = self.core.state()
            st = s["stats"]
            srv = s["server"]
            online = [p for p in s["peers"] if p["online"]]
            text = ["\U0001F7E2 <b>Server status</b>",
                    "Interface: <code>{}</code> ({})".format(html.escape(srv["interface"]),
                                                             "up" if srv["active"] else "down"),
                    "Endpoint: <code>{}</code>".format(html.escape(s["endpoint"])),
                    "Peers: {} total, {} online".format(st["total_peers"], st["online"]),
                    "Traffic today: {}".format(html.escape(st["today_traffic_h"])),
                    "All time: {}".format(html.escape(st["total_traffic_h"]))]
            if online:
                text.append("\nOnline now:")
                for p in online:
                    text.append("\u2022 {} {} \u2014 {} {}".format(
                        p["flag"], html.escape(p["name"]), html.escape(p["vpn_ip"]),
                        html.escape(p["country"] or "")))
            self.send(chat_id, "\n".join(text))
        elif command in ("/peers", "/users", "/list"):
            peers = self.db.peers()
            if not peers:
                self.send(chat_id, "No peers yet. Create one with <code>/add name</code>.")
                return
            for p in peers:
                view = self.core.peer_view(p)
                icon = {"online": "\U0001F7E2", "offline": "\u26AA", "disabled": "\u26D4",
                        "expired": "\u23F0", "quota": "\U0001F6D1"}.get(view["status"], "\u26AA")
                text = ("{} <b>{}</b> <code>{}</code>\n{} \u2014 {} \u2193 / {} \u2191\nLast seen: {}".format(
                    icon, html.escape(p["name"]), html.escape(p["vpn_ip"]),
                    html.escape(view["status"].upper()), html.escape(view["rx_h"]),
                    html.escape(view["tx_h"]), html.escape(view["last_seen_h"])))
                self.send(chat_id, text, markup=self._peer_buttons(p))
        elif command in ("/add", "/new"):
            if not args:
                self.send(chat_id, "Usage: <code>/add phone 30 50</code> (name, days, quota GB)")
                return
            data = {"name": args[0]}
            if len(args) > 1:
                data["expiry_days"] = args[1]
            if len(args) > 2:
                data["quota_gb"] = args[2]
            peer = self.core.add_peer(data, actor=actor)
            self.send(chat_id, "\u2705 Peer <b>{}</b> created with IP <code>{}</code>".format(
                html.escape(peer["name"]), html.escape(peer["vpn_ip"])))
            self._send_config(chat_id, peer)
        elif command in ("/conf", "/config", "/qr", "/usage", "/link", "/remove", "/delete"):
            if not args:
                self.send(chat_id, "Usage: <code>{} &lt;name&gt;</code>".format(command))
                return
            peer = self._find_peer(args[0])
            if not peer:
                self.send(chat_id, "\u2753 Peer '{}' not found".format(html.escape(args[0])))
                return
            if command in ("/conf", "/config"):
                self._send_config(chat_id, peer)
            elif command == "/qr":
                png, _ = self.core.qr_png(peer["id"])
                self.send_photo(chat_id, "wg-{}-qr.png".format(peer["name"]), png,
                                "\U0001F4F1 <b>{}</b>".format(html.escape(peer["name"])))
            elif command == "/usage":
                v = self.core.peer_view(peer)
                text = ("\U0001F4CA <b>{name}</b>\nStatus: {status}\nIP: <code>{ip}</code>\n"
                        "Location: {flag} {country} {city}\nSource IP: <code>{src}</code>\n"
                        "ISP: {isp}\nDownload: {rx}\nUpload: {tx}\nTotal: {total} / {quota}\n"
                        "Last seen: {seen}\nExpires: {exp}").format(
                    name=html.escape(v["name"]), status=v["status"], ip=v["vpn_ip"],
                    flag=v["flag"], country=html.escape(v["country"] or "Unknown"),
                    city=html.escape(v["city"] or ""), src=html.escape(v["last_ip"] or "-"),
                    isp=html.escape(v["isp"] or "-"), rx=v["rx_h"], tx=v["tx_h"],
                    total=v["total_h"], quota=v["quota_h"], seen=v["last_seen_h"], exp=v["expires_h"])
                self.send(chat_id, text, markup=self._peer_buttons(peer))
            elif command == "/link":
                share = self.core.create_share(peer["id"], actor=actor)
                self.send(chat_id, "\U0001F517 Share link for <b>{}</b> (expires in 24h):\n{}".format(
                    html.escape(peer["name"]), html.escape(share["url"] or share["path"])))
            else:
                self.send(chat_id, "Revoke <b>{}</b>?".format(html.escape(peer["name"])),
                          markup={"inline_keyboard": [[
                              {"text": "\u2705 Yes, remove", "callback_data": "delok:" + peer["id"]},
                              {"text": "\u274C Cancel", "callback_data": "cancel"}]]})
        elif command in ("/send", "/share"):
            if len(args) < 2:
                self.send(chat_id, "Usage: <code>/send name chat_id</code>")
                return
            peer = self._find_peer(args[0])
            if not peer:
                self.send(chat_id, "\u2753 Peer not found")
                return
            target = args[1]
            fields = {"chat_id": target, "caption": "WireGuard config for {}".format(peer["name"])}
            filename, text = self.core.client_config(peer["id"])
            ok = self.api("sendDocument", fields,
                          files=[("document", filename, text.encode(), "text/plain")])
            if ok.get("ok"):
                self.send(chat_id, "\u2705 Sent config for <b>{}</b> to <code>{}</code>".format(
                    html.escape(peer["name"]), html.escape(target)))
            else:
                self.send(chat_id, "\u274C Could not send: {}".format(
                    html.escape(str(ok.get("description", "unknown")))))
        elif command == "/backup":
            data = self.core.backup_zip()
            self.api("sendDocument", {"chat_id": chat_id, "caption": "WireGuard backup"},
                     files=[("document", "wireguard-backup.zip", data, "application/zip")])
        elif command == "/restart":
            ok, output = self.core.wg.restart()
            self.send(chat_id, ("\u2705 WireGuard restarted" if ok else "\u274C Restart failed: {}").format(
                html.escape(output[:300])))
            self.db.add_audit(actor, "server.restart", "telegram")
        elif command == "/settings":
            s = self.db.settings()
            self.send(chat_id, "\u2699 <b>Settings</b>\nOnline timeout: {}s\nSample: {}s\n"
                      "Default DNS: <code>{}</code>\nAllowedIPs: <code>{}</code>\n"
                      "Quota enforcement: {}\nEndpoint: <code>{}</code>".format(
                          s["online_timeout"], s["sample_interval"],
                          html.escape(str(s["default_dns"])), html.escape(str(s["default_allowed_ips"])),
                          s["enforce_quota"], html.escape(self.core.wg.endpoint())))
        else:
            self.send(chat_id, "Unknown command. Use /help")

    # ---------------- inline buttons ----------------
    def handle_callback(self, cb):
        chat_id = str(cb["message"]["chat"]["id"]) if cb.get("message") else str(cb["from"]["id"])
        data = cb.get("data", "")
        self.api("answerCallbackQuery", {"callback_query_id": cb["id"], "text": "Working..."})
        if not self._authorized(chat_id):
            return
        action, _, peer_id = data.partition(":")
        if action == "cancel":
            self.api("editMessageText", {"chat_id": chat_id, "message_id": cb["message"]["message_id"],
                                         "text": "Cancelled."})
            return
        peer = self.db.peer(peer_id) if peer_id else None
        if not peer:
            self.send(chat_id, "\u2753 Peer not found or already removed")
            return
        actor = "telegram:{}".format((cb.get("from") or {}).get("username") or chat_id)
        if action == "conf":
            self._send_config(chat_id, peer)
        elif action == "qr":
            png, _ = self.core.qr_png(peer["id"])
            self.send_photo(chat_id, "wg-{}-qr.png".format(peer["name"]), png,
                            "\U0001F4F1 <b>{}</b>".format(html.escape(peer["name"])))
        elif action == "usage":
            v = self.core.peer_view(peer)
            self.send(chat_id, "<b>{}</b>: {} \u2193 / {} \u2191 / {} total\n{} {}".format(
                html.escape(v["name"]), v["rx_h"], v["tx_h"], v["total_h"],
                v["flag"], html.escape(v["country"] or "Unknown")))
        elif action == "link":
            share = self.core.create_share(peer["id"], actor=actor)
            self.send(chat_id, "\U0001F517 <b>{}</b>: {}".format(
                html.escape(peer["name"]), html.escape(share["url"] or share["path"])))
        elif action == "del":
            self.send(chat_id, "Revoke <b>{}</b>?".format(html.escape(peer["name"])),
                      markup={"inline_keyboard": [[
                          {"text": "\u2705 Yes, remove", "callback_data": "delok:" + peer["id"]},
                          {"text": "\u274C Cancel", "callback_data": "cancel"}]]})
        elif action == "delok":
            self.core.revoke_peer(peer["id"], actor=actor)
            self.send(chat_id, "\U0001F5D1 Removed <b>{}</b>".format(html.escape(peer["name"])))
        elif action == "toggle":
            self.core.set_enabled(peer["id"], not bool(peer["enabled"]), actor=actor)
            self.send(chat_id, "\u2705 <b>{}</b> {}".format(
                html.escape(peer["name"]), "disabled" if peer["enabled"] else "enabled"))
