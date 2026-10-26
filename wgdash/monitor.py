"""Background sampler: live status, traffic accounting, events and enforcement."""
from __future__ import annotations

import html
import threading
import time

from . import geoip
from .core import human_bytes, human_duration
from .wireguard import parse_endpoint


class Monitor(threading.Thread):
    def __init__(self, core):
        super().__init__(name="wgdash-monitor", daemon=True)
        self.core = core
        self.db = core.db
        self.wg = core.wg
        self.stop_event = threading.Event()
        self.last_tick = 0
        self.last_sample = 0
        self.last_prune = 0
        self.last_daily = ""

    def run(self):
        # Give the web server / bot a moment to come up.
        self.stop_event.wait(1)
        self.tick(force=True)
        while not self.stop_event.wait(5):
            try:
                self.tick()
            except Exception as exc:
                self.db.add_event("warning", "Monitor error: {}".format(exc), detail={"error": str(exc)})

    def stop(self):
        self.stop_event.set()

    # ------------------------------------------------------------------
    def tick(self, force: bool = False):
        now = int(time.time())
        if not force and now - self.last_tick < 5:
            return
        self.last_tick = now
        settings = self.db.settings()
        timeout = int(settings["online_timeout"] or 180)
        runtime = self.wg.status()
        record = force or (now - self.last_sample >= int(settings["sample_interval"] or 30))
        if record:
            self.last_sample = now

        changed_conf = False
        for peer in self.db.peers():
            if not peer["enabled"]:
                continue
            rt = runtime.get(peer["pubkey"])
            patch = {}
            handshake = int(rt["handshake"]) if rt else 0
            if handshake and handshake > (peer["last_handshake"] or 0):
                patch["last_handshake"] = handshake
                patch["last_seen"] = handshake
            was_online = bool(peer["online"])
            online = bool(rt and handshake and (now - handshake) <= timeout)

            if rt:
                # `wg` counters reset when the interface restarts. Treat a
                # decrease as a fresh session and keep the historic totals.
                for field, runtime_key in (("rx", "rx"), ("tx", "tx")):
                    current = int(rt[runtime_key])
                    previous = int(peer["last_" + field] or 0)
                    delta = current - previous if current >= previous else current
                    if delta > 0:
                        patch["total_" + field] = int(peer["total_" + field] or 0) + delta
                    patch["last_" + field] = current

                ip, _port = parse_endpoint(rt["endpoint"])
                if ip and ip != peer["last_ip"]:
                    info = geoip.lookup(ip, self.db, settings, bool(self.core.config.get("demo")))
                    patch.update({
                        "last_ip": ip, "last_endpoint": rt["endpoint"],
                        "country": info.get("country", ""),
                        "country_code": info.get("country_code", ""),
                        "city": info.get("city", ""), "isp": info.get("isp", ""),
                    })
                elif rt["endpoint"] != peer["last_endpoint"]:
                    patch["last_endpoint"] = rt["endpoint"]
            if online != was_online:
                patch["online"] = 1 if online else 0
                if online:
                    msg = "{} connected from {} {}".format(
                        peer["name"], patch.get("country") or peer["country"] or "unknown",
                        patch.get("last_ip") or peer["last_ip"] or "")
                    self.db.add_event("connect", msg, peer["id"], peer["name"],
                                      {"ip": patch.get("last_ip") or peer["last_ip"],
                                       "country": patch.get("country") or peer["country"]})
                    if settings.get("notify_connect"):
                        self.core.notify(
                            "\U0001F7E2 <b>{}</b> connected\n{} {}\nIP: <code>{}</code>".format(
                                html.escape(peer["name"]),
                                (patch.get("country") or peer["country"] or "Unknown"),
                                self._flag(patch.get("country_code") or peer["country_code"]),
                                html.escape(patch.get("last_ip") or peer["last_ip"] or "?")), "connect")
                else:
                    seen = patch.get("last_seen") or peer["last_seen"] or now
                    self.db.add_event("disconnect", "{} disconnected (session {})".format(
                        peer["name"], human_duration(now - seen)), peer["id"], peer["name"])
                    if settings.get("notify_disconnect"):
                        self.core.notify("\U0001F534 <b>{}</b> disconnected".format(
                            html.escape(peer["name"])), "disconnect")
            if patch:
                self.db.update_peer(peer["id"], patch)
            if record:
                updated = self.db.peer(peer["id"])
                self.db.add_sample(now, peer["id"],
                                   max(0, (updated["total_rx"] or 0) - (peer["total_rx"] or 0)),
                                   max(0, (updated["total_tx"] or 0) - (peer["total_tx"] or 0)),
                                   updated["total_rx"], updated["total_tx"], online)

            # Enforce quota / expiry.
            updated = self.db.peer(peer["id"])
            total = (updated["total_rx"] or 0) + (updated["total_tx"] or 0)
            reason = ""
            if settings.get("enforce_quota") and updated["quota_bytes"] and total >= updated["quota_bytes"]:
                reason = "traffic quota reached ({})".format(human_bytes(updated["quota_bytes"]))
            elif settings.get("enforce_expiry") and updated["expires_at"] and updated["expires_at"] <= now:
                reason = "expired on {}".format(time.strftime("%Y-%m-%d", time.localtime(updated["expires_at"])))
            elif (settings.get("notify_expiry") and updated["expires_at"]
                  and 0 < updated["expires_at"] - now <= 86400
                  and not self.db.meta("expiry_warned_" + peer["id"])):
                self.db.set_meta("expiry_warned_" + peer["id"], True)
                self.core.notify("\u23F0 Peer <b>{}</b> expires within 24 hours".format(
                    html.escape(peer["name"])), "warning")
            if reason:
                self.db.update_peer(peer["id"], {"enabled": 0, "online": 0, "disabled_reason": reason})
                changed_conf = True
                self.db.add_event("peer_blocked", "Peer '{}' disabled: {}".format(peer["name"], reason),
                                  peer["id"], peer["name"])
                self.db.add_audit("system", "peer.auto-disable", "{}: {}".format(peer["name"], reason))
                if settings.get("notify_quota"):
                    self.core.notify("\u26A0 Peer <b>{}</b> disabled: {}".format(
                        html.escape(peer["name"]), html.escape(reason)), "warning")

        if changed_conf:
            self.wg.write_conf()
            self.wg.apply_conf()

        # Daily report.
        if settings.get("notify_daily"):
            stamp = time.strftime("%Y-%m-%d %H:%M")
            target = settings.get("daily_report_time", "09:00")
            if (stamp.split()[1][:5] >= target and self.db.meta("last_daily") != stamp.split()[0]):
                self.db.set_meta("last_daily", stamp.split()[0])
                self.send_daily_report()

        # Cleanup once a day.
        if now - self.last_prune > 86400:
            self.last_prune = now
            self.db.prune(int(settings.get("history_days") or 90))

    def _flag(self, code):
        from .wireguard import flag_emoji
        return flag_emoji(code or "")

    def send_daily_report(self):
        peers = self.db.peers()
        midnight = int(time.mktime(time.strptime(time.strftime("%Y-%m-%d"), "%Y-%m-%d")))
        row = self.db.q1("SELECT COALESCE(SUM(rx),0) AS rx, COALESCE(SUM(tx),0) AS tx "
                         "FROM samples WHERE ts>=?", (midnight,)) or {"rx": 0, "tx": 0}
        online = [p for p in peers if p["online"]]
        lines = [
            "\U0001F4CA <b>Daily WireGuard report</b>",
            "Peers: {} total / {} online now".format(len(peers), len(online)),
            "Traffic today: \u2B07 {} / \u2B06 {}".format(human_bytes(row["rx"]), human_bytes(row["tx"])),
        ]
        top = sorted(peers, key=lambda p: (p["total_rx"] or 0) + (p["total_tx"] or 0), reverse=True)[:5]
        if top:
            lines.append("\nTop users (all time):")
            for p in top:
                lines.append("\u2022 {} \u2014 {}".format(html.escape(p["name"]),
                             human_bytes((p["total_rx"] or 0) + (p["total_tx"] or 0))))
        self.core.notify("\n".join(lines), "report")
