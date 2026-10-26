"""Command line control: wgdash <command> [options]."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

from . import crypto
from .server import build


def out(data, as_json=False):
    if as_json:
        print(json.dumps(data, indent=2, default=str))
    elif isinstance(data, (dict, list)):
        print(json.dumps(data, indent=2, default=str))
    else:
        print(data)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="wgdash", description="WireGuard Dashboard control CLI")
    parser.add_argument("--config", default=None, help="config.json path")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("serve", help="run the web server")

    p = sub.add_parser("init-admin", help="create the first admin account")
    p.add_argument("-u", "--username", required=True)
    p.add_argument("-p", "--password", required=True)

    p = sub.add_parser("passwd", help="change an admin password")
    p.add_argument("-u", "--username", required=True)
    p.add_argument("-p", "--password", required=True)

    sub.add_parser("status", help="server + peer status")
    sub.add_parser("list", help="list peers")
    sub.add_parser("settings", help="show settings")
    p = sub.add_parser("set-setting", help="set one setting (JSON or plain value)")
    p.add_argument("key")
    p.add_argument("value")

    p = sub.add_parser("add", help="create a peer")
    p.add_argument("name")
    p.add_argument("--ip", default=None, help="VPN IP (default: next free)")
    p.add_argument("--days", type=int, default=None, help="expiry in days, 0 = never")
    p.add_argument("--quota", type=float, default=None, help="traffic quota in GB, 0 = unlimited")
    p.add_argument("--dns", default=None)
    p.add_argument("--allowed-ips", default=None)
    p.add_argument("--mtu", type=int, default=None)
    p.add_argument("--keepalive", type=int, default=None)
    p.add_argument("--split", action="store_true", help="only route VPN subnet (split tunnel)")
    p.add_argument("--no-psk", action="store_true")
    p.add_argument("--telegram", default=None, help="Telegram chat ID for this user")
    p.add_argument("--notes", default="")

    for name in ("remove", "enable", "disable", "config", "qr", "rekey", "share", "usage"):
        p = sub.add_parser(name, help=name + " a peer")
        p.add_argument("name")
        if name == "remove":
            p.add_argument("-y", "--yes", action="store_true")
        if name == "qr":
            p.add_argument("--out", default=None)
            p.add_argument("--terminal", action="store_true")
    p = sub.add_parser("send", help="send a peer config to a Telegram chat")
    p.add_argument("name")
    p.add_argument("chat_id")

    sub.add_parser("sync", help="import peers from wg0.conf")
    sub.add_parser("restart", help="restart the wg-quick interface")
    sub.add_parser("rotate-server-keys", help="rotate the SERVER keypair (clients must re-download)")
    sub.add_parser("backup", help="back up wg0.conf")
    sub.add_parser("backups", help="list backups")
    p = sub.add_parser("restore", help="restore a config backup")
    p.add_argument("name")
    p = sub.add_parser("token", help="create an API token")
    p.add_argument("name", nargs="?", default="automation")
    sub.add_parser("detect", help="auto-detect public endpoint and local DNS")
    sub.add_parser("demo-init", help="seed a demo database (DEMO MODE ONLY)")
    sub.add_parser("version", help="print version")

    args = parser.parse_args(argv)
    if args.cmd == "version":
        from .core import VERSION
        out(VERSION, args.json)
        return 0

    app, core = build(args.config)
    db, wg = core.db, core.wg
    actor = "cli"

    if args.cmd == "serve":
        from .server import main as serve_main
        serve_main(["--config", core.config.path] + (["--host", os.environ["WGDASH_HOST"]]
                   if "WGDASH_HOST" in os.environ else []))
        return 0
    if args.cmd == "init-admin":
        if len(args.password) < 10:
            print("Password must be at least 10 characters", file=sys.stderr)
            return 2
        existing = db.admin(args.username)
        if existing:
            db.update_admin(existing["id"], {"password_hash": crypto.hash_password(args.password)})
        else:
            db.create_admin(args.username, crypto.hash_password(args.password))
        out({"ok": True, "username": args.username}, args.json)
        return 0
    if args.cmd == "passwd":
        admin = db.admin(args.username)
        if not admin:
            print("No such admin", file=sys.stderr)
            return 2
        db.update_admin(admin["id"], {"password_hash": crypto.hash_password(args.password)})
        out({"ok": True}, args.json)
        return 0
    if args.cmd == "status":
        state = core.state()
        out({
            "server": {k: state["server"][k] for k in
                       ("interface", "active", "listen_port", "address", "public_key", "endpoint")},
            "stats": state["stats"],
            "bot": state["bot"], "version": state["version"],
        }, args.json)
        return 0
    if args.cmd == "list":
        rows = []
        for p in db.peers():
            v = core.peer_view(p)
            rows.append({k: v[k] for k in ("name", "vpn_ip", "status", "country", "last_ip",
                                           "rx_h", "tx_h", "total_h", "last_seen_h", "expires_h", "quota_h")})
        out(rows, args.json)
        return 0
    if args.cmd == "settings":
        s = db.settings()
        out(s, args.json)
        return 0
    if args.cmd == "set-setting":
        try:
            value = json.loads(args.value)
        except Exception:
            value = args.value
        out(db.set_settings({args.key: value}), args.json)
        return 0
    if args.cmd == "add":
        data = {"name": args.name}
        for src, dst in (("ip", "vpn_ip"), ("days", "expiry_days"), ("quota", "quota_gb"),
                         ("dns", "dns"), ("allowed_ips", "allowed_ips"), ("mtu", "mtu"),
                         ("keepalive", "keepalive"), ("telegram", "telegram_chat_id"),
                         ("notes", "notes")):
            val = getattr(args, src)
            if val is not None:
                data[dst] = val
        if args.split:
            data["full_tunnel"] = False
        if args.no_psk:
            data["use_psk"] = False
        peer = core.add_peer(data, actor)
        out({"ok": True, "peer": core.peer_view(peer),
             "config": wg.client_config(peer)}, args.json)
        return 0
    if args.cmd in ("remove", "enable", "disable", "config", "qr", "rekey", "share", "usage"):
        peer = db.peer(args.name)
        if not peer:
            print("Peer not found: {}".format(args.name), file=sys.stderr)
            return 2
        if args.cmd == "remove":
            if not args.yes:
                print("Refusing to remove without --yes", file=sys.stderr)
                return 2
            gone = core.revoke_peer(peer["id"], actor)
            out({"ok": True, "removed": gone["name"]}, args.json)
        elif args.cmd == "enable":
            out({"ok": True, "peer": core.peer_view(core.set_enabled(peer["id"], True, actor))}, args.json)
        elif args.cmd == "disable":
            out({"ok": True, "peer": core.peer_view(core.set_enabled(peer["id"], False, actor))}, args.json)
        elif args.cmd == "config":
            _, text = core.client_config(peer["id"])
            print(text) if not args.json else out({"config": text}, True)
        elif args.cmd == "qr":
            _, text = core.client_config(peer["id"])
            if args.terminal:
                import segno
                segno.make(text, micro=False).terminal(out=sys.stdout, compact=True)
            else:
                dest = args.out or "{}.png".format(peer["name"])
                with open(dest, "wb") as fh:
                    fh.write(wg.qr_png(text))
                out({"ok": True, "file": dest}, args.json)
        elif args.cmd == "rekey":
            out({"ok": True, "peer": core.peer_view(core.regenerate_keys(peer["id"], actor))}, args.json)
        elif args.cmd == "share":
            out({"ok": True, "share": core.create_share(peer["id"], actor)}, args.json)
        elif args.cmd == "usage":
            v = core.peer_view(peer)
            out({"peer": v, "events": db.events(20, peer["id"]),
                 "samples": db.peer_samples(peer["id"], int(time.time()) - 86400)}, args.json)
        return 0
    if args.cmd == "send":
        peer = db.peer(args.name)
        if not peer:
            print("Peer not found", file=sys.stderr)
            return 2
        core.start_services()
        filename, text = core.client_config(peer["id"])
        ok = core.bot.send_document(args.chat_id, filename, text.encode(),
                                    "WireGuard config for {}".format(peer["name"]))
        if ok.get("ok"):
            png, _ = core.qr_png(peer["id"])
            core.bot.send_photo(args.chat_id, "qr.png", png, "Scan to connect")
        core.stop_services()
        out(ok, args.json)
        return 0 if ok.get("ok") else 1
    if args.cmd == "sync":
        out({"ok": True, "imported": wg.sync_from_conf()}, args.json)
        return 0
    if args.cmd == "restart":
        ok, message = wg.restart()
        out({"ok": ok, "message": message}, args.json)
        return 0 if ok else 1
    if args.cmd == "rotate-server-keys":
        pub = wg.rotate_server_keys()
        out({"ok": True, "public_key": pub,
             "warning": "Every client must download a fresh config"}, args.json)
        return 0
    if args.cmd == "backup":
        out({"ok": True, "name": wg.backup("cli")}, args.json)
        return 0
    if args.cmd == "backups":
        out(wg.backups(), args.json)
        return 0
    if args.cmd == "restore":
        out({"ok": True, "message": wg.restore(args.name)}, args.json)
        return 0
    if args.cmd == "token":
        tid, token = db.create_api_token(args.name)
        out({"id": tid, "token": token,
             "usage": "curl -H 'X-API-Key: {}' https://your-domain/api/state".format(token)}, args.json)
        return 0
    if args.cmd == "detect":
        from . import net
        iface = wg.interface()
        port = iface["listen_port"] or 51820
        ip = net.public_ipv4() or ""
        endpoint = "{}:{}".format(ip, port) if ip else ""
        server_ip = (iface["address"].split(",")[0].split("/")[0] if iface["address"] else "10.8.0.1")
        dns = "1.1.1.1, 8.8.8.8"
        adguard = False
        try:
            import subprocess
            r = subprocess.run(["systemctl", "is-active", "AdGuardHome"],
                               capture_output=True, text=True, timeout=5)
            adguard = r.stdout.strip() == "active"
        except Exception:
            pass
        if adguard:
            dns = "{}, 1.1.1.1".format(server_ip)
        patch = {}
        if endpoint:
            patch["endpoint"] = endpoint
        if adguard:
            patch["default_dns"] = dns
        db.set_settings(patch)
        out({"ok": True, "detected": {"endpoint": endpoint, "adguard_home": adguard, "dns": dns}}, args.json)
        return 0
    if args.cmd == "demo-init":
        if not core.config.get("demo"):
            print("demo-init is only allowed in demo mode", file=sys.stderr)
            return 2
        demo_seed(core)
        out({"ok": True, "peers": len(db.peers())}, args.json)
        return 0
    return 1


def demo_seed(core):
    """Populate a local preview with realistic peers and 24h of history."""
    import random
    from .monitor import Monitor
    random.seed(42)
    names = [
        ("phone", 30, 50), ("laptop-maria", 90, 200), ("office-router", 0, 0),
        ("tablet-ali", 14, 20), ("ipad-kids", 7, 10), ("backup-pi", 365, 500),
    ]
    for name, days, quota in names:
        if core.db.peer(name):
            continue
        core.add_peer({"name": name, "expiry_days": days, "quota_gb": quota,
                       "notes": "Demo peer created for the live preview"}, actor="demo")
    peers = core.db.peers()
    # Historical samples so charts and totals look alive on first load.
    now = int(time.time())
    for p in peers:
        seed = int.from_bytes(bytes(p["name"], "utf8")[:4].ljust(4, b"\0"), "big")
        random.seed(seed)
        rx, tx = 0, 0
        for ts in range(now - 24 * 3600, now, 900):
            factor = 0.4 + 0.6 * (0.5 + 0.5 * __import__("math").sin((ts % 86400) / 86400 * 6.28))
            drx = int(random.uniform(200_000, 3_000_000) * factor)
            dtx = int(random.uniform(80_000, 900_000) * factor)
            rx += drx
            tx += dtx
            core.db.add_sample(ts, p["id"], drx, dtx, rx, tx, random.random() > 0.45)
        core.db.update_peer(p["id"], {"last_rx": 0, "last_tx": 0})
    # Seed cumulative counters from history and align runtime counters so the
    # first monitor tick doesn't double-count the fake interface counters.
    runtime = core.wg.status()
    for p in peers:
        last = core.db.q1("SELECT total_rx,total_tx FROM samples WHERE peer_id=? "
                          "ORDER BY ts DESC LIMIT 1", (p["id"],)) or {"total_rx": 0, "total_tx": 0}
        rt = runtime.get(p["pubkey"], {})
        core.db.update_peer(p["id"], {
            "total_rx": last["total_rx"], "total_tx": last["total_tx"],
            "last_rx": rt.get("rx", 0), "last_tx": rt.get("tx", 0),
        })
    m = Monitor(core)
    m.tick(force=True)
    core.db.add_event("info", "Demo environment initialized", detail={"peers": len(peers)})


if __name__ == "__main__":
    sys.exit(main())
