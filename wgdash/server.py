"""WSGI entry point and standalone server."""
from __future__ import annotations

import argparse
import os
import sys
import threading

from .config import Config
from .core import Core
from .db import Database
from .wireguard import WireGuard
from . import crypto


def build(config_path: str | None = None):
    cfg = Config(config_path)
    key = crypto.load_or_create_key(cfg["key_path"])
    db = Database(cfg["db_path"], key)
    wg = WireGuard(cfg, db)
    core = Core(cfg, db, wg)
    core.bootstrap()
    from .web import create_app
    app = create_app(core)
    return app, core


def main(argv=None):
    parser = argparse.ArgumentParser(description="WireGuard Dashboard server")
    parser.add_argument("--config", default=None, help="path to config.json")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--no-services", action="store_true",
                        help="do not start the monitor / Telegram bot (web only)")
    args = parser.parse_args(argv)

    app, core = build(args.config)
    host = args.host or core.config["listen_host"]
    port = args.port or int(core.config["listen_port"])
    if not args.no_services:
        core.start_services()
        print("[wgdash] monitor + telegram bot started", flush=True)
    print("[wgdash] listening on http://{}:{} (demo={})".format(host, port, core.config.get("demo")),
          flush=True)
    try:
        from waitress import serve
        serve(app, host=host, port=port, threads=8, ident="WireGuard-Dashboard")
    except ImportError:
        app.run(host=host, port=port, threaded=True, use_reloader=False)


if __name__ == "__main__":
    main()
