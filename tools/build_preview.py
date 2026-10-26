#!/usr/bin/env python3
"""Regenerate dashboard-preview.html — an offline, single-file snapshot of the UI.

Usage:  python3 tools/build_preview.py [demo-config.json]
The preview embeds real backend state as fixtures and stubs fetch(), so it opens
from disk (or in a sandboxed iframe) with zero network access.
"""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from jinja2 import Template  # noqa: E402

from wgdash.server import build  # noqa: E402


def main() -> int:
    config = sys.argv[1] if len(sys.argv) > 1 else str(ROOT / "demo-data" / "config.json")
    app, core = build(config)
    core.wg.endpoint()
    state = core.state()
    first = state["peers"][0]["id"] if state["peers"] else ""
    fixtures = {
        "state": state,
        "traffic": {"series": state["traffic"]},
        "server": {"info": core.wg.server_info(), "interface": core.wg.interface(),
                   "config": core.wg.read_conf(), "backups": core.wg.backups()},
        "settings": {"settings": state["settings"], "admins": core.db.admins(),
                     "tokens": core.db.api_tokens(), "shares": core.db.shares()},
        "events": {"events": state["events"]},
        "audit": {"audit": state["audit"]},
        "details": {"peer": state["peers"][0] if state["peers"] else {},
                    "events": core.db.events(20, first),
                    "samples": core.db.peer_samples(first, int(time.time()) - 7 * 86400, 200),
                    "shares": []},
        "conf": {"ok": True, "conf": core.wg.client_config(core.db.peer(first)) if first else ""},
    }
    fixtures["server"]["config"] = re.sub(r"(PrivateKey\s*=\s*)\S+", r"\1<redacted-in-preview>",
                                          fixtures["server"]["config"])
    fixtures["details"]["peer"] = dict(
        fixtures["details"]["peer"],
        privkey="", psk="")  # never embed key material
    for bucket in ("state",):
        for p in fixtures[bucket].get("peers", []):
            p["privkey"], p["psk"] = "", ""

    html = Template((ROOT / "wgdash" / "templates" / "index.html").read_text()).render(
        version=state["version"], csrf="preview", username="admin", demo=True)
    css = (ROOT / "wgdash" / "static" / "style.css").read_text()
    js = (ROOT / "wgdash" / "static" / "app.js").read_text()
    payload = json.dumps(fixtures, separators=(",", ":"), default=str).replace("<", "\\u003c")

    stub = """<script>
/* Offline preview: all API responses are embedded below. */
window.__WGDASH_FIXTURES__ = %s;
window.fetch = async function (url, opts) {
  var f = window.__WGDASH_FIXTURES__, data = {ok: true}, raw = null, u = String(url);
  if (u.indexOf('/api/state') === 0) data = f.state;
  else if (u.indexOf('/api/traffic') === 0) data = f.traffic;
  else if (u.indexOf('/api/server') === 0) data = f.server;
  else if (u.indexOf('/api/settings') === 0) data = f.settings;
  else if (u.indexOf('/api/events') === 0) data = f.events;
  else if (u.indexOf('/api/audit') === 0) data = f.audit;
  else if (/\\/api\\/peers\\/[^/]+\\/details/.test(u)) data = f.details;
  else if (/\\/conf$/.test(u)) data = f.conf;
  else if (/\\/api\\/peers\\/[^/]+\\/share/.test(u)) data = {ok: true, share: {path: '/s/preview', url: ''}};
  else if (u.indexOf('qr.svg') !== -1) raw = '<svg xmlns="http://www.w3.org/2000/svg" width="180" height="180"><rect width="180" height="180" fill="#fff"/><path d="M20 20h50v50H20zm90 0h50v50h-50zM20 110h50v50H20z" fill="#0f172a"/></svg>';
  return {status: 200, ok: true, text: async function () { return raw !== null ? raw : JSON.stringify(data); }};
};
window.prompt = function () { return null; };
if (!navigator.clipboard) navigator.clipboard = {writeText: async function () {}};
</script>
""" % payload

    icon = ("data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 64 64%22%3E"
            "%3Crect width=%2264%22 height=%2264%22 rx=%2216%22 fill=%22%230f172a%22/%3E"
            "%3Cpath d=%22M32 8 12 17v15c0 13 9 22 20 25 11-3 20-12 20-25V17z%22 fill=%22none%22 "
            "stroke=%22%233ddc84%22 stroke-width=%223%22/%3E%3C/svg%3E")
    html = html.replace('<link rel="stylesheet" href="/static/style.css">', "<style>\n" + css + "\n</style>")
    html = html.replace('<link rel="icon" href="/static/logo.svg" type="image/svg+xml">',
                        '<link rel="icon" href="' + icon + '">')
    html = html.replace('<script src="/static/app.js"></script>',
                        stub + "<script>\n" + js.replace("</script>", "<\\/script>") + "\n</script>")
    out = ROOT / "dashboard-preview.html"
    out.write_text(html)
    print("wrote {} ({:,} bytes, {} peers)".format(out, out.stat().st_size, len(state["peers"])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
