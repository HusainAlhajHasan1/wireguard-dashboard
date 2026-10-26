"""End-to-end smoke tests against an isolated demo environment.

Run: python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import os
import tempfile
import unittest

TMP = tempfile.mkdtemp(prefix="wgdash-test-")
os.environ["WGDASH_DEMO_DIR"] = TMP

from wgdash import demo_setup  # noqa: E402
from wgdash.server import build  # noqa: E402
from wgdash.wireguard import (DemoBackend, parse_config, normalize_endpoint,  # noqa: E402
                             parse_endpoint)

CONFIG = demo_setup.setup()


class DashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app, cls.core = build(CONFIG)
        cls.app.config["TESTING"] = True
        cls.client = cls.app.test_client()
        # Seed deterministic demo peers.
        from wgdash.cli import demo_seed
        demo_seed(cls.core)

    def login(self):
        res = self.client.post("/api/login", json={
            "username": "admin", "password": "DemoAdmin123!"})
        self.assertEqual(res.status_code, 200, res.get_data(as_text=True))
        return res.get_json()["csrf"]

    def test_01_login_and_state(self):
        csrf = self.login()
        state = self.client.get("/api/state").get_json()
        self.assertIn("peers", state)
        self.assertEqual(state["demo"], True)
        self.assertGreaterEqual(state["stats"]["total_peers"], 6)
        self.assertTrue(state["server"]["public_key"])
        self.assertTrue(state["endpoint"])
        self.assertGreater(len(state["traffic"]), 0)
        self.assertIsInstance(csrf, str)

    def test_02_add_peer_and_config(self):
        csrf = self.login()
        res = self.client.post("/api/peers", headers={"X-CSRF-Token": csrf}, json={
            "name": "test-laptop", "expiry_days": 14, "quota_gb": 5,
            "notes": "created by smoke test"})
        self.assertEqual(res.status_code, 200, res.get_data(as_text=True))
        peer = res.get_json()["peer"]
        self.assertEqual(peer["name"], "test-laptop")
        self.assertTrue(peer["vpn_ip"].startswith("10.8.0."))

        conf = self.client.get("/api/peers/{}/config".format(peer["id"])).get_data(as_text=True)
        self.assertIn("[Interface]", conf)
        self.assertIn("PrivateKey =", conf)
        self.assertIn("[Peer]", conf)
        self.assertIn("Endpoint =", conf)
        svg = self.client.get("/api/peers/{}/qr.svg".format(peer["id"])).get_data(as_text=True)
        self.assertIn("<svg", svg)
        png = self.client.get("/api/peers/{}/qr.png".format(peer["id"])).data
        self.assertTrue(png.startswith(b"\x89PNG"))

    def test_02b_allocation_never_uses_server_ip(self):
        reserved = self.core.wg.server_addresses()
        for peer in self.core.db.peers():
            from ipaddress import ip_address
            self.assertNotIn(ip_address(peer["vpn_ip"].split("/")[0]), reserved,
                             "peer {} got the server address".format(peer["name"]))
        from ipaddress import ip_address
        nxt = self.core.wg.next_ip()
        self.assertTrue(nxt.endswith("/32"))
        self.assertNotIn(ip_address(nxt.split("/")[0]), reserved)
        self.assertFalse(any(p["vpn_ip"] == nxt for p in self.core.db.peers()))
        # 10.8.0.1 is the server, .2-.7 are demo peers, .8 was taken by test_02.
        self.assertEqual(nxt, "10.8.0.9/32")

    def test_03_share_link(self):
        csrf = self.login()
        peer = self.core.db.peer("test-laptop")
        res = self.client.post("/api/peers/{}/share".format(peer["id"]),
                               headers={"X-CSRF-Token": csrf}, json={})
        self.assertEqual(res.status_code, 200)
        path = res.get_json()["share"]["path"]
        page = self.client.get(path)
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"Your WireGuard configuration", page.data)
        self.assertEqual(self.client.get(path + "/config").status_code, 200)
        self.assertEqual(self.client.get(path + "/qr.png").status_code, 200)

    def test_04_update_disable_enable(self):
        csrf = self.login()
        peer = self.core.db.peer("test-laptop")
        res = self.client.patch("/api/peers/{}".format(peer["id"]),
                                headers={"X-CSRF-Token": csrf},
                                json={"notes": "updated", "quota_bytes": 2 * 1024 ** 3})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()["peer"]["notes"], "updated")
        res = self.client.post("/api/peers/{}/disable".format(peer["id"]),
                               headers={"X-CSRF-Token": csrf}, json={})
        self.assertEqual(res.get_json()["peer"]["enabled"], 0)
        # Disabled peer must disappear from wg0.conf.
        from wgdash.wireguard import parse_config
        parsed = parse_config(self.core.wg.read_conf())
        self.assertNotIn(peer["pubkey"], [p.get("PublicKey") for p in parsed.peers])
        res = self.client.post("/api/peers/{}/enable".format(peer["id"]),
                               headers={"X-CSRF-Token": csrf}, json={})
        self.assertEqual(res.get_json()["peer"]["enabled"], 1)

    def test_05_settings_and_server(self):
        csrf = self.login()
        res = self.client.post("/api/settings", headers={"X-CSRF-Token": csrf},
                               json={"online_timeout": 240, "default_dns": "9.9.9.9"})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(self.core.db.settings()["online_timeout"], 240)
        server = self.client.get("/api/server").get_json()
        self.assertIn("PrivateKey", server["config"])
        self.assertIn("<redacted", server["config"])
        self.assertNotIn("private_key", server["interface"])
        self.assertEqual(server["interface"]["listen_port"], 54240)

    def test_06_api_token(self):
        csrf = self.login()
        res = self.client.post("/api/tokens", headers={"X-CSRF-Token": csrf},
                               json={"name": "smoke"})
        token = res.get_json()["token"]
        # Token auth works without a session or CSRF header.
        anon = self.app.test_client()
        state = anon.get("/api/state", headers={"X-API-Key": token})
        self.assertEqual(state.status_code, 200)

    def test_07_remove_peer(self):
        csrf = self.login()
        peer = self.core.db.peer("test-laptop")
        res = self.client.delete("/api/peers/{}".format(peer["id"]),
                                 headers={"X-CSRF-Token": csrf})
        self.assertEqual(res.status_code, 200)
        self.assertIsNone(self.core.db.peer(peer["id"]))

    def test_08_csrf_required(self):
        self.login()
        res = self.client.post("/api/peers", json={"name": "should-fail"})
        self.assertEqual(res.status_code, 403)


class EnforcementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app, cls.core = build(CONFIG)
        cls.client = cls.app.test_client()
        res = cls.client.post("/api/login", json={"username": "admin", "password": "DemoAdmin123!"})
        cls.csrf = res.get_json()["csrf"]

    def _new_peer(self, name):
        res = self.client.post("/api/peers", headers={"X-CSRF-Token": self.csrf},
                               json={"name": name})
        self.assertEqual(res.status_code, 200, res.get_data(as_text=True))
        return res.get_json()["peer"]["id"]

    def test_quota_auto_disable(self):
        from wgdash.monitor import Monitor
        import time
        pid = self._new_peer("quota-test")
        self.core.db.update_peer(pid, {"quota_bytes": 1000, "total_rx": 5000,
                                       "created_at": int(time.time())})
        m = Monitor(self.core)
        m.last_tick = 0
        m.tick()
        row = self.core.db.peer(pid)
        self.assertEqual(row["enabled"], 0)
        self.assertIn("quota", row["disabled_reason"])
        self.assertTrue(any(e["type"] == "peer_blocked" and e["peer_id"] == pid
                            for e in self.core.db.events(50)))

    def test_expiry_auto_disable(self):
        from wgdash.monitor import Monitor
        import time
        pid = self._new_peer("expiry-test")
        self.core.db.update_peer(pid, {"expires_at": int(time.time()) - 3600})
        m = Monitor(self.core)
        m.last_tick = 0
        m.tick()
        row = self.core.db.peer(pid)
        self.assertEqual(row["enabled"], 0)
        self.assertIn("expired", row["disabled_reason"])

    def test_disabled_peer_is_not_in_conf(self):
        from wgdash.wireguard import parse_config
        pid = self._new_peer("conf-test")
        peer = self.core.db.peer(pid)
        self.assertIn(peer["pubkey"], [s.get("PublicKey") for s in parse_config(self.core.wg.read_conf()).peers])
        self.core.set_enabled(pid, False, "test")
        self.assertNotIn(peer["pubkey"], [s.get("PublicKey") for s in parse_config(self.core.wg.read_conf()).peers])

    def test_server_key_rotation(self):
        from wgdash.wireguard import parse_config
        before = parse_config(self.core.wg.read_conf()).interface.get("PrivateKey")
        pub = self.core.wg.rotate_server_keys()
        after = parse_config(self.core.wg.read_conf()).interface.get("PrivateKey")
        self.assertNotEqual(before, after)
        self.assertEqual(pub, self.core.wg.server_pubkey())
        self.assertTrue(self.core.wg.backups())


class ParserTests(unittest.TestCase):
    def test_parse_multiple_peers(self):
        text = """[Interface]
PrivateKey = abc
Address = 10.8.0.1/24
ListenPort = 54240

[Peer]
# Client: phone (initial)
PublicKey = XYZ
AllowedIPs = 10.8.0.2/32

[Peer]
PublicKey = ABC
AllowedIPs = 10.8.0.3/32
"""
        parsed = parse_config(text)
        self.assertEqual(len(parsed.peers), 2)
        self.assertEqual(parsed.interface.get("ListenPort"), "54240")
        self.assertEqual(parsed.peers[0].get("PublicKey"), "XYZ")
        self.assertEqual(parsed.peers[1].get("AllowedIPs"), "10.8.0.3/32")

    def test_set_replaces_once(self):
        s = parse_config("[Interface]\nAddress = 10.8.0.1/24\nAddress = 10.9.0.1/24\n").interface
        s.set("Address", "10.10.0.1/24")
        self.assertEqual(s.get_all("Address"), ["10.10.0.1/24"])

    def test_float_counters_are_tolerated(self):
        """wg dump must never crash on float/empty fields."""
        be = DemoBackend("wg0", CONFIG.split("config.json")[0] + "wg0.conf")
        be.started = 1  # force float arithmetic in the fake backend
        dump = be.dump()
        self.assertIn("\t", dump)
        lines = dump.splitlines()[1:]
        for line in lines:
            parts = line.split("\t")
            self.assertEqual(len(parts), 8)
            self.assertIsInstance(int(float(parts[5])), int)

    @classmethod
    def setUpClass(cls):
        cls.app, cls.core = build(CONFIG)

    def test_numeric_defaults(self):
        db = self.core.db
        peer = db.add_peer({"id": "p-numtest", "pubkey": "NUMTESTKEY", "name": "numtest",
                            "vpn_ip": "10.8.0.99/32"})
        self.assertEqual(peer["online"], 0)
        self.assertEqual(peer["total_rx"], 0)
        self.assertEqual(peer["enabled"], 0 if peer["enabled"] == 0 else peer["enabled"])
        db.delete_peer(peer["id"])

    def test_endpoints(self):
        self.assertEqual(parse_endpoint("91.64.1.2:51820"), ("91.64.1.2", 51820))
        self.assertEqual(parse_endpoint("[2001:db8::1]:1234"), ("2001:db8::1", 1234))
        self.assertEqual(parse_endpoint("(none)"), ("", 0))
        self.assertEqual(normalize_endpoint("2001:db8::1", 51820), "[2001:db8::1]:51820")


if __name__ == "__main__":
    unittest.main(verbosity=2)
