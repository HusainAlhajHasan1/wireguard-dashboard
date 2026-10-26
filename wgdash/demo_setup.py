"""Create a fully local demo environment (no root, no WireGuard needed)."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

from . import crypto

ROOT = Path(os.environ.get("WGDASH_DEMO_DIR", Path(__file__).resolve().parent.parent / "demo-data"))


def setup() -> str:
    ROOT.mkdir(parents=True, exist_ok=True)
    conf_path = ROOT / "wg0.conf"
    if not conf_path.exists():
        priv = base64.b64encode(hashlib.sha256(b"wgdash-demo-server").digest()).decode()
        conf_path.write_text(
            "[Interface]\n"
            "PrivateKey = {}\n"
            "Address = 10.8.0.1/24\n"
            "ListenPort = 54240\n"
            "SaveConfig = false\n"
            "PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE\n"
            "PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE\n".format(priv))
    cfg_path = ROOT / "config.json"
    cfg_path.write_text(json.dumps({
        "demo": True,
        "install_dir": str(Path(__file__).resolve().parent.parent),
        "config_dir": str(ROOT), "data_dir": str(ROOT),
        "db_path": str(ROOT / "wgdash.db"), "key_path": str(ROOT / "secret.key"),
        "backup_dir": str(ROOT / "backups"),
        "wg_interface": "wg0", "wg_conf": str(conf_path),
        "wg_pubkey_file": str(ROOT / "publickey"),
        "wg_privkey_file": str(ROOT / "privatekey"),
        "public_endpoint": "vpn.example.com:54240",
        "listen_host": "0.0.0.0",
        "listen_port": int(os.environ.get("WGDASH_DEMO_PORT", "8080")),
        "public_url": "",
        "secret_key": crypto.new_token(32),
        "bootstrap_admin": None,
        "created_at": "",
    }, indent=2))
    os.chmod(cfg_path, 0o600)
    return str(cfg_path)


if __name__ == "__main__":
    print(setup())
