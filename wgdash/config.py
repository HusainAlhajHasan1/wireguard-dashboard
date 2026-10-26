"""Infrastructure configuration (paths, secrets, bind address)."""
from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path

DEFAULT_PATH = "/etc/wireguard-dashboard/config.json"


def _default_config(path: str) -> dict:
    root = Path(path).parent
    return {
        "demo": False,
        "install_dir": str(Path(__file__).resolve().parent.parent),
        "config_dir": str(root),
        "data_dir": str(root),
        "db_path": str(root / "wgdash.db"),
        "key_path": str(root / "secret.key"),
        "backup_dir": str(root / "backups"),
        "wg_interface": "wg0",
        "wg_conf": "/etc/wireguard/wg0.conf",
        "wg_pubkey_file": "/etc/wireguard/publickey",
        "wg_privkey_file": "/etc/wireguard/privatekey",
        "public_endpoint": "",
        "listen_host": "127.0.0.1",
        "listen_port": 8080,
        "public_url": "",
        "secret_key": "",
        "bootstrap_admin": None,
        "created_at": "",
    }


class Config:
    def __init__(self, path: str | None = None):
        self.path = str(Path(path or os.environ.get("WGDASH_CONFIG") or DEFAULT_PATH).resolve())
        self.data = _default_config(self.path)
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as fh:
                self.data.update(json.load(fh))
        # Environment overrides are useful for containers and for the demo.
        env_map = {
            "WGDASH_DEMO": "demo", "WGDASH_DB": "db_path", "WGDASH_KEY": "key_path",
            "WGDASH_WG_CONF": "wg_conf", "WGDASH_INTERFACE": "wg_interface",
            "WGDASH_HOST": "listen_host", "WGDASH_PORT": "listen_port",
            "WGDASH_ENDPOINT": "public_endpoint", "WGDASH_DATA_DIR": "data_dir",
            "WGDASH_BACKUP_DIR": "backup_dir", "WGDASH_SECRET_KEY": "secret_key",
        }
        for env, key in env_map.items():
            if env in os.environ:
                val: object = os.environ[env]
                if key == "demo":
                    val = str(val).lower() in ("1", "true", "yes", "on")
                elif key == "listen_port":
                    val = int(str(val))
                self.data[key] = val
        for d in (self.data["data_dir"], self.data["backup_dir"], self.data["config_dir"]):
            Path(d).mkdir(parents=True, exist_ok=True)
        Path(self.data["db_path"]).parent.mkdir(parents=True, exist_ok=True)

    def __getitem__(self, key: str):
        return self.data[key]

    def get(self, key: str, default=None):
        return self.data.get(key, default)

    def __setitem__(self, key: str, value):
        self.data[key] = value

    def save(self, updates: dict | None = None):
        if updates:
            self.data.update(updates)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(Path(self.path).parent), prefix=".cfg-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self.data, fh, indent=2, sort_keys=True)
                fh.write("\n")
            os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def as_public(self) -> dict:
        return {
            "demo": bool(self.data["demo"]),
            "wg_interface": self.data["wg_interface"],
            "wg_conf": self.data["wg_conf"],
            "public_endpoint": self.data["public_endpoint"],
            "listen_host": self.data["listen_host"],
            "listen_port": self.data["listen_port"],
            "public_url": self.data["public_url"],
            "install_dir": self.data["install_dir"],
            "data_dir": self.data["data_dir"],
        }
