"""WireGuard config + runtime management.

The wg0.conf file stays the source of truth for the running interface.  Peer
metadata lives in SQLite; each [Peer] block carries a `# wgdash-id:` comment so
config edits made by hand can be re-imported.  Live state comes from `wg show
<iface> dump`, so no kernel module or third-party daemon is required.
"""
from __future__ import annotations

import base64
import hashlib
import io
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from . import crypto

MANAGED_KEYS = ("publickey", "presharedkey", "allowedips", "persistentkeepalive")


class WgError(Exception):
    pass


class Section:
    def __init__(self, header: str, lines: list | None = None):
        self.header = header
        self.lines = list(lines or [])

    def get(self, key: str, default=None):
        for line in self.lines:
            s = line.strip()
            if not s or s.startswith("#") or "=" not in s:
                continue
            k, v = s.split("=", 1)
            if k.strip().lower() == key.lower():
                return v.strip()
        return default

    def get_all(self, key: str) -> list:
        out = []
        for line in self.lines:
            s = line.strip()
            if s and not s.startswith("#") and "=" in s:
                k, v = s.split("=", 1)
                if k.strip().lower() == key.lower():
                    out.append(v.strip())
        return out

    def set(self, key: str, value):
        """Replace the first occurrence of key, drop the rest, append if absent."""
        first = -1
        keep = []
        for idx, line in enumerate(self.lines):
            s = line.strip()
            if s and not s.startswith("#") and "=" in s and s.split("=", 1)[0].strip().lower() == key.lower():
                if first < 0:
                    first = idx
                else:
                    continue
            keep.append(line)
        self.lines = keep
        new_line = "{} = {}".format(key, value)
        if first >= 0 and first < len(self.lines):
            self.lines[first] = new_line
        else:
            while self.lines and not self.lines[-1].strip():
                self.lines.pop()
            self.lines.append(new_line)

    def delete(self, key: str):
        self.lines = [l for l in self.lines
                      if not (l.strip() and not l.strip().startswith("#") and "=" in l
                              and l.split("=", 1)[0].strip().lower() == key.lower())]

    def meta(self, name: str) -> str:
        prefix = "# wgdash-{}:".format(name)
        for line in self.lines:
            if line.strip().lower().startswith(prefix):
                return line.split(":", 1)[1].strip()
        return ""

    def render(self) -> str:
        return "\n".join([self.header] + [l.rstrip() for l in self.lines]) + "\n"


class ParsedConfig:
    def __init__(self):
        self.preamble: list = []
        self.interface: Section | None = None
        self.others: list = []
        self.peers: list = []

    def interface_or_create(self) -> Section:
        if not self.interface:
            self.interface = Section("[Interface]")
        return self.interface


def parse_config(text: str) -> ParsedConfig:
    parsed = ParsedConfig()
    current = None
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            header = s
            lower = header.lower()
            if lower == "[interface]":
                current = Section(header)
                parsed.interface = current
            elif lower == "[peer]":
                current = Section(header)
                parsed.peers.append(current)
            else:
                current = Section(header)
                parsed.others.append(current)
            continue
        if current is None:
            parsed.preamble.append(line)
        else:
            current.lines.append(line)
    return parsed


def _to_int(value, default: int = 0) -> int:
    """Tolerant int() for `wg dump` fields (handles "1.5", "", "-")."""
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def parse_endpoint(endpoint: str) -> tuple:
    endpoint = (endpoint or "").strip()
    if not endpoint or endpoint == "(none)":
        return "", 0
    if endpoint.startswith("["):
        close = endpoint.find("]")
        if close > 0:
            host = endpoint[1:close]
            tail = endpoint[close + 1:]
            port = int(tail.split(":")[-1]) if ":" in tail and tail.split(":")[-1].isdigit() else 0
            return host, port
    if ":" in endpoint:
        host, _, port = endpoint.rpartition(":")
        return host, int(port) if port.isdigit() else 0
    return endpoint, 0


def normalize_endpoint(host: str, port) -> str:
    host = (host or "").strip().strip("[]")
    if not host:
        return ""
    if ":" in host and not host.startswith("["):  # bare IPv6
        host = "[{}]".format(host)
    return "{}:{}".format(host, port) if port else host


def flag_emoji(code: str) -> str:
    if not code or len(code) != 2 or not code.isalpha():
        return "\U0001F3F3"
    return "".join(chr(0x1F1E6 + ord(c.upper()) - ord("A")) for c in code)


class RealBackend:
    def __init__(self, iface: str):
        self.iface = iface

    def run(self, args, input_data=None, check=True) -> str:
        try:
            proc = subprocess.run(args, input=input_data, text=True,
                                  capture_output=True, timeout=20)
        except FileNotFoundError as exc:
            raise WgError("Command not found: {} ({})".format(args[0], exc))
        if check and proc.returncode != 0:
            raise WgError("{} failed: {}".format(" ".join(args[:3]), (proc.stderr or proc.stdout).strip()))
        return proc.stdout.strip()

    def keygen(self) -> tuple:
        priv = self.run(["wg", "genkey"])
        pub = self.run(["wg", "pubkey"], input_data=priv + "\n")
        return priv, pub

    def pubkey(self, priv: str) -> str:
        return self.run(["wg", "pubkey"], input_data=priv + "\n")

    def psk(self) -> str:
        return self.run(["wg", "genpsk"])

    def dump(self) -> str:
        return self.run(["wg", "show", self.iface, "dump"], check=True)

    def server_pubkey(self) -> str:
        return self.run(["wg", "show", self.iface, "public-key"], check=False)

    def strip(self) -> str:
        return self.run(["wg-quick", "strip", self.iface])

    def syncconf(self, text: str):
        self.run(["wg", "syncconf", self.iface, "/dev/stdin"], input_data=text)

    def service(self, action: str) -> tuple:
        unit = "wg-quick@{}".format(self.iface)
        if shutil.which("systemctl"):
            proc = subprocess.run(["systemctl", action, unit], capture_output=True, text=True, timeout=30)
            if proc.returncode == 0:
                return True, proc.stdout.strip() or "systemctl {} {}".format(action, unit)
        try:
            down = subprocess.run(["wg-quick", "down", self.iface], capture_output=True, text=True, timeout=20)
            up = subprocess.run(["wg-quick", "up", self.iface], capture_output=True, text=True, timeout=20)
            ok = up.returncode == 0
            return ok, (up.stderr or up.stdout or down.stderr or "").strip()
        except Exception as exc:
            return False, str(exc)

    def is_active(self) -> bool:
        if shutil.which("systemctl"):
            proc = subprocess.run(["systemctl", "is-active", "wg-quick@{}".format(self.iface)],
                                  capture_output=True, text=True, timeout=10)
            if proc.stdout.strip() == "active":
                return True
        proc = subprocess.run(["ip", "link", "show", "dev", self.iface],
                              capture_output=True, text=True, timeout=10)
        return proc.returncode == 0


DEMO_ENDPOINTS = [
    ("91.64.182.11", "Germany", "DE", "Nuremberg", "Deutsche Telekom"),
    ("5.160.116.34", "Iran", "IR", "Tehran", "TIC"),
    ("45.83.220.9", "Netherlands", "NL", "Amsterdam", "Hetzner Online"),
    ("172.58.32.17", "United States", "US", "New York", "T-Mobile US"),
    ("78.186.111.25", "Turkey", "TR", "Istanbul", "Turk Telekom"),
    ("82.66.12.44", "France", "FR", "Paris", "Free SAS"),
    ("213.108.4.7", "United Kingdom", "GB", "London", "BT Group"),
    ("185.220.101.3", "Germany", "DE", "Berlin", "ZWIEBELFREUNDE"),
]


class DemoBackend:
    """Fake `wg` for local preview/testing: no root, no kernel, real config files."""
    def __init__(self, iface: str, conf_path: str):
        self.iface = iface
        self.conf_path = conf_path
        self.started = int(time.time())

    @staticmethod
    def _b64(data: bytes) -> str:
        return base64.b64encode(data).decode()

    def keygen(self):
        priv = self._b64(secrets.token_bytes(32))
        return priv, self.pubkey(priv)

    def pubkey(self, priv: str) -> str:
        return self._b64(hashlib.sha256(("pub:" + priv).encode()).digest())

    def psk(self) -> str:
        return self._b64(secrets.token_bytes(32))

    def _peer_keys(self):
        try:
            parsed = parse_config(Path(self.conf_path).read_text())
            return [p.get("PublicKey") for p in parsed.peers if p.get("PublicKey")]
        except Exception:
            return []

    def server_pubkey(self) -> str:
        try:
            parsed = parse_config(Path(self.conf_path).read_text())
            priv = parsed.interface_or_create().get("PrivateKey", "demo-server-key")
            return self.pubkey(priv)
        except Exception:
            return self.pubkey("demo-server-key")

    def strip(self) -> str:
        return "[]"

    def syncconf(self, text: str):
        return None

    def service(self, action: str):
        return True, "demo: no service restarted"

    def is_active(self) -> bool:
        return True

    def dump(self) -> str:
        now = int(time.time())
        elapsed = max(1, now - self.started)
        priv = "demo-server-key"
        try:
            parsed = parse_config(Path(self.conf_path).read_text())
            priv = parsed.interface_or_create().get("PrivateKey") or priv
        except Exception:
            pass
        lines = ["\t".join([priv, self.pubkey(priv), "54240", "off"])]
        for idx, pub in enumerate(self._peer_keys()):
            seed = int.from_bytes(hashlib.sha256(pub.encode()).digest()[:4], "big")
            online = (idx % 3) != 0  # 4 of 6 demo peers look connected
            ip, country, code, city, isp = DEMO_ENDPOINTS[seed % len(DEMO_ENDPOINTS)]
            port = 40000 + (seed % 20000)
            endpoint = "{}:{}".format(ip, port)
            handshake = now - (seed % 75) if online else now - (3600 + seed % 90000)
            rate_rx = 3000 + (seed % 9000)
            rate_tx = 1200 + (seed % 4000)
            rx = seed % 900_000_000 + elapsed * rate_rx
            tx = seed % 300_000_000 + elapsed * rate_tx
            lines.append("\t".join([pub, "(none)", endpoint, "10.8.0.{}/32".format(2 + idx),
                                    str(handshake), str(rx), str(tx), "25"]))
        return "\n".join(lines) + "\n"


class WireGuard:
    def __init__(self, config, db):
        self.config = config
        self.db = db
        self.iface = config["wg_interface"]
        self.conf_path = config["wg_conf"]
        self.backend = (DemoBackend(self.iface, self.conf_path) if config.get("demo")
                        else RealBackend(self.iface))
        self._endpoint_cache = ("", 0.0)

    # ------------- config file -------------
    def read_conf(self) -> str:
        try:
            return Path(self.conf_path).read_text(encoding="utf-8")
        except FileNotFoundError:
            raise WgError("WireGuard config not found: {}".format(self.conf_path))

    def parsed(self) -> ParsedConfig:
        return parse_config(self.read_conf())

    def interface(self) -> dict:
        p = self.parsed()
        i = p.interface_or_create()
        return {
            "private_key": i.get("PrivateKey", ""),
            "address": i.get("Address", ""),
            "listen_port": int(i.get("ListenPort", "0") or 0),
            "dns": i.get("DNS", ""),
            "mtu": int(i.get("MTU", "0") or 0),
            "table": i.get("Table", ""),
            "saveconfig": i.get("SaveConfig", "false"),
            "postup": i.get("PostUp", ""),
            "postdown": i.get("PostDown", ""),
            "preup": i.get("PreUp", ""),
            "predown": i.get("PreDown", ""),
        }

    def network(self):
        addr = self.interface()["address"].split(",")[0].strip()
        if not addr:
            return ipaddress.ip_network("10.8.0.0/24")
        try:
            return ipaddress.ip_network(addr, strict=False)
        except ValueError:
            return ipaddress.ip_network("10.8.0.0/24")

    def server_addresses(self) -> set:
        """Every address the server itself holds on this interface."""
        out = set()
        for part in self.interface()["address"].split(","):
            try:
                out.add(ipaddress.ip_address(part.strip().split("/")[0]))
            except ValueError:
                continue
        if not out:
            # Fall back to the first usable host of the network.
            out.add(ipaddress.ip_address(self.network().network_address) + 1)
        return out

    def next_ip(self) -> str:
        net = self.network()
        used = set()
        for p in self.db.peers():
            try:
                used.add(ipaddress.ip_address(p["vpn_ip"].split("/")[0]))
            except Exception:
                pass
        reserved = self.server_addresses() | {ipaddress.ip_address(net.network_address)}
        for host in net.hosts():
            if host in reserved or host in used:
                continue
            return "{}/32".format(host)
        raise WgError("No free VPN addresses left in {}".format(net))

    def write_conf(self, interface_patch: dict | None = None, backup: bool = True) -> str:
        parsed = self.parsed()
        iface = parsed.interface_or_create()
        for key, value in (interface_patch or {}).items():
            if value is None or value == "":
                iface.delete(key)
            else:
                iface.set(key, value)
        enabled = [p for p in self.db.peers() if p["enabled"]]
        existing = {}
        for section in parsed.peers:
            pid = section.meta("id")
            pub = section.get("PublicKey", "")
            if pid:
                existing[pid] = section
            if pub:
                existing[pub] = section

        peer_blocks = []
        for peer in enabled:
            old = existing.get(peer["id"]) or existing.get(peer["pubkey"])
            extra = []
            if old:
                for line in old.lines:
                    s = line.strip()
                    if s.lower().startswith("# wgdash-"):
                        continue
                    if not s or s.startswith("#"):
                        extra.append(line)
                        continue
                    if "=" in s and s.split("=", 1)[0].strip().lower() in MANAGED_KEYS:
                        continue
                    extra.append(line)
            block = [
                "[Peer]",
                "# wgdash-id: {}".format(peer["id"]),
                "# wgdash-name: {}".format(peer["name"]),
            ]
            if extra:
                block.extend(x.rstrip() for x in extra if x.strip())
            block.append("PublicKey = {}".format(peer["pubkey"]))
            if peer["psk"]:
                try:
                    block.append("PresharedKey = {}".format(crypto.decrypt(self.db.key, peer["psk"])))
                except Exception:
                    pass
            ip = peer["vpn_ip"].split("/")[0].strip()
            block.append("AllowedIPs = {}/32".format(ip))
            peer_blocks.append("\n".join(block))

        parts = []
        if parsed.preamble:
            parts.append("\n".join(x.rstrip() for x in parsed.preamble).strip())
        parts.append(iface.render().strip())
        for other in parsed.others:
            parts.append(other.render().strip())
        parts.extend(peer_blocks)
        text = "\n\n".join(p for p in parts if p) + "\n"

        if backup and self.db.settings().get("auto_backup"):
            try:
                self.backup("auto")
            except Exception:
                pass
        path = Path(self.conf_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".wg-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(text)
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        return text

    def apply_conf(self) -> str:
        try:
            stripped = self.backend.strip()
            self.backend.syncconf(stripped + "\n")
            return "wg syncconf applied"
        except WgError as exc:
            return "Config written but not applied: {}".format(exc)

    def sync_from_conf(self) -> list:
        """Import peers found in wg0.conf that are not in the database."""
        parsed = self.parsed()
        imported = []
        settings = self.db.settings()
        for section in parsed.peers:
            pub = section.get("PublicKey", "")
            if not pub or self.db.peer_by_pubkey(pub):
                continue
            pid = section.meta("id") or "imp-" + hashlib.sha1(pub.encode()).hexdigest()[:10]
            allowed = section.get("AllowedIPs", "").split(",")[0].strip()
            vpn_ip = allowed.split("/")[0] if allowed else ""
            name = section.meta("name")
            if not name:
                m = re.search(r"#\s*(?:Client|Name)\s*[:=]\s*(.+)", "\n".join(section.lines), re.I)
                name = m.group(1).strip() if m else "Imported-" + pid[-4:]
            self.db.add_peer({
                "id": pid, "pubkey": pub, "name": name, "vpn_ip": vpn_ip,
                "privkey": "", "psk": "", "created_at": int(time.time()),
                "expires_at": 0, "quota_bytes": 0, "enabled": 1,
                "notes": "Imported from wg0.conf. The original private key is unknown; "
                         "use 'Regenerate keys' to issue a fresh config.",
                "telegram_chat_id": "", "dns": "", "allowed_ips": settings["default_allowed_ips"],
                "mtu": settings["default_mtu"], "keepalive": settings["default_keepalive"],
                "country": "", "country_code": "", "city": "", "isp": "",
            })
            imported.append(name)
        self.write_conf(backup=False)
        return imported

    # ------------- keys / peers -------------
    def generate_material(self, use_psk: bool = True) -> dict:
        priv, pub = self.backend.keygen()
        return {
            "privkey": crypto.encrypt(self.db.key, priv),
            "pubkey": pub,
            "psk": crypto.encrypt(self.db.key, self.backend.psk()) if use_psk else "",
        }

    def regenerate_keys(self, peer_id: str, use_psk: bool = True) -> dict:
        peer = self.db.peer(peer_id)
        if not peer:
            raise WgError("Peer not found")
        material = self.generate_material(use_psk)
        self.db.update_peer(peer_id, material)
        self.write_conf()
        self.apply_conf()
        return self.db.peer(peer_id)

    def server_pubkey(self) -> str:
        pub = self.backend.server_pubkey()
        if pub and len(pub) > 20:
            return pub
        priv = self.interface()["private_key"]
        if priv:
            try:
                return self.backend.pubkey(priv)
            except Exception:
                pass
        for path in (self.config.get("wg_pubkey_file"),):
            try:
                return Path(path).read_text().strip()
            except Exception:
                continue
        return ""

    # ------------- live state -------------
    def status(self) -> dict:
        try:
            dump = self.backend.dump()
        except Exception:
            return {}
        out = {}
        for line in dump.splitlines()[1:]:
            parts = line.split("\t")
            if len(parts) < 8:
                continue
            try:
                out[parts[0]] = {
                    "preshared": parts[1], "endpoint": parts[2],
                    "allowed_ips": parts[3], "handshake": _to_int(parts[4]),
                    "rx": _to_int(parts[5]), "tx": _to_int(parts[6]),
                    "keepalive": _to_int(parts[7]),
                }
            except (ValueError, IndexError):
                continue
        return out

    def is_active(self) -> bool:
        try:
            return self.backend.is_active()
        except Exception:
            return False

    def restart(self) -> tuple:
        return self.backend.service("restart")

    def rotate_server_keys(self) -> str:
        priv, pub = self.backend.keygen()
        self.backup("before-key-rotation")
        self.write_conf(interface_patch={"PrivateKey": priv}, backup=False)
        for attr in ("wg_privkey_file", "wg_pubkey_file"):
            path = self.config.get(attr)
            if not path:
                continue
            try:
                p = Path(path)
                p.write_text((priv if "priv" in attr else pub) + "\n")
                os.chmod(p, 0o600)
            except Exception:
                pass
        if not self.config.get("demo"):
            self.restart()
        return pub

    # ------------- client config / QR -------------
    def endpoint(self) -> str:
        settings = self.db.settings()
        endpoint = settings.get("endpoint") or self.config.get("public_endpoint") or ""
        if endpoint:
            return endpoint
        iface = self.interface()
        port = iface["listen_port"] or 51820
        if self.config.get("demo"):
            return "vpn.example.com:{}".format(port)
        cached, ts = self._endpoint_cache
        if cached and time.time() - ts < 600:
            return cached
        ip = ""
        try:
            from .net import public_ipv4
            ip = public_ipv4()
        except Exception:
            pass
        if not ip:
            try:
                ip = socket.gethostbyname(socket.gethostname())
            except OSError:
                ip = ""
        value = normalize_endpoint(ip, port)
        self._endpoint_cache = (value, time.time())
        return value

    def client_config(self, peer: dict) -> str:
        settings = self.db.settings()
        priv = ""
        if peer["privkey"]:
            try:
                priv = crypto.decrypt(self.db.key, peer["privkey"])
            except Exception:
                priv = ""
        if not priv:
            raise WgError("This peer has no stored private key (imported peer). Regenerate its keys first.")
        address = peer["vpn_ip"]
        if not address:
            raise WgError("This peer has no VPN address; edit the peer to assign one.")
        if "/" not in address:
            address = address + "/32"
        endpoint = self.endpoint()
        dns = peer["dns"] or settings["default_dns"]
        allowed = peer["allowed_ips"] or settings["default_allowed_ips"]
        mtu = peer["mtu"] or settings["default_mtu"]
        keepalive = peer["keepalive"] or settings["default_keepalive"]
        lines = [
            "# WireGuard client: {}".format(peer["name"]),
            "# Generated by WireGuard Dashboard on {}".format(
                time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime())),
            "# Dashboard: {}".format(self.config.get("public_url") or "(local)"),
            "",
            "[Interface]",
            "PrivateKey = {}".format(priv),
            "Address = {}".format(address),
        ]
        if dns:
            lines.append("DNS = {}".format(dns))
        if mtu:
            lines.append("MTU = {}".format(mtu))
        lines += ["", "[Peer]", "PublicKey = {}".format(self.server_pubkey()),
                  "Endpoint = {}".format(endpoint), "AllowedIPs = {}".format(allowed)]
        if peer["psk"]:
            try:
                lines.append("PresharedKey = {}".format(crypto.decrypt(self.db.key, peer["psk"])))
            except Exception:
                pass
        if keepalive:
            lines.append("PersistentKeepalive = {}".format(keepalive))
        lines.append("")
        return "\n".join(lines)

    @staticmethod
    def qr_svg(text: str, size: int = 8) -> str:
        import segno
        qr = segno.make(text, error="m", micro=False)
        buf = io.BytesIO()
        qr.save(buf, kind="svg", scale=size, border=2, dark="#0f172a", light="#ffffff")
        svg = buf.getvalue().decode("utf-8")
        svg = re.sub(r"<\?xml[^>]*\?>", "", svg)
        svg = re.sub(r"<!DOCTYPE[^>]*>", "", svg)
        return svg.strip()

    @staticmethod
    def qr_png(text: str, size: int = 8) -> bytes:
        import segno
        qr = segno.make(text, error="m", micro=False)
        buf = io.BytesIO()
        qr.save(buf, kind="png", scale=size, border=2, dark="#0f172a", light="#ffffff")
        return buf.getvalue()

    # ------------- backups -------------
    def backup(self, reason: str = "manual") -> str:
        src = Path(self.conf_path)
        if not src.exists():
            raise WgError("No config to back up")
        folder = Path(self.config.get("backup_dir") or (Path(self.config["data_dir"]) / "backups"))
        folder.mkdir(parents=True, exist_ok=True)
        name = "wg0-{}-{}.conf".format(time.strftime("%Y%m%d-%H%M%S"), reason)
        dest = folder / name
        shutil.copy2(src, dest)
        os.chmod(dest, 0o600)
        files = sorted(folder.glob("wg0-*.conf"))
        for old in files[:-60]:
            old.unlink(missing_ok=True)
        return name

    def backups(self) -> list:
        folder = Path(self.config.get("backup_dir") or (Path(self.config["data_dir"]) / "backups"))
        if not folder.exists():
            return []
        out = []
        for p in sorted(folder.glob("*.conf"), reverse=True):
            stat = p.stat()
            out.append({"name": p.name, "size": stat.st_size,
                        "created_at": int(stat.st_mtime), "reason": p.stem.split("-")[-1]})
        return out[:60]

    def restore(self, name: str) -> str:
        folder = Path(self.config.get("backup_dir") or (Path(self.config["data_dir"]) / "backups"))
        src = folder / Path(name).name
        if not src.exists() or folder not in src.parents:
            raise WgError("Backup not found")
        self.backup("before-restore")
        Path(self.conf_path).write_text(src.read_text())
        os.chmod(self.conf_path, 0o600)
        imported = self.sync_from_conf()
        self.apply_conf()
        return "Restored {} ({} imported peers)".format(name, len(imported))

    def server_info(self) -> dict:
        iface = self.interface()
        info = {
            "interface": self.iface,
            "active": self.is_active(),
            "listen_port": iface["listen_port"],
            "address": iface["address"],
            "public_key": self.server_pubkey(),
            "endpoint": self.endpoint(),
            "config_path": self.conf_path,
            "dns": iface["dns"],
            "mtu": iface["mtu"],
            "postup": iface["postup"],
            "postdown": iface["postdown"],
            "network": str(self.network()),
            "hostname": socket.gethostname(),
            "services": {},
        }
        for name, unit in (("AdGuard Home", "AdGuardHome"), ("Caddy", "caddy"),
                           ("WireGuard", "wg-quick@{}".format(self.iface))):
            try:
                proc = subprocess.run(["systemctl", "is-active", unit], capture_output=True,
                                      text=True, timeout=5)
                info["services"][name] = proc.stdout.strip() if proc.returncode == 0 else "inactive"
            except Exception:
                info["services"][name] = "unknown"
        return info
