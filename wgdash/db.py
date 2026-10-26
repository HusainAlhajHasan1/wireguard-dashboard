"""SQLite store: peers, live state, history, settings, audit log, shares."""
from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
import time
from pathlib import Path

from . import crypto

DEFAULT_SETTINGS = {
    "online_timeout": 180,
    "sample_interval": 30,
    "history_days": 90,
    "default_allowed_ips": "0.0.0.0/0, ::/0",
    "default_dns": "1.1.1.1, 8.8.8.8",
    "default_mtu": 1420,
    "default_keepalive": 25,
    "default_expiry_days": 0,
    "default_quota_gb": 0,
    "default_full_tunnel": True,
    "use_psk": True,
    "enforce_quota": True,
    "enforce_expiry": True,
    "telegram_token": "",
    "telegram_admins": [],
    "notify_connect": True,
    "notify_disconnect": True,
    "notify_quota": True,
    "notify_expiry": True,
    "notify_peer_changes": True,
    "notify_daily": False,
    "daily_report_time": "09:00",
    "geoip_provider": "auto",
    "geoip_token": "",
    "endpoint": "",
    "theme": "midnight",
    "auto_backup": True,
    "share_link_hours": 24,
    "require_2fa": False,
}

SECRET_SETTINGS = ("telegram_token", "geoip_token")

PEER_COLUMNS = (
    "id", "pubkey", "name", "vpn_ip", "privkey", "psk", "created_at",
    "expires_at", "quota_bytes", "enabled", "notes", "telegram_chat_id",
    "dns", "allowed_ips", "mtu", "keepalive", "last_rx", "last_tx",
    "total_rx", "total_tx", "last_handshake", "last_endpoint", "last_ip",
    "last_seen", "online", "country", "country_code", "city", "isp",
    "disabled_reason",
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS secrets (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL, totp_secret TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL, last_login INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS peers (
  id TEXT PRIMARY KEY, pubkey TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
  vpn_ip TEXT NOT NULL, privkey TEXT NOT NULL DEFAULT '', psk TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL DEFAULT 0,
  quota_bytes INTEGER NOT NULL DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1,
  notes TEXT NOT NULL DEFAULT '', telegram_chat_id TEXT NOT NULL DEFAULT '',
  dns TEXT NOT NULL DEFAULT '', allowed_ips TEXT NOT NULL DEFAULT '',
  mtu INTEGER NOT NULL DEFAULT 0, keepalive INTEGER NOT NULL DEFAULT 25,
  last_rx INTEGER NOT NULL DEFAULT 0, last_tx INTEGER NOT NULL DEFAULT 0,
  total_rx INTEGER NOT NULL DEFAULT 0, total_tx INTEGER NOT NULL DEFAULT 0,
  last_handshake INTEGER NOT NULL DEFAULT 0, last_endpoint TEXT NOT NULL DEFAULT '',
  last_ip TEXT NOT NULL DEFAULT '', last_seen INTEGER NOT NULL DEFAULT 0,
  online INTEGER NOT NULL DEFAULT 0, country TEXT NOT NULL DEFAULT '',
  country_code TEXT NOT NULL DEFAULT '', city TEXT NOT NULL DEFAULT '',
  isp TEXT NOT NULL DEFAULT '', disabled_reason TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_peers_pubkey ON peers(pubkey);
CREATE TABLE IF NOT EXISTS samples (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, peer_id TEXT NOT NULL,
  rx INTEGER NOT NULL DEFAULT 0, tx INTEGER NOT NULL DEFAULT 0,
  total_rx INTEGER NOT NULL DEFAULT 0, total_tx INTEGER NOT NULL DEFAULT 0,
  online INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples(ts);
CREATE INDEX IF NOT EXISTS idx_samples_peer ON samples(peer_id, ts);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, type TEXT NOT NULL,
  peer_id TEXT NOT NULL DEFAULT '', peer_name TEXT NOT NULL DEFAULT '',
  message TEXT NOT NULL, detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, actor TEXT NOT NULL,
  action TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '', ip TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS shares (
  token TEXT PRIMARY KEY, peer_id TEXT NOT NULL, created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL, max_uses INTEGER NOT NULL DEFAULT 1,
  uses INTEGER NOT NULL DEFAULT 0, created_by TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS api_tokens (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL, last_used INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS geo_cache (
  ip TEXT PRIMARY KEY, data TEXT NOT NULL, ts INTEGER NOT NULL
);
"""


class Database:
    def __init__(self, db_path: str, key: bytes):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.key = key
        self.path = db_path
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(db_path, check_same_thread=False, timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        with self.lock:
            self.conn.executescript(SCHEMA)
            self.conn.commit()
        try:
            import os
            os.chmod(db_path, 0o600)
        except OSError:
            pass

    # ---------------- low level ----------------
    def q(self, sql: str, args=()):
        with self.lock:
            cur = self.conn.execute(sql, args)
            rows = [dict(r) for r in cur.fetchall()]
            self.conn.commit()
            return rows

    def q1(self, sql: str, args=()):
        rows = self.q(sql, args)
        return rows[0] if rows else None

    def execute(self, sql: str, args=()):
        with self.lock:
            cur = self.conn.execute(sql, args)
            self.conn.commit()
            return cur.lastrowid

    # ---------------- settings ----------------
    def settings(self, include_secrets: bool = False) -> dict:
        out = dict(DEFAULT_SETTINGS)
        for row in self.q("SELECT key, value FROM settings"):
            try:
                out[row["key"]] = json.loads(row["value"])
            except Exception:
                out[row["key"]] = row["value"]
        for key in SECRET_SETTINGS:
            value = self.get_secret(key)
            out[key] = value if include_secrets else ("*" * 8 if value else "")
        return out

    def set_settings(self, patch: dict) -> dict:
        allowed = set(DEFAULT_SETTINGS)
        for key, value in patch.items():
            if key not in allowed:
                continue
            if key in SECRET_SETTINGS:
                if value and set(str(value)) == {"*"}:  # masked UI value => unchanged
                    continue
                self.set_secret(key, str(value or ""))
                continue
            self.execute("INSERT INTO settings(key,value) VALUES(?,?) "
                         "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                         (key, json.dumps(value)))
        return self.settings(include_secrets=True)

    def get_secret(self, key: str) -> str:
        row = self.q1("SELECT value FROM secrets WHERE key=?", (key,))
        if not row or not row["value"]:
            return ""
        try:
            return crypto.decrypt(self.key, row["value"])
        except Exception:
            return ""

    def set_secret(self, key: str, value: str):
        blob = crypto.encrypt(self.key, value) if value else ""
        self.execute("INSERT INTO secrets(key,value) VALUES(?,?) "
                     "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, blob))

    def meta(self, key: str, default=None):
        row = self.q1("SELECT value FROM meta WHERE key=?", (key,))
        if not row:
            return default
        try:
            return json.loads(row["value"])
        except Exception:
            return row["value"]

    def set_meta(self, key: str, value):
        self.execute("INSERT INTO meta(key,value) VALUES(?,?) "
                     "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                     (key, json.dumps(value)))

    # ---------------- admins ----------------
    def admins(self):
        return self.q("SELECT id, username, totp_secret <> '' AS has_2fa, created_at, last_login FROM admins")

    def admin(self, username: str):
        return self.q1("SELECT * FROM admins WHERE username=?", (username,))

    def admin_by_id(self, admin_id: int):
        return self.q1("SELECT * FROM admins WHERE id=?", (admin_id,))

    def create_admin(self, username: str, password_hash: str):
        return self.execute("INSERT OR REPLACE INTO admins(username,password_hash,created_at) VALUES(?,?,?)",
                            (username, password_hash, int(time.time())))

    def update_admin(self, admin_id: int, patch: dict):
        for key in ("username", "password_hash", "totp_secret", "last_login"):
            if key in patch:
                self.execute("UPDATE admins SET {}=? WHERE id=?".format(key), (patch[key], admin_id))

    def delete_admin(self, admin_id: int):
        self.execute("DELETE FROM admins WHERE id=?", (admin_id,))

    # ---------------- peers ----------------
    def peers(self) -> list:
        return self.q("SELECT * FROM peers ORDER BY created_at ASC, name ASC")

    def peer(self, ident: str):
        return self.q1("SELECT * FROM peers WHERE id=? OR name=? OR pubkey=? LIMIT 1",
                       (ident, ident, ident))

    def peer_by_pubkey(self, pubkey: str):
        return self.q1("SELECT * FROM peers WHERE pubkey=?", (pubkey,))

    NUMERIC_COLUMNS = {"expires_at", "quota_bytes", "enabled", "mtu", "keepalive",
                      "last_rx", "last_tx", "total_rx", "total_tx", "last_handshake",
                      "last_seen", "online", "created_at"}

    def add_peer(self, data: dict):
        payload = {}
        for col in PEER_COLUMNS:
            value = data.get(col)
            if value is None:
                value = 0 if col in self.NUMERIC_COLUMNS else ""
            payload[col] = value
        cols = ",".join(PEER_COLUMNS)
        marks = ",".join("?" for _ in PEER_COLUMNS)
        self.execute("INSERT INTO peers({}) VALUES({})".format(cols, marks),
                     tuple(payload[c] for c in PEER_COLUMNS))
        return self.peer(data["id"])

    def update_peer(self, peer_id: str, patch: dict):
        allowed = set(PEER_COLUMNS) - {"id"}
        keys = [k for k in patch if k in allowed]
        if not keys:
            return self.peer(peer_id)
        sql = "UPDATE peers SET " + ",".join("{}=?".format(k) for k in keys) + " WHERE id=?"
        self.execute(sql, tuple(patch[k] for k in keys) + (peer_id,))
        return self.peer(peer_id)

    def delete_peer(self, peer_id: str):
        self.execute("DELETE FROM peers WHERE id=?", (peer_id,))

    # ---------------- history ----------------
    def add_sample(self, ts, peer_id, rx, tx, total_rx, total_tx, online):
        self.execute("INSERT INTO samples(ts,peer_id,rx,tx,total_rx,total_tx,online) VALUES(?,?,?,?,?,?,?)",
                     (ts, peer_id, rx, tx, total_rx, total_tx, 1 if online else 0))

    def traffic_series(self, since: int, bucket: int = 3600, peer_id: str | None = None):
        where = "WHERE ts>=?"
        args = [since]
        if peer_id:
            where += " AND peer_id=?"
            args.append(peer_id)
        rows = self.q(
            "SELECT (ts/?)*? AS bucket, SUM(rx) AS rx, SUM(tx) AS tx, "
            "MAX(total_rx) AS cum_rx, MAX(total_tx) AS cum_tx "
            "FROM samples {} GROUP BY bucket ORDER BY bucket ASC".format(where),
            tuple([bucket, bucket] + args))
        return [{"ts": r["bucket"], "rx": r["rx"] or 0, "tx": r["tx"] or 0,
                 "cum_rx": r["cum_rx"] or 0, "cum_tx": r["cum_tx"] or 0} for r in rows]

    def peer_samples(self, peer_id: str, since: int, limit: int = 500):
        return self.q("SELECT * FROM samples WHERE peer_id=? AND ts>=? ORDER BY ts DESC LIMIT ?",
                      (peer_id, since, limit))[::-1]

    def add_event(self, etype: str, message: str, peer_id: str = "",
                  peer_name: str = "", detail: dict | None = None, ts: int | None = None):
        return self.execute("INSERT INTO events(ts,type,peer_id,peer_name,message,detail) VALUES(?,?,?,?,?,?)",
                            (int(ts or time.time()), etype, peer_id, peer_name, message,
                             json.dumps(detail or {})))

    def events(self, limit: int = 100, peer_id: str | None = None):
        if peer_id:
            return self.q("SELECT * FROM events WHERE peer_id=? ORDER BY ts DESC, id DESC LIMIT ?",
                          (peer_id, limit))
        return self.q("SELECT * FROM events ORDER BY ts DESC, id DESC LIMIT ?", (limit,))

    def add_audit(self, actor: str, action: str, detail: str = "", ip: str = ""):
        return self.execute("INSERT INTO audit(ts,actor,action,detail,ip) VALUES(?,?,?,?,?)",
                            (int(time.time()), actor, action, detail, ip))

    def audit(self, limit: int = 200):
        return self.q("SELECT * FROM audit ORDER BY ts DESC, id DESC LIMIT ?", (limit,))

    def prune(self, days: int):
        cutoff = int(time.time()) - days * 86400
        self.execute("DELETE FROM samples WHERE ts<?", (cutoff,))
        self.execute("DELETE FROM events WHERE ts<?", (cutoff,))
        self.execute("DELETE FROM audit WHERE ts<?", (cutoff,))
        self.execute("DELETE FROM shares WHERE expires_at<?", (cutoff,))
        self.execute("DELETE FROM geo_cache WHERE ts<?", (cutoff,))

    # ---------------- share links ----------------
    def create_share(self, peer_id: str, hours: int = 24, max_uses: int = 10, created_by: str = ""):
        token = secrets.token_urlsafe(24)
        self.execute("INSERT INTO shares(token,peer_id,created_at,expires_at,max_uses,uses,created_by) "
                     "VALUES(?,?,?,?,?,0,?)",
                     (token, peer_id, int(time.time()), int(time.time()) + hours * 3600, max_uses, created_by))
        return token

    def share(self, token: str):
        return self.q1("SELECT * FROM shares WHERE token=?", (token,))

    def shares(self, peer_id: str | None = None):
        if peer_id:
            return self.q("SELECT * FROM shares WHERE peer_id=? ORDER BY created_at DESC", (peer_id,))
        return self.q("SELECT * FROM shares ORDER BY created_at DESC")

    def consume_share(self, token: str):
        row = self.share(token)
        if not row or row["expires_at"] < time.time() or row["uses"] >= row["max_uses"]:
            return None
        self.execute("UPDATE shares SET uses=uses+1 WHERE token=?", (token,))
        return self.peer(row["peer_id"])

    def revoke_share(self, token: str):
        self.execute("DELETE FROM shares WHERE token=?", (token,))

    # ---------------- API tokens ----------------
    def create_api_token(self, name: str) -> tuple:
        token = crypto.new_token(32)
        digest = hashlib.sha256(token.encode()).hexdigest()
        tid = secrets.token_hex(6)
        self.execute("INSERT INTO api_tokens(id,name,token_hash,created_at) VALUES(?,?,?,?)",
                     (tid, name, digest, int(time.time())))
        return tid, token

    def api_tokens(self):
        return self.q("SELECT id,name,created_at,last_used FROM api_tokens ORDER BY created_at DESC")

    def verify_api_token(self, token: str):
        digest = hashlib.sha256(token.encode()).hexdigest()
        row = self.q1("SELECT * FROM api_tokens WHERE token_hash=?", (digest,))
        if row:
            self.execute("UPDATE api_tokens SET last_used=? WHERE id=?", (int(time.time()), row["id"]))
        return row

    def delete_api_token(self, token_id: str):
        self.execute("DELETE FROM api_tokens WHERE id=?", (token_id,))

    # ---------------- geo cache ----------------
    def geo(self, ip: str, max_age: int = 7 * 86400):
        row = self.q1("SELECT * FROM geo_cache WHERE ip=?", (ip,))
        if row and row["ts"] > time.time() - max_age:
            try:
                return json.loads(row["data"])
            except Exception:
                pass
        return None

    def cache_geo(self, ip: str, data: dict):
        self.execute("INSERT INTO geo_cache(ip,data,ts) VALUES(?,?,?) "
                     "ON CONFLICT(ip) DO UPDATE SET data=excluded.data, ts=excluded.ts",
                     (ip, json.dumps(data), int(time.time())))
