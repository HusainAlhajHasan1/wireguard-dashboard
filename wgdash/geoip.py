"""Endpoint IP -> country/city/ISP with local caching and offline demo data."""
from __future__ import annotations

import hashlib
import ipaddress
import time
from urllib.parse import quote

from . import net
from .wireguard import DEMO_ENDPOINTS, flag_emoji

DEMO_BY_IP = {row[0]: row for row in DEMO_ENDPOINTS}


def _private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
    except ValueError:
        return True


def _blank(country="Unknown", code="", city="", isp="") -> dict:
    return {"country": country, "country_code": code, "city": city, "isp": isp,
            "flag": flag_emoji(code)}


def lookup(ip: str, db, settings: dict, demo: bool = False) -> dict:
    ip = (ip or "").strip()
    if not ip:
        return _blank()
    if _private(ip):
        return _blank("Private / Local", "", "", "LAN")
    cached = db.geo(ip)
    if cached:
        return cached

    result = None
    provider = settings.get("geoip_provider", "auto")
    token = db.get_secret("geoip_token") or settings.get("geoip_token", "")

    # 1. ipwho.is (HTTPS, no key)
    if provider in ("auto", "ipwho.is"):
        try:
            data = net.get_json("https://ipwho.is/" + quote(ip, safe=""), timeout=6)
            if data.get("success"):
                result = _blank(
                    data.get("country") or "Unknown",
                    (data.get("country_code") or "")[:2].upper(),
                    data.get("city") or data.get("region") or "",
                    (data.get("connection") or {}).get("isp") or data.get("isp") or "",
                )
        except Exception:
            pass
    # 2. ipinfo.io (works with optional token)
    if not result and provider in ("auto", "ipinfo.io"):
        try:
            url = "https://ipinfo.io/{}/json{}".format(quote(ip, safe=""),
                                                       "?token=" + token if token else "")
            data = net.get_json(url, timeout=6)
            if data.get("country") or data.get("city"):
                result = _blank(data.get("country") or "Unknown",
                                (data.get("country") or "")[:2].upper(),
                                data.get("city") or "", data.get("org") or "")
        except Exception:
            pass
    # 3. ip-api.com (HTTP fallback, 45 req/min)
    if not result and provider in ("auto", "ip-api.com"):
        try:
            url = ("http://ip-api.com/json/{}?fields=status,message,country,countryCode,"
                   "city,isp,query").format(quote(ip, safe=""))
            data = net.get_json(url, timeout=6)
            if data.get("status") == "success":
                result = _blank(data.get("country") or "Unknown",
                                (data.get("countryCode") or "")[:2].upper(),
                                data.get("city") or "", data.get("isp") or "")
        except Exception:
            pass

    if not result:
        if demo:
            row = DEMO_BY_IP.get(ip)
            if row:
                result = _blank(row[1], row[2], row[3], row[4])
            else:
                idx = int.from_bytes(hashlib.sha256(ip.encode()).digest()[:2], "big") % len(DEMO_ENDPOINTS)
                row = DEMO_ENDPOINTS[idx]
                result = _blank(row[1], row[2], row[3], row[4])
        else:
            result = _blank()
    result["ip"] = ip
    result["checked_at"] = int(time.time())
    db.cache_geo(ip, result)
    return result
