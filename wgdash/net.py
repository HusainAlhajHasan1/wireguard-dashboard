"""Tiny HTTP helper built on the standard library (no requests dependency)."""
from __future__ import annotations

import json
import secrets
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Iterable

UA = "WireGuard-Dashboard/1.0"
CTX = ssl.create_default_context()


def _request(url: str, method: str = "GET", data: bytes | None = None,
             headers: dict | None = None, timeout: int = 15):
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("User-Agent", UA)
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    with urllib.request.urlopen(req, timeout=timeout, context=CTX) as resp:
        return resp.read(), resp.headers.get("Content-Type", "")


def get_json(url: str, timeout: int = 8, headers: dict | None = None):
    body, _ = _request(url, "GET", headers=headers, timeout=timeout)
    return json.loads(body.decode("utf-8", "replace"))


def post_json(url: str, payload: dict, timeout: int = 15):
    data = json.dumps(payload).encode("utf-8")
    body, _ = _request(url, "POST", data=data,
                       headers={"Content-Type": "application/json"}, timeout=timeout)
    return json.loads(body.decode("utf-8", "replace"))


def post_form(url: str, fields: dict, files: Iterable[tuple] = (), timeout: int = 30):
    """Multipart/form-data POST.  files: (field, filename, bytes, mime)."""
    boundary = "----wgdash" + secrets.token_hex(12)
    chunks = []

    def add_field(name, value):
        chunks.append(("--" + boundary + "\r\n").encode())
        chunks.append(('Content-Disposition: form-data; name="{}"\r\n\r\n'.format(name)).encode())
        chunks.append(str(value).encode("utf-8"))
        chunks.append(b"\r\n")

    for key, value in fields.items():
        if isinstance(value, (dict, list, tuple)):
            value = json.dumps(value)
        if value is None:
            continue
        add_field(key, value)
    for field, filename, content, mime in files:
        chunks.append(("--" + boundary + "\r\n").encode())
        chunks.append(('Content-Disposition: form-data; name="{}"; filename="{}"\r\n'.format(
            field, filename.replace('"', ""))).encode())
        chunks.append(("Content-Type: {}\r\n\r\n".format(mime)).encode())
        chunks.append(content)
        chunks.append(b"\r\n")
    chunks.append(("--" + boundary + "--\r\n").encode())
    data = b"".join(chunks)
    body, _ = _request(url, "POST", data=data, timeout=timeout,
                       headers={"Content-Type": "multipart/form-data; boundary=" + boundary})
    try:
        return json.loads(body.decode("utf-8", "replace"))
    except Exception:
        return {"ok": False, "raw": body.decode("utf-8", "replace")[:500]}


def public_ipv4(timeout: int = 5) -> str:
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"):
        try:
            body, _ = _request(url, timeout=timeout)
            candidate = body.decode().strip()
            if candidate and len(candidate) < 46:
                return candidate
        except Exception:
            continue
    return ""
