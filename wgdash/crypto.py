"""Small, dependency-free secret helpers.

Passwords use scrypt.  Sensitive values (client private keys, bot tokens, ...)
are encrypted with an encrypt-then-MAC stream cipher derived from a local key
file that is created with mode 0600 during installation.  This is deliberate:
the service must be able to re-issue a client config without a human typing a
password, so the key has to live next to the database.  Protect that file.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from pathlib import Path

MAC_KEY = b"wgdash-mac-key-v1"
ENC_KEY = b"wgdash-enc-key-v1"


def random_key() -> bytes:
    return secrets.token_bytes(32)


def load_or_create_key(path: str) -> bytes:
    p = Path(path)
    if p.exists():
        data = p.read_bytes()
        if len(data) >= 32:
            return data[:32]
    p.parent.mkdir(parents=True, exist_ok=True)
    key = random_key()
    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    os.chmod(p, 0o600)
    return key


def _stream(key: bytes, nonce: bytes, length: int) -> bytes:
    enc_key = hmac.new(key, ENC_KEY, hashlib.sha256).digest()
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hmac.new(enc_key, nonce + counter.to_bytes(4, "big"), hashlib.sha256).digest())
        counter += 1
    return bytes(out[:length])


def encrypt(key: bytes, plaintext) -> str:
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    nonce = secrets.token_bytes(16)
    stream = _stream(key, nonce, len(plaintext))
    ciphertext = bytes(a ^ b for a, b in zip(plaintext, stream))
    mac_key = hmac.new(key, MAC_KEY, hashlib.sha256).digest()
    tag = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()[:16]
    return base64.urlsafe_b64encode(nonce + ciphertext + tag).decode("ascii")


def decrypt(key: bytes, blob: str) -> str:
    raw = base64.urlsafe_b64decode(blob.encode("ascii"))
    if len(raw) < 32:
        raise ValueError("invalid ciphertext")
    nonce, ciphertext, tag = raw[:16], raw[16:-16], raw[-16:]
    mac_key = hmac.new(key, MAC_KEY, hashlib.sha256).digest()
    expected = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(tag, expected):
        raise ValueError("ciphertext authentication failed")
    stream = _stream(key, nonce, len(ciphertext))
    return bytes(a ^ b for a, b in zip(ciphertext, stream)).decode("utf-8")


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    n, r, p = 2 ** 14, 8, 1
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=32)
    return "scrypt${}${}${}${}${}".format(
        n, r, p,
        base64.b64encode(salt).decode(),
        base64.b64encode(digest).decode(),
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, n, r, p, salt, digest = encoded.split("$")
        if scheme != "scrypt":
            return False
        calc = hashlib.scrypt(
            password.encode("utf-8"),
            salt=base64.b64decode(salt),
            n=int(n), r=int(r), p=int(p), dklen=32,
        )
        return hmac.compare_digest(calc, base64.b64decode(digest))
    except Exception:
        return False


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def totp_code(secret_b32: str, step: int = 30) -> str:
    """RFC 6238 TOTP, base32 secret, 6 digits."""
    import time
    key = base64.b32decode(secret_b32.upper() + "=" * ((8 - len(secret_b32) % 8) % 8))
    counter = int(time.time() // step).to_bytes(8, "big")
    mac = hmac.new(key, counter, hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    code = (int.from_bytes(mac[off:off + 4], "big") & 0x7FFFFFFF) % 1000000
    return "{:06d}".format(code)


def verify_totp(secret_b32: str, code: str, window: int = 1) -> bool:
    import time
    if not code or not code.isdigit():
        return False
    now = int(time.time() // 30)
    for offset in range(-window, window + 1):
        key = base64.b32decode(secret_b32.upper() + "=" * ((8 - len(secret_b32) % 8) % 8))
        mac = hmac.new(key, (now + offset).to_bytes(8, "big"), hashlib.sha1).digest()
        off = mac[-1] & 0x0F
        expected = "{:06d}".format((int.from_bytes(mac[off:off + 4], "big") & 0x7FFFFFFF) % 1000000)
        if hmac.compare_digest(expected, code):
            return True
    return False


def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")
