"""Password hashing with scrypt (stdlib). Format: scrypt$N$r$p$salt$hash (base64)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os

N, R, P = 2 ** 14, 8, 1
MIN_LEN = 10


def _b(x: bytes) -> str:
    return base64.b64encode(x).decode()


def hash_password(password: str) -> str:
    if len(password) < MIN_LEN:
        raise ValueError(f"password must be at least {MIN_LEN} characters")
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=N, r=R, p=P, dklen=32)
    return f"scrypt${N}${R}${P}${_b(salt)}${_b(dk)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt, expected = stored.split("$")
        if scheme != "scrypt":
            return False
        dk = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p), dklen=32)
        return hmac.compare_digest(dk, base64.b64decode(expected))
    except Exception:
        return False


DUMMY_HASH = hash_password("dummy-password-for-timing")  # equalises timing for unknown users
