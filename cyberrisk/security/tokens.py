"""HS256 bearer tokens (JWT-compatible format) using only hmac/hashlib. Algorithm is pinned."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid


class TokenError(Exception):
    pass


def _enc(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def issue(secret: str, subject: str, role: str, ttl_seconds: int, now: float | None = None) -> str:
    now = time.time() if now is None else now
    header = _enc(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    body = _enc(json.dumps({"sub": subject, "role": role, "iat": int(now), "exp": int(now) + ttl_seconds,
                            "jti": uuid.uuid4().hex}, separators=(",", ":")).encode())
    sig = _enc(hmac.new(secret.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest())
    return f"{header}.{body}.{sig}"


def verify(secret: str, token: str, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    try:
        header_s, body_s, sig_s = token.split(".")
        header = json.loads(_dec(header_s))
        if header.get("alg") != "HS256":  # never trust the token to pick the algorithm ("none" attack)
            raise TokenError("unsupported algorithm")
        expected = hmac.new(secret.encode(), f"{header_s}.{body_s}".encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _dec(sig_s)):
            raise TokenError("bad signature")
        claims = json.loads(_dec(body_s))
    except TokenError:
        raise
    except Exception as exc:
        raise TokenError("malformed token") from exc
    if int(claims.get("exp", 0)) <= now:
        raise TokenError("token expired")
    return claims
