"""Indicator normalisation: refang, detect type, canonicalise. Pure functions, no network."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

TYPES = ("ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email", "cve")
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_EMAIL = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@([A-Za-z0-9.\-]+)$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
_HEX = {32: "md5", 40: "sha1", 64: "sha256"}


@dataclass(frozen=True)
class Normalized:
    type: str
    value: str
    original: str


def refang(v: str) -> str:
    v = v.strip()
    v = re.sub(r"^hxxp", "http", v, flags=re.I)
    for a, b in (("[.]", "."), ("(.)", "."), ("[dot]", "."), ("[@]", "@"), ("[at]", "@"), ("[:]", ":")):
        v = v.replace(a, b)
    return v


def _domain(v: str) -> str:
    v = v.strip().rstrip(".").lower()
    try:
        v = v.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("invalid domain") from exc
    labels = v.split(".")
    if len(v) > 253 or len(labels) < 2 or not all(_LABEL.match(l) for l in labels) or labels[-1].isdigit():
        raise ValueError("invalid domain")
    return v


def normalize(value: str, hint: str | None = None) -> Normalized:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("empty indicator")
    original = value
    v = refang(value)
    if len(v) > 2048:
        raise ValueError("indicator too long")
    if re.match(r"^[a-z][a-z0-9+.\-]*://", v, re.I):
        parts = urlsplit(v)
        if parts.scheme.lower() not in ("http", "https", "ftp") or not parts.hostname:
            raise ValueError("invalid url")
        host = parts.hostname
        try:
            ipaddress.ip_address(host)
        except ValueError:
            host = _domain(host)
        default = {"http": 80, "https": 443, "ftp": 21}[parts.scheme.lower()]
        netloc = f"[{host}]" if ":" in host else host
        if parts.port and parts.port != default:
            netloc += f":{parts.port}"
        return Normalized("url", urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, "")), original)
    m = _EMAIL.match(v)
    if m:
        return Normalized("email", v.lower().split("@")[0] + "@" + _domain(m.group(1)), original)
    if _CVE.match(v):
        return Normalized("cve", v.upper(), original)
    if re.fullmatch(r"[0-9a-fA-F]+", v) and len(v) in _HEX:
        return Normalized(_HEX[len(v)], v.lower(), original)
    try:
        ip = ipaddress.ip_address(v)
        return Normalized("ipv4" if ip.version == 4 else "ipv6", ip.compressed, original)
    except ValueError:
        pass
    return Normalized("domain", _domain(v), original)


def host_of(n: Normalized) -> str | None:
    if n.type == "domain":
        return n.value
    if n.type == "url":
        return urlsplit(n.value).hostname
    if n.type == "email":
        return n.value.split("@")[1]
    return None
