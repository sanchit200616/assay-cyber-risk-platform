"""SSRF guard for any outbound fetch. The baseline product makes NO outbound requests;
this guard exists so that adding a feed adapter cannot bypass the checks."""
from __future__ import annotations

import ipaddress
import socket
from typing import Callable
from urllib.parse import urlsplit

ALLOWED_PORTS = {80, 443}


class SSRFError(ValueError):
    pass


def _is_public(ip: ipaddress._BaseAddress) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified)


def validate_outbound_url(url: str, resolver: Callable = socket.getaddrinfo, allow_hosts: set | None = None) -> str:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise SSRFError("only http/https URLs are allowed")
    if parts.username or parts.password:
        raise SSRFError("credentials in URLs are not allowed")
    host = parts.hostname
    if not host:
        raise SSRFError("URL has no host")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise SSRFError(f"port {port} is not allowed")
    if allow_hosts is not None and host.lower() not in allow_hosts:
        raise SSRFError("host is not on the allow-list")
    try:
        literal = ipaddress.ip_address(host)
        addrs = [literal]
    except ValueError:
        try:
            infos = resolver(host, port, proto=socket.IPPROTO_TCP)
        except OSError as exc:
            raise SSRFError("host did not resolve") from exc
        addrs = [ipaddress.ip_address(i[4][0]) for i in infos]
    if not addrs:
        raise SSRFError("host did not resolve")
    for a in addrs:  # every resolved address must be public (defeats DNS answers mixing public/private)
        if not _is_public(a):
            raise SSRFError("target address is not publicly routable")
    return url
