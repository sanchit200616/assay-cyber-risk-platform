"""Correlation: corroborate signals per indicator and tie indicators to vendors/assets."""
from __future__ import annotations

from typing import Iterable, List

from .normalize import Normalized, host_of


def corroborated_confidence(confidences: Iterable[float]) -> float:
    """Independent sources compound: 1 - prod(1 - c). Two 0.6 sources -> 0.84."""
    remaining = 1.0
    for c in confidences:
        remaining *= 1.0 - max(0.0, min(1.0, c))
    return round(1.0 - remaining, 4)


def _host_matches(host: str | None, domain: str) -> bool:
    return bool(host) and (host == domain or host.endswith("." + domain))


def match_target(indicator: Normalized, vendor_domain: str, assets: List[dict]) -> str | None:
    """Return a human-readable reason if the indicator concerns this vendor, else None."""
    vd = vendor_domain.lower()
    host = host_of(indicator)
    if _host_matches(host, vd):
        return f"{indicator.type} host '{host}' is within vendor domain {vd}"
    for a in assets:
        ident = a["identifier"].lower()
        if indicator.type in ("ipv4", "ipv6") and indicator.value == ident:
            return f"IP matches asset '{a['name']}'"
        if host and host == ident:
            return f"host matches asset '{a['name']}'"
    return None
