"""Versioned, content-hashed risk policy. Pure domain: no framework imports.

Policy v1.0 uses the weights from the project brief (0.30/0.25/0.20/0.15/0.10).
Level bands are half-open intervals on the score rounded to 2 decimals:
[0,20) Minimal, [20,40) Low, [40,60) Medium, [60,80) High, [80,100] Critical.
(The brief lists integer bands, which leave gaps such as 19.5; half-open
intervals close those gaps without moving any threshold.)
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from decimal import Decimal, ROUND_HALF_UP
from typing import Mapping, Tuple

FACTORS = ("vulnerability", "threat", "exposure", "compliance", "investigation")
SEVERITIES = ("none", "info", "low", "medium", "high", "critical")
Q2 = Decimal("0.01")


class PolicyError(ValueError):
    pass


def q2(value) -> Decimal:
    return Decimal(value).quantize(Q2, rounding=ROUND_HALF_UP)


@dataclass(frozen=True)
class RiskPolicy:
    version: str
    weights: Mapping[str, Decimal]
    bands: Tuple[Tuple[str, Decimal], ...]
    severity_points: Mapping[str, Decimal]
    stale_after_days: int = 90
    low_confidence_below: Decimal = Decimal("0.5")
    min_coverage: Decimal = Decimal("0.5")

    def __post_init__(self):
        if set(self.weights) != set(FACTORS):
            raise PolicyError("weights must define exactly the five risk factors")
        if any(w < 0 for w in self.weights.values()):
            raise PolicyError("weights must be non-negative")
        if sum(self.weights.values()) != Decimal("1"):
            raise PolicyError("weights must sum to 1.0")
        lowers = [b[1] for b in self.bands]
        if not self.bands or lowers[0] != 0 or lowers != sorted(set(lowers)):
            raise PolicyError("bands must start at 0 and be strictly ascending")
        if set(self.severity_points) != set(SEVERITIES):
            raise PolicyError("severity_points must cover all severities")
        if any(not (0 <= p <= 100) for p in self.severity_points.values()):
            raise PolicyError("severity points must be within 0..100")
        if self.stale_after_days <= 0:
            raise PolicyError("stale_after_days must be positive")

    def level_for(self, score: Decimal) -> str:
        if score < 0 or score > 100:
            raise PolicyError("score out of range 0..100")
        name = self.bands[0][0]
        for band, lower in self.bands:
            if score >= lower:
                name = band
        return name

    def lower_bound_of(self, level: str) -> Decimal:
        return dict(self.bands)[level]

    def level_below(self, level: str):
        names = [b[0] for b in self.bands]
        i = names.index(level)
        return names[i - 1] if i > 0 else None

    def canonical(self) -> dict:
        return {
            "version": self.version,
            "weights": {k: str(self.weights[k]) for k in FACTORS},
            "bands": [[n, str(l)] for n, l in self.bands],
            "severity_points": {k: str(self.severity_points[k]) for k in SEVERITIES},
            "stale_after_days": self.stale_after_days,
            "low_confidence_below": str(self.low_confidence_below),
            "min_coverage": str(self.min_coverage),
        }

    def content_hash(self) -> str:
        blob = json.dumps(self.canonical(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode()).hexdigest()


def _d(x) -> Decimal:
    return Decimal(str(x))


DEFAULT_POLICY = RiskPolicy(
    version="1.0",
    weights={"vulnerability": _d("0.30"), "threat": _d("0.25"), "exposure": _d("0.20"),
             "compliance": _d("0.15"), "investigation": _d("0.10")},
    bands=(("Minimal", _d(0)), ("Low", _d(20)), ("Medium", _d(40)), ("High", _d(60)), ("Critical", _d(80))),
    severity_points={"none": _d(0), "info": _d(10), "low": _d(25), "medium": _d(50), "high": _d(75), "critical": _d(95)},
)

POLICIES = {DEFAULT_POLICY.version: DEFAULT_POLICY}
