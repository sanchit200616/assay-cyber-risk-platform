"""Source adapters. Baseline = local synthetic files / inline records; no live feeds, no network."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Protocol

from ..domain.risk import iso
from ..domain.policy import SEVERITIES
from .normalize import normalize

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


class Source(Protocol):
    name: str

    def fetch(self) -> list: ...


class LocalFileSource:
    def __init__(self, filename: str, name: str):
        self.name, self.path = name, DATA_DIR / filename

    def fetch(self) -> list:
        return json.loads(self.path.read_text(encoding="utf-8"))


class InlineSource:
    def __init__(self, records: list, name: str = "inline"):
        self.name, self._records = name, records

    def fetch(self) -> list:
        return self._records


@dataclass
class ParsedSignal:
    source: str
    source_record_id: str
    original: str
    type: str
    value: str
    severity: str
    confidence: float
    first_seen: str | None
    last_seen: str
    tags: list
    description: str
    synthetic: bool


def parse_records(records: list, default_source: str) -> tuple[List[ParsedSignal], List[dict]]:
    """Validate + normalise. Bad records are reported, never silently dropped and never fatal."""
    good, errors = [], []
    for idx, rec in enumerate(records):
        try:
            if not isinstance(rec, dict):
                raise ValueError("record must be an object")
            n = normalize(rec.get("indicator"))
            sev = rec.get("severity", "medium")
            if sev not in SEVERITIES:
                raise ValueError(f"unknown severity '{sev}'")
            conf = float(rec.get("confidence", 0.5))
            if not 0 <= conf <= 1:
                raise ValueError("confidence must be within 0..1")
            rid = str(rec.get("source_record_id") or "").strip()
            if not rid:
                raise ValueError("source_record_id is required")
            last = iso(rec["last_seen"]) if rec.get("last_seen") else None
            if last is None:
                raise ValueError("last_seen is required")
            tags = rec.get("tags", [])
            if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
                raise ValueError("tags must be a list of strings")
            good.append(ParsedSignal(str(rec.get("source") or default_source)[:80], rid[:120], n.original[:2048], n.type, n.value,
                                     sev, conf, iso(rec["first_seen"]) if rec.get("first_seen") else None, last,
                                     [t[:40] for t in tags[:12]], str(rec.get("description", ""))[:500], bool(rec.get("synthetic", False))))
        except (ValueError, TypeError, KeyError) as exc:
            errors.append({"index": idx, "error": str(exc)})
    return good, errors
