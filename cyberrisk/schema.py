"""Strict request validation: unknown fields rejected, types/lengths/enums enforced."""
from __future__ import annotations

import re
from typing import Any

from .domain.policy import FACTORS, SEVERITIES
from .domain.risk import iso
from .errors import Invalid
from .security.sanitize import clean_text

_ID = re.compile(r"^[a-z]{3}_[0-9a-f]{16}$")


def S(max=200, min=1, req=True):
    return {"t": "str", "max": max, "min": min, "req": req}


def E(choices, req=True):
    return {"t": "enum", "choices": tuple(choices), "req": req}


def F(lo=0.0, hi=1.0, req=True):
    return {"t": "float", "lo": lo, "hi": hi, "req": req}


def I(lo=1, hi=100, req=False):
    return {"t": "int", "lo": lo, "hi": hi, "req": req}


def DT(req=True):
    return {"t": "dt", "req": req}


def ID(req=True):
    return {"t": "id", "req": req}


def B(req=False):
    return {"t": "bool", "req": req}


def L(req=True, max_items=500):
    return {"t": "list", "req": req, "max_items": max_items}


def _one(name: str, spec: dict, v: Any):
    t = spec["t"]
    if t == "str":
        if not isinstance(v, str):
            raise ValueError("must be a string")
        v = clean_text(v, spec["max"])
        if len(v) < spec["min"]:
            raise ValueError("must not be empty")
        return v
    if t == "enum":
        if v not in spec["choices"]:
            raise ValueError(f"must be one of {list(spec['choices'])}")
        return v
    if t == "float":
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            raise ValueError("must be a number")
        if not spec["lo"] <= v <= spec["hi"]:
            raise ValueError(f"must be between {spec['lo']} and {spec['hi']}")
        return float(v)
    if t == "int":
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError("must be an integer")
        if not spec["lo"] <= v <= spec["hi"]:
            raise ValueError(f"must be between {spec['lo']} and {spec['hi']}")
        return v
    if t == "dt":
        try:
            return iso(v)
        except Exception as exc:  # noqa: BLE001
            raise ValueError("must be an ISO-8601 timestamp") from exc
    if t == "id":
        if not isinstance(v, str) or not _ID.match(v):
            raise ValueError("must be a valid identifier")
        return v
    if t == "bool":
        if not isinstance(v, bool):
            raise ValueError("must be a boolean")
        return v
    if t == "list":
        if not isinstance(v, list) or len(v) > spec["max_items"]:
            raise ValueError(f"must be a list of at most {spec['max_items']} items")
        return v
    raise AssertionError(t)


def validate(body: Any, spec: dict, partial: bool = False) -> dict:
    if not isinstance(body, dict):
        raise Invalid("request body must be a JSON object")
    errors = {k: "unknown field" for k in body if k not in spec}
    out = {}
    for name, sp in spec.items():
        if name not in body or body[name] is None:
            if sp["req"] and not partial:
                errors[name] = "required"
            continue
        try:
            out[name] = _one(name, sp, body[name])
        except ValueError as exc:
            errors[name] = str(exc)
    if errors:
        raise Invalid("request validation failed", errors)
    return out


VENDOR = {"name": S(), "category": S(100), "domain": S(253), "criticality": E(("low", "medium", "high", "critical")), "synthetic": B()}
VENDOR_PATCH = {**{k: v for k, v in VENDOR.items() if k != "synthetic"}, "status": E(("active", "inactive"), req=False)}
ASSET = {"vendor_id": ID(), "name": S(), "type": E(("host", "service", "application", "database", "other")), "identifier": S(253),
         "environment": E(("production", "staging", "development")), "exposure": E(("internal", "partner", "internet"))}
ASSESSMENT = {"vendor_id": ID(), "title": S()}
FINDING = {"title": S(), "description": S(2000, min=0, req=False), "factor": E(FACTORS), "severity": E(SEVERITIES), "source": S(120),
           "cve_id": S(40, req=False), "confidence": F(), "observed_at": DT(), "asset_id": ID(req=False)}
FINDING_PATCH = {"title": S(), "description": S(2000, min=0), "severity": E(SEVERITIES), "confidence": F(),
                 "status": E(("open", "in_progress", "accepted", "resolved"))}
EVIDENCE = {"finding_id": ID(), "source": S(120), "uri": S(500, req=False), "content": S(100000, req=False),
            "content_hash": S(64, req=False), "note": S(1000, min=0, req=False), "confidence": F(), "observed_at": DT()}
COLLECT = {"source": E(("sample", "inline")), "records": L(req=False, max_items=1000)}
DOCUMENT = {"title": S(), "content": S(200000), "source": S(200, req=False), "media_type": E(("text/plain", "text/markdown"), req=False)}
RAGQ = {"question": S(500), "top_k": I(1, 10)}
WORKFLOW = {"assessment_id": ID(), "finding_id": ID(req=False), "title": S(), "owner": S(120, req=False), "due_date": S(10, req=False)}
WORKFLOW_PATCH = {"title": S(), "status": E(("todo", "doing", "blocked", "done")), "owner": S(120), "due_date": S(10)}
REPORT = {"assessment_id": ID(), "format": E(("markdown", "html"), req=False), "run_id": ID(req=False)}
LOGIN = {"email": S(254), "password": S(200)}
USER = {"email": S(254), "password": S(200), "role": E(("analyst", "assessor", "admin"))}
APIKEY = {"name": S(80), "scopes": L(max_items=40)}
