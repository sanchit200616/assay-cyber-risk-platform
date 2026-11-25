"""Demo seeding. Everything created here is SYNTHETIC and flagged as such in the UI and reports."""
from __future__ import annotations

import pathlib
import secrets

from .service import Platform

CORPUS = pathlib.Path(__file__).resolve().parent / "data" / "corpus"


def seed_demo(p: Platform, passwords: dict | None = None) -> dict:
    """Idempotent-ish: refuses to run twice. Returns generated credentials (shown once, never stored in plain text)."""
    if p.db.one("SELECT 1 FROM users LIMIT 1"):
        raise RuntimeError("database already contains users; seed only a fresh database")
    creds = passwords or {r: secrets.token_urlsafe(12) for r in ("admin", "assessor", "analyst")}
    users = {"admin": "admin@demo.example", "assessor": "assessor@demo.example", "analyst": "analyst@demo.example"}
    for role, email in users.items():
        p.create_user(email, creds[role], role, actor="seed")
    for path in sorted(CORPUS.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        p.ingest_document(text.splitlines()[0].lstrip("# ").strip(), text, "synthetic-corpus", "text/markdown", synthetic=True)
    p.collect_intelligence("sample", None, "seed")

    nw = p.create_vendor({"name": "Northwind Payments Ltd", "category": "Payment processing", "domain": "northwind-payments.example", "criticality": "critical", "synthetic": True}, "seed")
    hl = p.create_vendor({"name": "Helios Logistics", "category": "Logistics", "domain": "helios-logistics.example", "criticality": "high", "synthetic": True}, "seed")
    qa = p.create_vendor({"name": "Quartz Analytics", "category": "Data analytics", "domain": "quartz-analytics.example", "criticality": "medium", "synthetic": True}, "seed")
    for vid, name, typ, ident, env, exp in [
        (nw["id"], "Payments API", "service", "api.northwind-payments.example", "production", "internet"),
        (nw["id"], "Edge host", "host", "203.0.113.10", "production", "internet"),
        (nw["id"], "Reporting DB", "database", "db.northwind-payments.example", "production", "internal"),
        (hl["id"], "Tracking portal", "application", "track.helios-logistics.example", "production", "internet"),
        (qa["id"], "Analytics workbench", "application", "bench.quartz-analytics.example", "staging", "partner")]:
        p.create_asset({"vendor_id": vid, "name": name, "type": typ, "identifier": ident, "environment": env, "exposure": exp}, "seed")

    a = p.create_assessment(nw["id"], "Annual third-party assessment 2026", "seed")
    payments = next(x for x in p.get_vendor(nw["id"])["assets"] if x["name"] == "Payments API")
    f1 = p.add_finding(a["id"], {"title": "Remote code execution in web framework", "factor": "vulnerability", "severity": "high", "source": "vendor scan report",
                                 "cve_id": "CVE-2099-10001", "confidence": 0.8, "observed_at": "2026-11-05T00:00:00Z", "asset_id": payments["id"]}, "seed")
    p.add_finding(a["id"], {"title": "TLS library denial of service", "factor": "vulnerability", "severity": "medium", "source": "vendor scan report",
                            "cve_id": "CVE-2099-10002", "confidence": 0.7, "observed_at": "2026-10-28T00:00:00Z"}, "seed")
    p.add_finding(a["id"], {"title": "No evidence of MFA on administrative accounts", "factor": "compliance", "severity": "high", "source": "questionnaire",
                            "confidence": 0.6, "observed_at": "2026-10-20T00:00:00Z"}, "seed")
    p.add_finding(a["id"], {"title": "Backup restore test not performed this year", "factor": "compliance", "severity": "medium", "source": "questionnaire",
                            "confidence": 0.7, "observed_at": "2026-10-20T00:00:00Z"}, "seed")
    p.add_finding(a["id"], {"title": "Credential-harvesting incident under investigation", "factor": "investigation", "severity": "medium", "source": "incident ticket",
                            "confidence": 0.65, "observed_at": "2026-11-12T00:00:00Z"}, "seed")
    p.add_evidence({"finding_id": f1["id"], "source": "scanner export", "note": "Version banner matches the affected release (synthetic).",
                    "content": "synthetic scanner export for Northwind Payments API", "confidence": 0.7, "observed_at": "2026-11-05T00:00:00Z"}, "seed")
    p.run_assessment(a["id"], "seed")
    return {"credentials": {users[r]: creds[r] for r in users}, "vendors": [nw["id"], hl["id"], qa["id"]], "assessment_id": a["id"]}
