"""Application services / orchestrator. Coordinates repositories, intelligence, RAG, the domain
risk engine, the audit ledger and the job queue. Business rules live in `domain/`; this layer
only gathers evidence and persists outcomes inside transactions."""
from __future__ import annotations

import hashlib
import json
import re
import secrets
from datetime import datetime, timezone
from typing import Callable, Optional

from . import reports as rpt
from .config import Settings
from .db import Database, new_id, row_dict, utcnow_iso
from .domain import lifecycle
from .domain.policy import DEFAULT_POLICY, FACTORS, POLICIES, SEVERITIES, RiskPolicy
from .domain.risk import EvidenceItem, assess, iso, parse_dt, result_hash
from .errors import Conflict, Invalid, NotFound
from .intelligence import correlate
from .intelligence.normalize import normalize
from .intelligence.sources import InlineSource, LocalFileSource, parse_records
from .jobs import JobQueue
from .ledger import Ledger
from .observability import METRICS, correlation_id, event, span
from .rag.store import RagError, RagStore
from .security.passwords import DUMMY_HASH, hash_password, verify_password
from .security.rbac import ALL_PERMISSIONS, Principal, ROLE_PERMISSIONS

_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
_EXPOSURE_SEV = {"internet": "medium", "partner": "low", "internal": "info"}
_DOWNGRADE = {"medium": "low", "low": "info", "info": "info"}


def cvss_severity(cvss: float) -> str:
    return "critical" if cvss >= 9 else "high" if cvss >= 7 else "medium" if cvss >= 4 else "low" if cvss > 0 else "info"


def _max_sev(a: str, b: str) -> str:
    return a if _SEV_RANK[a] >= _SEV_RANK[b] else b


class Platform:
    def __init__(self, db: Database, settings: Settings, clock: Optional[Callable[[], datetime]] = None,
                 policy: RiskPolicy = DEFAULT_POLICY, embedder=None):
        self.db, self.settings, self.policy = db, settings, policy
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.ledger = Ledger(db)
        self.rag = RagStore(db, embedder)
        self.jobs = JobQueue(db, self.clock, settings.job_max_attempts, settings.job_backoff_base_seconds, settings.job_backoff_cap_seconds)

    # ------------------------------------------------------------------ users / keys
    def create_user(self, email: str, password: str, role: str, actor: str = "system") -> dict:
        email = email.strip().lower()
        if not re.fullmatch(r"[^@\s]{1,64}@[^@\s]+\.[^@\s]+", email):
            raise Invalid("invalid email")
        if role not in ROLE_PERMISSIONS:
            raise Invalid("unknown role")
        try:
            pw = hash_password(password)
        except ValueError as exc:
            raise Invalid(str(exc)) from exc
        with self.db.tx():
            if self.db.one("SELECT 1 FROM users WHERE email=?", (email,)):
                raise Conflict("a user with this email already exists")
            uid = new_id("usr")
            self.db.execute("INSERT INTO users VALUES(?,?,?,?,?,?)", (uid, email, pw, role, "active", utcnow_iso()))
            self.ledger.append(actor, "user.create", uid, detail={"role": role})
        return {"id": uid, "email": email, "role": role}

    def authenticate(self, email: str, password: str) -> Optional[dict]:
        row = self.db.one("SELECT * FROM users WHERE email=?", (email.strip().lower(),))
        ok = verify_password(password, row["password_hash"] if row else DUMMY_HASH)  # constant work for unknown users
        if row and ok and row["status"] == "active":
            return row_dict(row)
        return None

    def get_user(self, uid: str) -> Optional[dict]:
        r = self.db.one("SELECT id,email,role,status FROM users WHERE id=?", (uid,))
        return row_dict(r)

    def create_api_key(self, name: str, scopes: list, actor_id: str) -> dict:
        bad = [s for s in scopes if s not in ALL_PERMISSIONS]
        if bad or not scopes:
            raise Invalid("scopes must be a non-empty list of known permissions", {"unknown": bad})
        raw = "ak_" + secrets.token_urlsafe(32)
        kid = new_id("key")
        with self.db.tx():
            self.db.execute("INSERT INTO api_keys VALUES(?,?,?,?,?,?,NULL)",
                            (kid, name, hashlib.sha256(raw.encode()).hexdigest(), json.dumps(sorted(scopes)), actor_id, utcnow_iso()))
            self.ledger.append(actor_id, "apikey.create", kid, detail={"scopes": sorted(scopes)})
        return {"id": kid, "name": name, "scopes": sorted(scopes), "key": raw}  # raw key is shown exactly once

    def authenticate_api_key(self, raw: str) -> Optional[Principal]:
        row = self.db.one("SELECT * FROM api_keys WHERE key_hash=? AND revoked_at IS NULL", (hashlib.sha256(raw.encode()).hexdigest(),))
        if not row:
            return None
        return Principal(row["id"], f"apikey:{row['name']}", "apikey", frozenset(json.loads(row["scopes"])), "api_key")

    def revoke_api_key(self, key_id: str, actor: str) -> dict:
        with self.db.tx():
            cur = self.db.execute("UPDATE api_keys SET revoked_at=? WHERE id=? AND revoked_at IS NULL", (utcnow_iso(), key_id))
            if cur.rowcount == 0:
                raise NotFound("active API key not found")
            self.ledger.append(actor, "apikey.revoke", key_id)
        return {"id": key_id, "revoked": True}

    def list_api_keys(self) -> list:
        return [{**row_dict(r), "scopes": json.loads(r["scopes"])} for r in
                self.db.all("SELECT id,name,scopes,created_by,created_at,revoked_at FROM api_keys ORDER BY created_at DESC")]

    # ------------------------------------------------------------------ vendors / assets
    def create_vendor(self, d: dict, actor: str) -> dict:
        domain = self._domain(d["domain"])
        vid, now = new_id("ven"), utcnow_iso()
        with self.db.tx():
            self.db.execute("INSERT INTO vendors VALUES(?,?,?,?,?,?,?,?,?)",
                            (vid, d["name"], d["category"], domain, d["criticality"], "active", int(d.get("synthetic", False)), now, now))
            self.ledger.append(actor, "vendor.create", vid, detail={"name": d["name"]})
        return self.get_vendor(vid)

    @staticmethod
    def _domain(value: str) -> str:
        try:
            n = normalize(value)
        except ValueError as exc:
            raise Invalid(f"invalid domain: {exc}") from exc
        if n.type != "domain":
            raise Invalid("domain must be a bare domain name")
        return n.value

    def list_vendors(self, q: str | None = None, limit: int = 100, offset: int = 0) -> list:
        like = f"%{(q or '').lower()}%"
        rows = self.db.all(
            "SELECT v.*, (SELECT score FROM assessments a WHERE a.vendor_id=v.id AND a.status!='archived' AND a.score IS NOT NULL ORDER BY a.updated_at DESC LIMIT 1) latest_score, "
            "(SELECT level FROM assessments a WHERE a.vendor_id=v.id AND a.status!='archived' AND a.score IS NOT NULL ORDER BY a.updated_at DESC LIMIT 1) latest_level "
            "FROM vendors v WHERE lower(v.name) LIKE ? OR lower(v.domain) LIKE ? ORDER BY v.name LIMIT ? OFFSET ?",
            (like, like, max(1, min(limit, 200)), max(0, offset)))
        return [row_dict(r) for r in rows]

    def get_vendor(self, vid: str) -> dict:
        row = self.db.one("SELECT * FROM vendors WHERE id=?", (vid,))
        if not row:
            raise NotFound("vendor not found")
        v = row_dict(row)
        v["assets"] = [row_dict(a) for a in self.db.all("SELECT * FROM assets WHERE vendor_id=? ORDER BY name", (vid,))]
        v["assessments"] = [row_dict(a) for a in self.db.all(
            "SELECT id,title,status,score,level,updated_at FROM assessments WHERE vendor_id=? ORDER BY created_at DESC", (vid,))]
        return v

    def update_vendor(self, vid: str, patch: dict, actor: str) -> dict:
        self.get_vendor(vid)
        if "domain" in patch:
            patch = {**patch, "domain": self._domain(patch["domain"])}
        cols = [k for k in ("name", "category", "domain", "criticality", "status") if k in patch]
        if not cols:
            raise Invalid("no updatable fields supplied")
        with self.db.tx():
            self.db.execute(f"UPDATE vendors SET {','.join(c + '=?' for c in cols)}, updated_at=? WHERE id=?",
                            [patch[c] for c in cols] + [utcnow_iso(), vid])
            self.ledger.append(actor, "vendor.update", vid, detail={"fields": cols})
        return self.get_vendor(vid)

    def create_asset(self, d: dict, actor: str) -> dict:
        self.get_vendor(d["vendor_id"])
        try:
            n = normalize(d["identifier"])
        except ValueError as exc:
            raise Invalid(f"invalid identifier: {exc}") from exc
        if n.type not in ("ipv4", "ipv6", "domain"):
            raise Invalid("asset identifier must be an IP address or hostname")
        aid = new_id("ast")
        with self.db.tx():
            self.db.execute("INSERT INTO assets VALUES(?,?,?,?,?,?,?,?)",
                            (aid, d["vendor_id"], d["name"], d["type"], n.value, d["environment"], d["exposure"], utcnow_iso()))
            self.ledger.append(actor, "asset.create", aid, detail={"vendor": d["vendor_id"]})
        return row_dict(self.db.one("SELECT * FROM assets WHERE id=?", (aid,)))

    def list_assets(self, vendor_id: str | None = None) -> list:
        if vendor_id:
            return [row_dict(r) for r in self.db.all("SELECT * FROM assets WHERE vendor_id=? ORDER BY name", (vendor_id,))]
        return [row_dict(r) for r in self.db.all("SELECT * FROM assets ORDER BY name LIMIT 500")]

    # ------------------------------------------------------------------ assessments / findings / evidence
    def create_assessment(self, vendor_id: str, title: str, actor: str) -> dict:
        self.get_vendor(vendor_id)
        aid, now = new_id("asm"), utcnow_iso()
        with self.db.tx():
            self.db.execute("INSERT INTO assessments(id,vendor_id,title,status,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                            (aid, vendor_id, title, "draft", actor, now, now))
            self.ledger.append(actor, "assessment.create", aid, detail={"vendor": vendor_id})
        return self.get_assessment(aid)

    def _assessment_row(self, aid: str) -> dict:
        row = self.db.one("SELECT * FROM assessments WHERE id=?", (aid,))
        if not row:
            raise NotFound("assessment not found")
        return row_dict(row)

    def list_assessments(self, vendor_id: str | None = None, status: str | None = None, limit: int = 100) -> list:
        sql, args = "SELECT a.*, v.name vendor_name FROM assessments a JOIN vendors v ON v.id=a.vendor_id WHERE 1=1", []
        if vendor_id:
            sql += " AND a.vendor_id=?"; args.append(vendor_id)
        if status:
            sql += " AND a.status=?"; args.append(status)
        return [row_dict(r) for r in self.db.all(sql + " ORDER BY a.updated_at DESC LIMIT ?", args + [max(1, min(limit, 200))])]

    def get_assessment(self, aid: str) -> dict:
        a = self._assessment_row(aid)
        a["vendor_name"] = self.db.one("SELECT name FROM vendors WHERE id=?", (a["vendor_id"],))["name"]
        a["findings"] = self.list_findings(aid)
        runs = self.db.all("SELECT id,ran_at,as_of,policy_version,score,level,result_hash,ledger_seq FROM assessment_runs WHERE assessment_id=? ORDER BY ran_at DESC, rowid DESC", (aid,))
        a["runs"] = [row_dict(r) for r in runs]
        latest = None
        if a["latest_run_id"]:
            r = self.db.one("SELECT result_json, snapshot_json, result_hash FROM assessment_runs WHERE id=?", (a["latest_run_id"],))
            latest = {"result": json.loads(r["result_json"]), "snapshot": json.loads(r["snapshot_json"]), "result_hash": r["result_hash"]}
        a["latest"] = latest
        return a

    def list_findings(self, aid: str) -> list:
        rows = self.db.all("SELECT f.*, (SELECT COUNT(*) FROM evidence e WHERE e.finding_id=f.id) evidence_count FROM findings f "
                           "WHERE assessment_id=? ORDER BY created_at, id", (aid,))
        return [row_dict(r) for r in rows]

    def add_finding(self, aid: str, d: dict, actor: str) -> dict:
        a = self._assessment_row(aid)
        if a["status"] == "archived":
            raise Conflict("assessment is archived")
        cve = None
        if d.get("cve_id"):
            try:
                n = normalize(d["cve_id"])
            except ValueError as exc:
                raise Invalid("invalid CVE identifier") from exc
            if n.type != "cve":
                raise Invalid("cve_id must be a CVE identifier")
            cve = n.value
        if d.get("asset_id"):
            asset = self.db.one("SELECT vendor_id FROM assets WHERE id=?", (d["asset_id"],))
            if not asset or asset["vendor_id"] != a["vendor_id"]:
                raise Invalid("asset does not belong to this assessment's vendor")
        fid, now = new_id("fnd"), utcnow_iso()
        with self.db.tx():
            self.db.execute("INSERT INTO findings VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            (fid, aid, d.get("asset_id"), d["title"], d.get("description", ""), d["factor"], d["severity"], d["source"],
                             cve, d["confidence"], iso(d["observed_at"]), "open", actor, now, now))
            if a["status"] == "draft":
                self.db.execute("UPDATE assessments SET status='in_progress', updated_at=? WHERE id=?", (now, aid))
            self.ledger.append(actor, "finding.create", fid, detail={"assessment": aid, "severity": d["severity"], "factor": d["factor"]})
        return row_dict(self.db.one("SELECT * FROM findings WHERE id=?", (fid,)))

    def update_finding(self, fid: str, patch: dict, actor: str) -> dict:
        row = self.db.one("SELECT * FROM findings WHERE id=?", (fid,))
        if not row:
            raise NotFound("finding not found")
        if "status" in patch:
            try:
                lifecycle.check_transition("finding", row["status"], patch["status"])
            except lifecycle.TransitionError as exc:
                raise Conflict(str(exc)) from exc
        cols = [k for k in ("title", "description", "severity", "confidence", "status") if k in patch]
        if not cols:
            raise Invalid("no updatable fields supplied")
        with self.db.tx():
            self.db.execute(f"UPDATE findings SET {','.join(c + '=?' for c in cols)}, updated_at=? WHERE id=?",
                            [patch[c] for c in cols] + [utcnow_iso(), fid])
            self.ledger.append(actor, "finding.update", fid, detail={k: patch[k] for k in cols if k in ("status", "severity")})
        return row_dict(self.db.one("SELECT * FROM findings WHERE id=?", (fid,)))

    def add_evidence(self, d: dict, actor: str) -> dict:
        if not self.db.one("SELECT 1 FROM findings WHERE id=?", (d["finding_id"],)):
            raise NotFound("finding not found")
        if d.get("content") is not None:
            digest = hashlib.sha256(d["content"].encode()).hexdigest()
        elif d.get("content_hash"):
            digest = d["content_hash"].lower()
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise Invalid("content_hash must be a SHA-256 hex digest")
        else:
            raise Invalid("provide either content or content_hash so evidence is tamper-evident")
        eid = new_id("evd")
        with self.db.tx():
            self.db.execute("INSERT INTO evidence VALUES(?,?,?,?,?,?,?,?,?,?)",
                            (eid, d["finding_id"], d["source"], d.get("uri"), digest, d.get("note", ""), d["confidence"],
                             iso(d["observed_at"]), actor, utcnow_iso()))
            self.ledger.append(actor, "evidence.create", eid, detail={"finding": d["finding_id"], "sha256": digest})
        return row_dict(self.db.one("SELECT * FROM evidence WHERE id=?", (eid,)))

    def list_evidence(self, finding_id: str) -> list:
        return [row_dict(r) for r in self.db.all("SELECT * FROM evidence WHERE finding_id=? ORDER BY observed_at", (finding_id,))]

    # ------------------------------------------------------------------ intelligence
    def collect_intelligence(self, source: str, records: list | None, actor: str) -> dict:
        src = LocalFileSource("intel_feed.json", "local-sample") if source == "sample" else InlineSource(records or [], "inline")
        parsed, errors = parse_records(src.fetch(), src.name)
        new = dup = 0
        now = utcnow_iso()
        with span("intel.collect"), self.db.tx():
            for s in parsed:
                ind = self.db.one("SELECT id FROM indicators WHERE type=? AND value_norm=?", (s.type, s.value))
                ind_id = ind["id"] if ind else new_id("ind")
                if not ind:
                    self.db.execute("INSERT INTO indicators VALUES(?,?,?,?)", (ind_id, s.type, s.value, now))
                cur = self.db.execute("INSERT OR IGNORE INTO signals VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                                      (new_id("sig"), ind_id, s.source, s.source_record_id, s.original, s.severity, s.confidence,
                                       s.first_seen, s.last_seen, json.dumps(s.tags), s.description, int(s.synthetic), now))
                new, dup = (new + 1, dup) if cur.rowcount else (new, dup + 1)
            self.ledger.append(actor, "intelligence.collect", source, detail={"new": new, "duplicates": dup, "errors": len(errors)})
            if source == "sample":
                self.load_vuln_records(actor)  # enrichment data for CVE findings ships with the sample set
        METRICS.inc("intel_signals_ingested_total")
        return {"received": len(parsed) + len(errors), "new_signals": new, "duplicates_ignored": dup, "errors": errors}

    def load_vuln_records(self, actor: str) -> int:
        recs = LocalFileSource("vuln_records.json", "local-vuln").fetch()
        with self.db.tx():
            for r in recs:
                n = normalize(r["cve_id"])
                self.db.execute("INSERT OR REPLACE INTO vuln_records VALUES(?,?,?,?,?,?)",
                                (n.value, float(r["cvss"]), int(r["known_exploited"]), r["summary"], r["source"], int(r.get("synthetic", False))))
            self.ledger.append(actor, "vuln_records.load", "local-vuln", detail={"count": len(recs)})
        return len(recs)

    def list_indicators(self, q: str | None = None, type_: str | None = None, limit: int = 100) -> list:
        sql, args = "SELECT * FROM indicators WHERE 1=1", []
        if q:
            sql += " AND value_norm LIKE ?"; args.append(f"%{q.lower()}%")
        if type_:
            sql += " AND type=?"; args.append(type_)
        out = []
        for ind in self.db.all(sql + " ORDER BY value_norm LIMIT ?", args + [max(1, min(limit, 500))]):
            sigs = self.db.all("SELECT * FROM signals WHERE indicator_id=? ORDER BY last_seen DESC", (ind["id"],))
            out.append(self._indicator_view(ind, sigs))
        return out

    @staticmethod
    def _indicator_view(ind, sigs) -> dict:
        sig_list = [{**row_dict(s), "tags": json.loads(s["tags"]), "synthetic": bool(s["synthetic"])} for s in sigs]
        return {"id": ind["id"], "type": ind["type"], "value": ind["value_norm"], "signals": sig_list,
                "source_count": len({s["source"] for s in sig_list}),
                "corroborated_confidence": correlate.corroborated_confidence(s["confidence"] for s in sig_list),
                "max_severity": max((s["severity"] for s in sig_list), key=lambda x: _SEV_RANK[x]) if sig_list else "none",
                "last_seen": max((s["last_seen"] for s in sig_list), default=None)}

    def vendor_intel(self, vendor_id: str) -> list:
        v = self.get_vendor(vendor_id)
        matched = []
        for ind in self.db.all("SELECT * FROM indicators ORDER BY value_norm"):
            from .intelligence.normalize import Normalized
            reason = correlate.match_target(Normalized(ind["type"], ind["value_norm"], ind["value_norm"]), v["domain"], v["assets"])
            if reason:
                view = self._indicator_view(ind, self.db.all("SELECT * FROM signals WHERE indicator_id=? ORDER BY last_seen DESC", (ind["id"],)))
                view["match_reason"] = reason
                matched.append(view)
        return matched

    def ingest_document(self, title, content, source, media_type="text/markdown", synthetic=False) -> dict:
        try:
            return self.rag.ingest(title, content, source, media_type, synthetic)
        except (RagError, ValueError) as exc:
            raise Invalid(str(exc)) from exc

    # ------------------------------------------------------------------ risk orchestration
    def build_evidence(self, aid: str, as_of: str) -> list:
        """Gather every input the domain engine will score. Intelligence/RAG supply evidence; they never score."""
        a = self._assessment_row(aid)
        v = self.get_vendor(a["vendor_id"])
        items: list[EvidenceItem] = []
        for f in self.db.all("SELECT * FROM findings WHERE assessment_id=?", (aid,)):
            confs = [f["confidence"]] + [e["confidence"] for e in self.db.all("SELECT confidence FROM evidence WHERE finding_id=?", (f["id"],))]
            conf = correlate.corroborated_confidence(confs)
            sev, resolved = f["severity"], f["status"] == "resolved"
            title = f["title"]
            if f["cve_id"]:
                vr = self.db.one("SELECT * FROM vuln_records WHERE cve_id=?", (f["cve_id"],))
                if vr:
                    sev = _max_sev(sev, cvss_severity(vr["cvss"]))
                    title = f"{title} ({f['cve_id']}, CVSS {vr['cvss']})"
                    if vr["known_exploited"]:
                        items.append(EvidenceItem(f"kev:{f['id']}", "threat", "high", 0.9, f["observed_at"], f"vuln_db:{vr['source']}",
                                                  f"Known exploitation of {f['cve_id']}", resolved))
            items.append(EvidenceItem(f"fnd:{f['id']}", f["factor"], sev, conf, f["observed_at"], f"finding:{f['source']}", title, resolved))
        for ind in self.vendor_intel(v["id"]):
            sigs = ind["signals"]
            items.append(EvidenceItem(f"sig:{ind['id']}", "threat", ind["max_severity"], ind["corroborated_confidence"], ind["last_seen"],
                                      "intel:" + ",".join(sorted({s["source"] for s in sigs})),
                                      f"{ind['type']} {ind['value']} [{', '.join(sorted({t for s in sigs for t in s['tags']}))}]"))
        for asset in v["assets"]:
            sev = _EXPOSURE_SEV[asset["exposure"]]
            if asset["environment"] != "production":
                sev = _DOWNGRADE[sev]
            items.append(EvidenceItem(f"ast:{asset['id']}", "exposure", sev, 0.9, asset["created_at"], "asset_inventory",
                                      f"{asset['exposure']}-facing {asset['environment']} {asset['type']} '{asset['name']}'"))
        return items

    def run_assessment(self, aid: str, actor: str, as_of: str | None = None) -> dict:
        a = self._assessment_row(aid)
        if a["status"] == "archived":
            raise Conflict("assessment is archived")
        as_of = iso(as_of or self.clock())
        with span("assessment.run"):
            items = self.build_evidence(aid, as_of)
            result = assess(items, as_of, self.policy)
            rhash = result_hash(items, result)
        run_id = new_id("run")
        with self.db.tx():
            ev = self.ledger.append(actor, "assessment.run", aid, detail={
                "run_id": run_id, "score": result["score"], "level": result["level"], "result_hash": rhash,
                "policy_version": self.policy.version, "policy_hash": result["policy_hash"]})
            self.db.execute("INSERT INTO assessment_runs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            (run_id, aid, utcnow_iso(), as_of, self.policy.version, result["policy_hash"],
                             json.dumps([i.to_dict() for i in items], sort_keys=True), json.dumps(result, sort_keys=True), rhash,
                             result["score"], result["level"], ev["seq"], actor))
            status = "completed" if result["score"] is not None else ("in_progress" if a["status"] == "draft" else a["status"])
            if a["status"] == "draft" and status == "completed":
                self.db.execute("UPDATE assessments SET status='in_progress' WHERE id=?", (aid,))
            self.db.execute("UPDATE assessments SET status=?, score=?, level=?, policy_version=?, latest_run_id=?, updated_at=? WHERE id=?",
                            (status, result["score"], result["level"], self.policy.version, run_id, utcnow_iso(), aid))
        METRICS.inc("assessments_run_total", level=str(result["level"]))
        event("assessment.run", assessment_id=aid, run_id=run_id, score=result["score"], level=result["level"])
        return {"run_id": run_id, "result": result, "result_hash": rhash, "ledger_seq": ev["seq"]}

    def verify_run(self, aid: str, run_id: str | None = None) -> dict:
        """Replay proof: recompute from the stored snapshot under the stored policy and compare hashes."""
        self._assessment_row(aid)
        row = (self.db.one("SELECT * FROM assessment_runs WHERE id=? AND assessment_id=?", (run_id, aid)) if run_id else
               self.db.one("SELECT * FROM assessment_runs WHERE assessment_id=? ORDER BY ran_at DESC, rowid DESC LIMIT 1", (aid,)))
        if not row:
            raise NotFound("no run to verify")
        policy = POLICIES.get(row["policy_version"])
        if policy is None:
            return {"ok": False, "run_id": row["id"], "reason": f"policy version {row['policy_version']} is not available for replay"}
        items = [EvidenceItem.from_dict(d) for d in json.loads(row["snapshot_json"])]
        recomputed = result_hash(items, assess(items, row["as_of"], policy))
        policy_ok = policy.content_hash() == row["policy_hash"]
        ledger_ok = False
        ev = self.db.one("SELECT detail, hash FROM audit_events WHERE seq=?", (row["ledger_seq"],))
        if ev:
            ledger_ok = json.loads(ev["detail"]).get("result_hash") == row["result_hash"]
        chain = self.ledger.verify()
        return {"ok": recomputed == row["result_hash"] and policy_ok and ledger_ok and chain["ok"], "run_id": row["id"],
                "stored_hash": row["result_hash"], "recomputed_hash": recomputed, "hash_match": recomputed == row["result_hash"],
                "policy_hash_match": policy_ok, "ledger_entry_match": ledger_ok, "ledger_chain_ok": chain["ok"],
                "ledger_seq": row["ledger_seq"], "ledger_head": chain["head"]}

    # ------------------------------------------------------------------ workflows
    def create_workflow(self, d: dict, actor: str) -> dict:
        self._assessment_row(d["assessment_id"])
        if d.get("finding_id") and not self.db.one("SELECT 1 FROM findings WHERE id=? AND assessment_id=?", (d["finding_id"], d["assessment_id"])):
            raise Invalid("finding does not belong to this assessment")
        wid, now = new_id("wfl"), utcnow_iso()
        with self.db.tx():
            self.db.execute("INSERT INTO workflows VALUES(?,?,?,?,?,?,?,?,?,?)",
                            (wid, d["assessment_id"], d.get("finding_id"), d["title"], "todo", d.get("owner"), d.get("due_date"), actor, now, now))
            self.db.execute("INSERT INTO workflow_actions VALUES(?,?,?,?,?,?)", (new_id("act"), wid, actor, "created", "", now))
            self.ledger.append(actor, "workflow.create", wid, detail={"assessment": d["assessment_id"]})
        return self.get_workflow(wid)

    def get_workflow(self, wid: str) -> dict:
        row = self.db.one("SELECT * FROM workflows WHERE id=?", (wid,))
        if not row:
            raise NotFound("workflow not found")
        w = row_dict(row)
        w["history"] = [row_dict(r) for r in self.db.all("SELECT * FROM workflow_actions WHERE workflow_id=? ORDER BY at, rowid", (wid,))]
        return w

    def list_workflows(self, assessment_id: str | None = None) -> list:
        sql, args = "SELECT * FROM workflows", []
        if assessment_id:
            sql += " WHERE assessment_id=?"; args.append(assessment_id)
        return [row_dict(r) for r in self.db.all(sql + " ORDER BY updated_at DESC LIMIT 300", args)]

    def update_workflow(self, wid: str, patch: dict, actor: str) -> dict:
        w = self.get_workflow(wid)
        if "status" in patch:
            try:
                lifecycle.check_transition("workflow", w["status"], patch["status"])
            except lifecycle.TransitionError as exc:
                raise Conflict(str(exc)) from exc
        cols = [k for k in ("title", "status", "owner", "due_date") if k in patch]
        if not cols:
            raise Invalid("no updatable fields supplied")
        now = utcnow_iso()
        with self.db.tx():
            self.db.execute(f"UPDATE workflows SET {','.join(c + '=?' for c in cols)}, updated_at=? WHERE id=?", [patch[c] for c in cols] + [now, wid])
            for c in cols:
                self.db.execute("INSERT INTO workflow_actions VALUES(?,?,?,?,?,?)",
                                (new_id("act"), wid, actor, f"{c}_changed", f"{w[c]} -> {patch[c]}", now))
            self.ledger.append(actor, "workflow.update", wid, detail={c: patch[c] for c in cols if c in ("status", "owner")})
        return self.get_workflow(wid)

    # ------------------------------------------------------------------ reports
    def generate_report(self, aid: str, fmt: str, actor: str, run_id: str | None = None) -> dict:
        a = self.get_assessment(aid)
        run = (self.db.one("SELECT * FROM assessment_runs WHERE id=? AND assessment_id=?", (run_id, aid)) if run_id else
               (self.db.one("SELECT * FROM assessment_runs WHERE id=?", (a["latest_run_id"],)) if a["latest_run_id"] else None))
        if not run:
            raise Conflict("run the assessment before generating a report")
        result, snapshot = json.loads(run["result_json"]), json.loads(run["snapshot_json"])
        vendor = self.get_vendor(a["vendor_id"])
        blocks = self._report_blocks(a, vendor, run, result, snapshot)
        content = rpt.to_markdown(blocks) if fmt == "markdown" else rpt.to_html(blocks, f"Risk report - {a['title']}")
        rid = new_id("rpt")
        with self.db.tx():
            self.db.execute("INSERT INTO reports VALUES(?,?,?,?,?,?,?,?,?)",
                            (rid, aid, run["id"], fmt, "ready", content, hashlib.sha256(content.encode()).hexdigest(), utcnow_iso(), actor))
            self.ledger.append(actor, "report.generate", rid, detail={"assessment": aid, "run": run["id"], "format": fmt})
        return self.get_report(rid, with_content=False)

    def get_report(self, rid: str, with_content: bool = True) -> dict:
        row = self.db.one("SELECT * FROM reports WHERE id=?", (rid,))
        if not row:
            raise NotFound("report not found")
        d = row_dict(row)
        if not with_content:
            d.pop("content", None)
        return d

    def list_reports(self, assessment_id: str | None = None) -> list:
        sql, args = "SELECT id,assessment_id,run_id,format,status,content_hash,generated_at,created_by FROM reports", []
        if assessment_id:
            sql += " WHERE assessment_id=?"; args.append(assessment_id)
        return [row_dict(r) for r in self.db.all(sql + " ORDER BY generated_at DESC LIMIT 200", args)]

    def _report_blocks(self, a, vendor, run, result, snapshot) -> list:
        f = lambda x: "n/a" if x is None else f"{x:.2f}"
        b = [("h1", f"Cyber risk report: {vendor['name']}")]
        if vendor["synthetic"]:
            b.append(("note", "SYNTHETIC DATA: every vendor, indicator and document in this report was generated for demonstration. Nothing here is live threat intelligence."))
        b += [("table", ["Field", "Value"], [["Assessment", f"{a['title']} ({a['id']})"], ["Vendor domain", vendor["domain"]],
              ["Overall score", f"{f(result['score'])} / 100"], ["Risk level", result["level"] or "n/a"], ["Status", result["status"]],
              ["Evidence coverage", f"{result['coverage']:.0%}"], ["Evidence trust", f"{result['trust']:.2f}"],
              ["Policy version", result["policy_version"]], ["Evaluated as of", result["as_of"]]]),
              ("p", "The score is produced only by the deterministic domain policy. Intelligence and retrieved documents supply evidence; no model or LLM assigns or alters the score.")]
        b.append(("h2", "How the score was produced"))
        b.append(("table", ["Factor", "Score", "Weight", "Effective weight", "Contribution", "Rationale"],
                  [[x["factor"], f(x["score"]), x["weight"], x["effective_weight"], f(x["contribution"]), x["rationale"]] for x in result["factors"]]))
        if result["warnings"]:
            b += [("h2", "Warnings"), ("ul", [w["message"] for w in result["warnings"]])]
        b.append(("h2", "Evidence considered"))
        b.append(("table", ["Evidence ID", "Factor", "Severity", "Confidence", "Observed", "Source", "Title", "Resolved"],
                  [[s["id"], s["factor"], s["severity"], s["confidence"], s["observed_at"], s["source"], s["title"], "yes" if s["resolved"] else "no"] for s in snapshot]))
        cf = result["counterfactuals"]
        b.append(("h2", "What would change the risk level"))
        if cf["level_drop"]:
            b.append(("table", ["Factor", "Current", "Needed to reach lower level", "Reduction", "Feasible alone"],
                      [[r["factor"], r["current"], f(r["required_score"]), f(r["reduction"]), "yes" if r["feasible"] else "no"] for r in cf["level_drop"]]))
        if cf["remediation"]:
            b += [("h3", "Highest-impact remediations (simulated by resolving each item)"),
                  ("table", ["Evidence", "Severity", "Score if resolved", "Score change", "Level if resolved"],
                   [[r["title"], r["severity"], f(r["score_if_resolved"]), f"-{r['delta']:.2f}", r["level_if_resolved"]] for r in cf["remediation"]])]
            seen, cites = set(), []
            for r in cf["remediation"][:3]:
                res = self.rag.query(f"{r['title']} {r['factor']} remediation")
                for p in res["passages"][:1]:
                    c = p["citation"]
                    if c["chunk_id"] not in seen:
                        seen.add(c["chunk_id"]); cites.append(f"{c['title']} [{c['chunk_id']}]" + (" (synthetic)" if c["synthetic"] else ""))
            b += [("h3", "Supporting guidance (advisory; does not affect the score)"),
                  ("ul", cites or ["No evidence found in the document corpus for these remediation topics."])]
        ev = self.db.one("SELECT seq, hash, correlation_id, ts FROM audit_events WHERE seq=?", (run["ledger_seq"],))
        b += [("h2", "Integrity proof"),
              ("table", ["Item", "Value"], [["Run ID", run["id"]], ["Policy hash (SHA-256)", run["policy_hash"]], ["Result hash (SHA-256)", run["result_hash"]],
                                              ["Audit ledger entry", f"#{ev['seq']} at {ev['ts']}"], ["Audit entry hash", ev["hash"]],
                                              ["Audit correlation ID", ev["correlation_id"]], ["Ledger head at report time", self.ledger.head()["hash"]]]),
              ("p", "Anyone with the database can re-run verification (GET /api/v1/assessments/{id}/verify): the stored evidence snapshot is re-scored under the stored policy and compared to the hashes above.")]
        return b

    # ------------------------------------------------------------------ dashboard / jobs / handlers
    def dashboard(self) -> dict:
        levels = {r["level"] or "Unscored": r["c"] for r in self.db.all("SELECT level, COUNT(*) c FROM assessments GROUP BY level")}
        open_f = {r["severity"]: r["c"] for r in self.db.all("SELECT severity, COUNT(*) c FROM findings WHERE status IN ('open','in_progress') GROUP BY severity")}
        return {"vendors": self.db.one("SELECT COUNT(*) c FROM vendors")["c"], "assessments": self.db.one("SELECT COUNT(*) c FROM assessments")["c"],
                "by_level": levels, "open_findings": open_f, "jobs": self.jobs.stats(),
                "open_workflows": self.db.one("SELECT COUNT(*) c FROM workflows WHERE status!='done'")["c"],
                "recent_activity": [{"ts": e["ts"], "action": e["action"], "outcome": e["outcome"]} for e in self.ledger.list(8)]}

    def enqueue(self, type_: str, payload: dict, idempotency_key: str | None = None) -> dict:
        if type_ not in self.handlers():
            raise Invalid(f"unknown job type '{type_}'")
        return self.jobs.enqueue(type_, payload, idempotency_key)

    def handlers(self) -> dict:
        def risk(p):
            r = self.run_assessment(p["assessment_id"], p["actor"])
            return {"run_id": r["run_id"], "score": r["result"]["score"], "level": r["result"]["level"]}

        def intel(p):
            r = self.collect_intelligence(p["source"], p.get("records"), p["actor"])
            return {k: r[k] for k in ("new_signals", "duplicates_ignored")} | {"errors": len(r["errors"])}

        def rag(p):
            return self.ingest_document(p["title"], p["content"], p.get("source", "upload"), p.get("media_type", "text/markdown"))

        def report(p):
            return {"report_id": self.generate_report(p["assessment_id"], p.get("format", "markdown"), p["actor"])["id"]}

        return {"risk_assessment": risk, "intelligence_collect": intel, "rag_ingest": rag, "report_generate": report}
