"""Tamper-evident audit ledger: hash-chained, append-only (enforced by SQLite triggers).

Each event's hash covers its content AND the previous event's hash. Editing or
deleting any past row breaks every later hash, which verify() pinpoints. The head
hash can be anchored outside the database (e.g. printed in a report) so even a full
chain rewrite by someone with file access becomes detectable.
"""
from __future__ import annotations

import hashlib
import json

from .db import Database, utcnow_iso
from .observability import correlation_id

GENESIS = "0" * 64


def _digest(prev: str, ts: str, actor: str, action: str, target: str, outcome: str, cid: str, detail: str) -> str:
    blob = json.dumps([prev, ts, actor, action, target, outcome, cid, detail], separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(blob.encode()).hexdigest()


class Ledger:
    def __init__(self, db: Database):
        self.db = db

    def append(self, actor: str, action: str, target: str = "-", outcome: str = "success", detail: dict | None = None) -> dict:
        detail_s = json.dumps(detail or {}, sort_keys=True, separators=(",", ":"), default=str)
        with self.db.tx():
            last = self.db.one("SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1")
            prev = last["hash"] if last else GENESIS
            ts, cid = utcnow_iso(), correlation_id.get()
            h = _digest(prev, ts, actor, action, target, outcome, cid, detail_s)
            cur = self.db.execute(
                "INSERT INTO audit_events(ts,actor,action,target,outcome,correlation_id,detail,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?,?)",
                (ts, actor, action, target, outcome, cid, detail_s, prev, h))
            return {"seq": cur.lastrowid, "hash": h}

    def head(self) -> dict:
        row = self.db.one("SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1")
        return {"seq": row["seq"], "hash": row["hash"]} if row else {"seq": 0, "hash": GENESIS}

    def verify(self) -> dict:
        prev, count = GENESIS, 0
        for r in self.db.all("SELECT * FROM audit_events ORDER BY seq"):
            expected = _digest(prev, r["ts"], r["actor"], r["action"], r["target"], r["outcome"], r["correlation_id"], r["detail"])
            if r["prev_hash"] != prev or r["hash"] != expected:
                return {"ok": False, "checked": count, "first_bad_seq": r["seq"], "head": self.head()}
            prev, count = r["hash"], count + 1
        return {"ok": True, "checked": count, "first_bad_seq": None, "head": self.head()}

    def list(self, limit: int = 100, correlation: str | None = None) -> list:
        limit = max(1, min(limit, 500))
        if correlation:
            rows = self.db.all("SELECT * FROM audit_events WHERE correlation_id=? ORDER BY seq DESC LIMIT ?", (correlation, limit))
        else:
            rows = self.db.all("SELECT * FROM audit_events ORDER BY seq DESC LIMIT ?", (limit,))
        return [{k: r[k] for k in r.keys()} for r in rows]
