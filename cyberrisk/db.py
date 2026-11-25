"""SQLite persistence with numbered migrations and explicit transactions.

One connection guarded by an RLock keeps the prototype simple and correct under
a threaded server. PostgreSQL notes are in docs/ARCHITECTURE.md.
"""
from __future__ import annotations

import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


MIGRATIONS = [
    (1, "core schema", """
CREATE TABLE users(id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('analyst','assessor','admin')), status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled')),
  created_at TEXT NOT NULL);
CREATE TABLE api_keys(id TEXT PRIMARY KEY, name TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE, scopes TEXT NOT NULL,
  created_by TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL, revoked_at TEXT);
CREATE TABLE vendors(id TEXT PRIMARY KEY, name TEXT NOT NULL, category TEXT NOT NULL, domain TEXT NOT NULL,
  criticality TEXT NOT NULL CHECK(criticality IN ('low','medium','high','critical')),
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','inactive')), synthetic INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE assets(id TEXT PRIMARY KEY, vendor_id TEXT NOT NULL REFERENCES vendors(id), name TEXT NOT NULL,
  type TEXT NOT NULL CHECK(type IN ('host','service','application','database','other')), identifier TEXT NOT NULL,
  environment TEXT NOT NULL CHECK(environment IN ('production','staging','development')),
  exposure TEXT NOT NULL CHECK(exposure IN ('internal','partner','internet')), created_at TEXT NOT NULL);
CREATE TABLE assessments(id TEXT PRIMARY KEY, vendor_id TEXT NOT NULL REFERENCES vendors(id), title TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','in_progress','completed','archived')),
  score REAL, level TEXT, policy_version TEXT, latest_run_id TEXT, created_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE assessment_runs(id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL REFERENCES assessments(id),
  ran_at TEXT NOT NULL, as_of TEXT NOT NULL, policy_version TEXT NOT NULL, policy_hash TEXT NOT NULL,
  snapshot_json TEXT NOT NULL, result_json TEXT NOT NULL, result_hash TEXT NOT NULL, score REAL, level TEXT,
  ledger_seq INTEGER, run_by TEXT NOT NULL);
CREATE TABLE findings(id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL REFERENCES assessments(id), asset_id TEXT REFERENCES assets(id),
  title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
  factor TEXT NOT NULL CHECK(factor IN ('vulnerability','threat','exposure','compliance','investigation')),
  severity TEXT NOT NULL CHECK(severity IN ('none','info','low','medium','high','critical')),
  source TEXT NOT NULL, cve_id TEXT, confidence REAL NOT NULL CHECK(confidence>=0 AND confidence<=1),
  observed_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','in_progress','accepted','resolved')),
  created_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE evidence(id TEXT PRIMARY KEY, finding_id TEXT NOT NULL REFERENCES findings(id), source TEXT NOT NULL, uri TEXT,
  content_hash TEXT NOT NULL, note TEXT NOT NULL DEFAULT '', confidence REAL NOT NULL CHECK(confidence>=0 AND confidence<=1),
  observed_at TEXT NOT NULL, created_by TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE indicators(id TEXT PRIMARY KEY, type TEXT NOT NULL, value_norm TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE(type,value_norm));
CREATE TABLE signals(id TEXT PRIMARY KEY, indicator_id TEXT NOT NULL REFERENCES indicators(id), source TEXT NOT NULL,
  source_record_id TEXT NOT NULL, original_value TEXT NOT NULL, severity TEXT NOT NULL, confidence REAL NOT NULL,
  first_seen TEXT, last_seen TEXT NOT NULL, tags TEXT NOT NULL DEFAULT '[]', description TEXT NOT NULL DEFAULT '',
  synthetic INTEGER NOT NULL DEFAULT 0, collected_at TEXT NOT NULL, UNIQUE(indicator_id, source, source_record_id));
CREATE TABLE vuln_records(cve_id TEXT PRIMARY KEY, cvss REAL NOT NULL, known_exploited INTEGER NOT NULL DEFAULT 0,
  summary TEXT NOT NULL, source TEXT NOT NULL, synthetic INTEGER NOT NULL DEFAULT 0);
CREATE TABLE documents(id TEXT PRIMARY KEY, title TEXT NOT NULL, source TEXT NOT NULL, content_hash TEXT NOT NULL UNIQUE,
  media_type TEXT NOT NULL, size_bytes INTEGER NOT NULL, synthetic INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL);
CREATE TABLE chunks(id TEXT PRIMARY KEY, document_id TEXT NOT NULL REFERENCES documents(id), ordinal INTEGER NOT NULL,
  text TEXT NOT NULL, char_start INTEGER NOT NULL, embedding TEXT NOT NULL, UNIQUE(document_id, ordinal));
CREATE TABLE workflows(id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL REFERENCES assessments(id), finding_id TEXT REFERENCES findings(id),
  title TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'todo' CHECK(status IN ('todo','doing','blocked','done')),
  owner TEXT, due_date TEXT, created_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE workflow_actions(id TEXT PRIMARY KEY, workflow_id TEXT NOT NULL REFERENCES workflows(id), actor TEXT NOT NULL,
  action TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '', at TEXT NOT NULL);
CREATE TABLE reports(id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL REFERENCES assessments(id), run_id TEXT NOT NULL,
  format TEXT NOT NULL CHECK(format IN ('markdown','html')), status TEXT NOT NULL, content TEXT, content_hash TEXT,
  generated_at TEXT NOT NULL, created_by TEXT NOT NULL);
CREATE TABLE jobs(id TEXT PRIMARY KEY, type TEXT NOT NULL, payload TEXT NOT NULL, idempotency_key TEXT UNIQUE,
  status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','succeeded','failed')),
  attempts INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL, run_after TEXT NOT NULL, last_error TEXT,
  result TEXT, correlation_id TEXT, created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT);
CREATE TABLE audit_events(seq INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
  target TEXT NOT NULL, outcome TEXT NOT NULL, correlation_id TEXT NOT NULL, detail TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT,'audit_events is append-only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_events BEGIN SELECT RAISE(ABORT,'audit_events is append-only'); END;
"""),
    (2, "indexes", """
CREATE INDEX ix_assets_vendor ON assets(vendor_id);
CREATE INDEX ix_assess_vendor ON assessments(vendor_id);
CREATE INDEX ix_assess_status ON assessments(status);
CREATE INDEX ix_runs_assess ON assessment_runs(assessment_id, ran_at);
CREATE INDEX ix_findings_assess ON findings(assessment_id);
CREATE INDEX ix_findings_status ON findings(status);
CREATE INDEX ix_evidence_finding ON evidence(finding_id);
CREATE INDEX ix_signals_ind ON signals(indicator_id);
CREATE INDEX ix_chunks_doc ON chunks(document_id);
CREATE INDEX ix_workflows_assess ON workflows(assessment_id);
CREATE INDEX ix_jobs_status ON jobs(status, run_after);
CREATE INDEX ix_audit_ts ON audit_events(ts);
"""),
]


class Database:
    def __init__(self, path: str):
        self.path = path
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys=ON")
        if path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._lock = threading.RLock()
        self._depth = 0

    def migrate(self) -> list:
        applied = []
        with self._lock:
            self._conn.execute("CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)")
            done = {r["version"] for r in self._conn.execute("SELECT version FROM schema_migrations")}
            for version, name, sql in MIGRATIONS:
                if version in done:
                    continue
                with self.tx():
                    for stmt in _split_sql(sql):
                        self._conn.execute(stmt)
                    self._conn.execute("INSERT INTO schema_migrations VALUES(?,?,?)", (version, name, utcnow_iso()))
                applied.append(version)
        return applied

    @contextmanager
    def tx(self):
        """Re-entrant transaction: the outermost block commits or rolls back everything."""
        with self._lock:
            outer = self._depth == 0
            if outer:
                self._conn.execute("BEGIN IMMEDIATE")
            self._depth += 1
            try:
                yield self
            except BaseException:
                self._depth -= 1
                if outer:
                    self._conn.execute("ROLLBACK")
                raise
            else:
                self._depth -= 1
                if outer:
                    self._conn.execute("COMMIT")

    def execute(self, sql, params=()):
        with self._lock:
            return self._conn.execute(sql, params)

    def one(self, sql, params=()):
        with self._lock:
            return self._conn.execute(sql, params).fetchone()

    def all(self, sql, params=()):
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def ping(self) -> bool:
        try:
            self.one("SELECT 1")
            return True
        except Exception:
            return False

    def schema_version(self) -> int:
        row = self.one("SELECT MAX(version) v FROM schema_migrations")
        return row["v"] or 0

    def close(self):
        with self._lock:
            self._conn.close()


def _split_sql(script: str):
    """Split on ';' but keep CREATE TRIGGER ... END; blocks intact."""
    stmts, buf = [], []
    for line in script.strip().splitlines():
        buf.append(line)
        joined = "\n".join(buf).strip()
        if joined.endswith(";"):
            if "CREATE TRIGGER" in joined.upper() and not joined.rstrip(";").rstrip().upper().endswith("END"):
                continue
            stmts.append(joined)
            buf = []
    if buf and "\n".join(buf).strip():
        stmts.append("\n".join(buf).strip())
    return stmts


def row_dict(row):
    return None if row is None else {k: row[k] for k in row.keys()}
