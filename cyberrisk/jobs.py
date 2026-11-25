"""Persistent job queue: states queued/running/succeeded/failed, bounded exponential backoff,
idempotency keys, stuck-job recovery and a graceful-shutdown worker thread."""
from __future__ import annotations

import json
import threading
from datetime import timedelta
from typing import Callable, Dict

from .db import Database, new_id, row_dict
from .domain.risk import iso
from .errors import AppError
from .observability import METRICS, correlation_id, event, new_correlation_id


class JobQueue:
    def __init__(self, db: Database, clock: Callable, max_attempts: int = 3, backoff_base: float = 2.0, backoff_cap: float = 60.0):
        self.db, self.clock = db, clock
        self.max_attempts, self.base, self.cap = max_attempts, backoff_base, backoff_cap

    def backoff(self, attempts: int) -> float:
        return min(self.cap, self.base * (2 ** max(0, attempts - 1)))

    def enqueue(self, type_: str, payload: dict, idempotency_key: str | None = None, max_attempts: int | None = None) -> dict:
        with self.db.tx():
            if idempotency_key:
                row = self.db.one("SELECT * FROM jobs WHERE idempotency_key=?", (idempotency_key,))
                if row:
                    return {**self._view(row), "created": False}
            jid, now = new_id("job"), iso(self.clock())
            self.db.execute("INSERT INTO jobs(id,type,payload,idempotency_key,status,attempts,max_attempts,run_after,correlation_id,created_at) "
                            "VALUES(?,?,?,?,?,?,?,?,?,?)",
                            (jid, type_, json.dumps(payload, sort_keys=True), idempotency_key, "queued", 0,
                             max_attempts or self.max_attempts, now, correlation_id.get(), now))
        METRICS.inc("jobs_enqueued_total", type=type_)
        return {**self._view(self.db.one("SELECT * FROM jobs WHERE id=?", (jid,))), "created": True}

    @staticmethod
    def _view(row) -> dict:
        d = row_dict(row)
        d["payload"] = json.loads(d["payload"])
        d["result"] = json.loads(d["result"]) if d["result"] else None
        return d

    def get(self, job_id: str):
        row = self.db.one("SELECT * FROM jobs WHERE id=?", (job_id,))
        return self._view(row) if row else None

    def list(self, limit: int = 50) -> list:
        return [self._view(r) for r in self.db.all("SELECT * FROM jobs ORDER BY created_at DESC, id DESC LIMIT ?", (max(1, min(limit, 200)),))]

    def stats(self) -> dict:
        out = {"queued": 0, "running": 0, "succeeded": 0, "failed": 0}
        for r in self.db.all("SELECT status, COUNT(*) c FROM jobs GROUP BY status"):
            out[r["status"]] = r["c"]
        return out

    def retry(self, job_id: str) -> dict:
        with self.db.tx():
            self.db.execute("UPDATE jobs SET status='queued', attempts=0, last_error=NULL, run_after=? WHERE id=? AND status='failed'",
                            (iso(self.clock()), job_id))
        return self.get(job_id)

    def recover_stuck(self, timeout_seconds: int = 300) -> int:
        cutoff = iso(self.clock() - timedelta(seconds=timeout_seconds))
        with self.db.tx():
            cur = self.db.execute("UPDATE jobs SET status='queued', last_error='recovered from stuck running state' "
                                  "WHERE status='running' AND started_at < ?", (cutoff,))
        return cur.rowcount

    def run_pending(self, handlers: Dict[str, Callable], limit: int = 10) -> list:
        results = []
        for _ in range(limit):
            claimed = self._claim()
            if claimed is None:
                break
            results.append(self._execute(claimed, handlers))
        return results

    def _claim(self):
        now = iso(self.clock())
        with self.db.tx():
            row = self.db.one("SELECT * FROM jobs WHERE status='queued' AND run_after<=? ORDER BY run_after, created_at LIMIT 1", (now,))
            if not row:
                return None
            self.db.execute("UPDATE jobs SET status='running', attempts=attempts+1, started_at=? WHERE id=?", (now, row["id"]))
            return self._view(self.db.one("SELECT * FROM jobs WHERE id=?", (row["id"],)))

    def _execute(self, job: dict, handlers: Dict[str, Callable]) -> dict:
        token = correlation_id.set(job.get("correlation_id") or new_correlation_id())  # carry the originating request's ID
        try:
            handler = handlers.get(job["type"])
            if handler is None:
                raise AppError(f"no handler registered for '{job['type']}'")
            result = handler(job["payload"])
            with self.db.tx():
                self.db.execute("UPDATE jobs SET status='succeeded', result=?, finished_at=?, last_error=NULL WHERE id=?",
                                (json.dumps(result, default=str), iso(self.clock()), job["id"]))
            METRICS.inc("jobs_total", type=job["type"], outcome="succeeded")
            event("job.succeeded", job_id=job["id"], type=job["type"], attempts=job["attempts"])
            return {"id": job["id"], "status": "succeeded"}
        except Exception as exc:  # noqa: BLE001 - any handler failure must be recorded, not crash the worker
            permanent = isinstance(exc, AppError) and exc.status < 500
            final = permanent or job["attempts"] >= job["max_attempts"]
            err = f"{type(exc).__name__}: {exc}"[:500]
            with self.db.tx():
                if final:
                    self.db.execute("UPDATE jobs SET status='failed', last_error=?, finished_at=? WHERE id=?", (err, iso(self.clock()), job["id"]))
                else:
                    self.db.execute("UPDATE jobs SET status='queued', last_error=?, run_after=? WHERE id=?",
                                    (err, iso(self.clock() + timedelta(seconds=self.backoff(job["attempts"]))), job["id"]))
            METRICS.inc("jobs_total", type=job["type"], outcome="failed" if final else "retry")
            event("job.failed" if final else "job.retry", job_id=job["id"], type=job["type"], attempts=job["attempts"], error=err)
            return {"id": job["id"], "status": "failed" if final else "retry_scheduled"}
        finally:
            correlation_id.reset(token)


class Worker(threading.Thread):
    """Background poller. stop() lets the in-flight job finish, then exits (graceful shutdown)."""

    def __init__(self, queue: JobQueue, handlers: Dict[str, Callable], interval: float = 1.0):
        super().__init__(daemon=True, name="job-worker")
        self.queue, self.handlers, self.interval, self._stop_evt = queue, handlers, interval, threading.Event()

    def run(self):
        while not self._stop_evt.is_set():
            try:
                self.queue.recover_stuck()
                if not self.queue.run_pending(self.handlers, limit=5):
                    self._stop_evt.wait(self.interval)
            except Exception:  # noqa: BLE001
                self._stop_evt.wait(self.interval)

    def stop(self, timeout: float = 10.0):
        self._stop_evt.set()
        self.join(timeout)
