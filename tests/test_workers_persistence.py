import json
import os
import sqlite3
import tempfile
import time
import unittest

from tests.helpers import *  # noqa
from cyberrisk.db import Database
from cyberrisk.errors import Invalid
from cyberrisk.jobs import Worker


class JobTests(unittest.TestCase):
    def setUp(self):
        self.e = Env()
        self.q = self.e.p.jobs
        self.calls = []

    def test_success_lifecycle(self):
        j = self.q.enqueue("ok", {"n": 1})
        self.assertEqual((j["status"], j["attempts"]), ("queued", 0))
        res = self.q.run_pending({"ok": lambda p: {"echo": p["n"]}})
        self.assertEqual(res, [{"id": j["id"], "status": "succeeded"}])
        done = self.q.get(j["id"])
        self.assertEqual((done["status"], done["attempts"], done["result"]), ("succeeded", 1, {"echo": 1}))
        self.assertIsNotNone(done["started_at"] and done["finished_at"])

    def test_retry_with_exponential_backoff_then_success(self):
        def flaky(p):
            self.calls.append(1)
            if len(self.calls) < 3:
                raise RuntimeError("transient")
            return {"ok": True}
        j = self.q.enqueue("flaky", {})
        self.q.run_pending({"flaky": flaky})
        a = self.q.get(j["id"])
        self.assertEqual((a["status"], a["attempts"]), ("queued", 1))
        self.assertIn("transient", a["last_error"])
        self.assertEqual(self.q.run_pending({"flaky": flaky}), [])            # not due yet (backoff 2s)
        self.e.clock.advance(2)
        self.q.run_pending({"flaky": flaky})
        self.assertEqual(self.q.get(j["id"])["attempts"], 2)
        self.e.clock.advance(3)                                               # second backoff is 4s -> still not due
        self.assertEqual(self.q.run_pending({"flaky": flaky}), [])
        self.e.clock.advance(1)
        self.q.run_pending({"flaky": flaky})
        self.assertEqual((self.q.get(j["id"])["status"], len(self.calls)), ("succeeded", 3))

    def test_backoff_is_bounded(self):
        self.assertEqual([self.q.backoff(n) for n in (1, 2, 3, 4, 5, 9)], [2, 4, 8, 10, 10, 10])

    def test_max_attempts_then_failed(self):
        j = self.q.enqueue("bad", {}, max_attempts=2)
        for _ in range(4):
            self.q.run_pending({"bad": lambda p: 1 / 0})
            self.e.clock.advance(60)
        f = self.q.get(j["id"])
        self.assertEqual((f["status"], f["attempts"]), ("failed", 2))
        self.assertIn("ZeroDivisionError", f["last_error"])
        self.e.clock.advance(999)
        self.assertEqual(self.q.run_pending({"bad": lambda p: 1 / 0}), [])    # failed jobs are not retried automatically
        again = self.q.retry(j["id"])
        self.assertEqual((again["status"], again["attempts"]), ("queued", 0))  # explicit retry only

    def test_validation_errors_fail_permanently_without_retry(self):
        j = self.q.enqueue("inv", {})
        def bad(p): raise Invalid("bad input")
        self.q.run_pending({"inv": bad})
        self.assertEqual((self.q.get(j["id"])["status"], self.q.get(j["id"])["attempts"]), ("failed", 1))

    def test_unknown_handler_fails(self):
        j = self.q.enqueue("ghost", {}, max_attempts=1)
        self.q.run_pending({})
        self.assertEqual(self.q.get(j["id"])["status"], "failed")

    def test_idempotency_key_prevents_duplicates(self):
        a = self.q.enqueue("ok", {"x": 1}, idempotency_key="k1")
        b = self.q.enqueue("ok", {"x": 2}, idempotency_key="k1")
        self.assertEqual((a["created"], b["created"], a["id"] == b["id"]), (True, False, True))
        self.assertEqual(self.q.stats()["queued"], 1)

    def test_stuck_running_jobs_are_recovered(self):
        j = self.q.enqueue("ok", {})
        self.q._claim()
        self.assertEqual(self.q.get(j["id"])["status"], "running")
        self.assertEqual(self.q.recover_stuck(300), 0)
        self.e.clock.advance(301)
        self.assertEqual(self.q.recover_stuck(300), 1)
        self.assertEqual(self.q.get(j["id"])["status"], "queued")

    def test_job_inherits_originating_correlation_id(self):
        from cyberrisk.observability import correlation_id
        seen = []
        tok = correlation_id.set("origin-cid-0001")
        j = self.q.enqueue("ok", {})
        correlation_id.reset(tok)
        self.q.run_pending({"ok": lambda p: seen.append(correlation_id.get()) or {}})
        self.assertEqual(seen, ["origin-cid-0001"])

    def test_worker_thread_processes_and_stops_gracefully(self):
        j = self.q.enqueue("ok", {})
        w = Worker(self.q, {"ok": lambda p: {"done": 1}}, interval=0.05)
        w.start()
        deadline = time.time() + 3
        while time.time() < deadline and self.q.get(j["id"])["status"] != "succeeded":
            time.sleep(0.02)
        w.stop(2)
        self.assertEqual(self.q.get(j["id"])["status"], "succeeded")
        self.assertFalse(w.is_alive())

    def test_real_handlers_via_api_async_paths(self):
        v = self.e.vendor(); a = self.e.assessment(v["id"]); self.e.finding(a["id"])
        s, job = self.e.call("POST", f"/api/v1/assessments/{a['id']}/run?async=1", "assessor", headers={"Idempotency-Key": "run-1"})
        self.assertEqual(s, 202)
        s2, job2 = self.e.call("POST", f"/api/v1/assessments/{a['id']}/run?async=1", "assessor", headers={"Idempotency-Key": "run-1"})
        self.assertEqual(job2["id"], job["id"])
        self.assertEqual(self.e.call("POST", "/api/v1/jobs/run-pending", "admin")[1]["results"][0]["status"], "succeeded")
        s, j = self.e.call("GET", f"/api/v1/jobs/{job['id']}", "analyst")
        self.assertEqual((j["status"], j["result"]["level"]), ("succeeded", "High"))
        self.assertEqual(self.e.call("GET", f"/api/v1/assessments/{a['id']}", "analyst")[1]["level"], "High")
        s, doc = self.e.call("POST", "/api/v1/documents?async=1", "admin", {"title": "T", "content": "Alpha beta gamma policy text"})
        s, rep = self.e.call("POST", "/api/v1/reports?async=1", "assessor", {"assessment_id": a["id"]})
        self.e.call("POST", "/api/v1/jobs/run-pending", "admin")
        self.assertEqual(self.e.call("GET", f"/api/v1/jobs/{doc['id']}", "analyst")[1]["status"], "succeeded")
        self.assertEqual(self.e.call("GET", f"/api/v1/jobs/{rep['id']}", "analyst")[1]["status"], "succeeded")


class PersistenceTests(unittest.TestCase):
    def test_migrations_are_idempotent_and_versioned(self):
        db = Database(":memory:")
        self.assertEqual(db.migrate(), [1, 2])
        self.assertEqual(db.migrate(), [])
        self.assertEqual(db.schema_version(), 2)

    def test_constraints_reject_bad_rows(self):
        e = Env()
        v = e.vendor()
        bad = [("INSERT INTO vendors VALUES('x','n','c','d.example','extreme','active',0,'t','t')", ()),
               ("INSERT INTO assets VALUES('a','nope','n','host','1.1.1.1','production','internet','t')", ()),
               ("INSERT INTO findings VALUES('f','nope',NULL,'t','','vulnerability','high','s',NULL,0.5,'t','open','u','t','t')", ()),
               ("INSERT INTO findings VALUES('f','%s',NULL,'t','','vulnerability','high','s',NULL,1.5,'t','open','u','t','t')" % "x", ())]
        for sql, args in bad:
            with self.assertRaises(sqlite3.IntegrityError):
                e.db.execute(sql, args)

    def test_transaction_rolls_back_everything_on_failure(self):
        e = Env()
        v = e.vendor(); a = e.assessment(v["id"]); e.finding(a["id"])
        runs_before = e.db.one("SELECT COUNT(*) c FROM assessment_runs")["c"]
        audits_before = e.db.one("SELECT COUNT(*) c FROM audit_events")["c"]
        orig = e.p.db.execute
        def boom(sql, params=()):
            if sql.startswith("UPDATE assessments SET status=?, score"):
                raise sqlite3.OperationalError("disk full")
            return orig(sql, params)
        e.p.db.execute = boom
        with self.assertRaises(sqlite3.OperationalError):
            e.p.run_assessment(a["id"], "t")
        e.p.db.execute = orig
        self.assertEqual(e.db.one("SELECT COUNT(*) c FROM assessment_runs")["c"], runs_before)   # run row rolled back
        self.assertEqual(e.db.one("SELECT COUNT(*) c FROM audit_events")["c"], audits_before)     # ledger entry rolled back
        self.assertTrue(e.p.ledger.verify()["ok"])
        self.assertIsNone(e.p.get_assessment(a["id"])["score"])

    def test_data_survives_reopen_on_disk(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "t.db")
            db = Database(path); db.migrate()
            p = Platform(db, Env().settings); p.create_user("a@b.example", "long-password-1", "admin")
            v = p.create_vendor({"name": "Persist", "category": "c", "domain": "p.example", "criticality": "low"}, "t")
            db.close()
            db2 = Database(path); self.assertEqual(db2.migrate(), [])
            p2 = Platform(db2, Env().settings)
            self.assertEqual(p2.get_vendor(v["id"])["name"], "Persist")
            self.assertTrue(p2.ledger.verify()["ok"])
            db2.close()

    def test_assessment_history_is_preserved(self):
        e = Env()
        v = e.vendor(); a = e.assessment(v["id"]); f = e.finding(a["id"])
        r1 = e.call("POST", f"/api/v1/assessments/{a['id']}/run", "assessor")[1]
        e.clock.advance(60)
        e.call("PATCH", f"/api/v1/findings/{f['id']}", "analyst", {"status": "resolved"})
        r2 = e.call("POST", f"/api/v1/assessments/{a['id']}/run", "assessor")[1]
        asm = e.call("GET", f"/api/v1/assessments/{a['id']}", "analyst")[1]
        self.assertEqual(len(asm["runs"]), 2)
        self.assertGreater(r1["result"]["score"], r2["result"]["score"])
        self.assertTrue(e.call("GET", f"/api/v1/assessments/{a['id']}/verify?run_id={r1['run_id']}", "analyst")[1]["ok"])  # old run still verifiable


if __name__ == "__main__":
    unittest.main()
