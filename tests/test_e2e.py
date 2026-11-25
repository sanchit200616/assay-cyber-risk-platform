import json
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer

from tests.helpers import *  # noqa
from cyberrisk.server import make_handler


class EndToEnd(unittest.TestCase):
    """The brief's primary demo, driven through the public HTTP API."""

    def test_full_workflow_vendor_to_report(self):
        e = Env()
        # 1-2 vendor, asset, assessment
        v = e.vendor(name="Northwind Test", domain="northwind-payments.example", criticality="critical")
        s, asset = e.call("POST", "/api/v1/assets", "assessor", {"vendor_id": v["id"], "name": "Edge", "type": "host", "identifier": "203.0.113.10", "environment": "production", "exposure": "internet"})
        self.assertEqual(s, 201)
        a = e.assessment(v["id"])
        self.assertEqual(a["status"], "draft")
        # 3 findings + evidence (analyst role can do this)
        f1 = e.finding(a["id"], title="RCE", cve_id="cve-2099-10001", severity="high", asset_id=asset["id"])
        e.finding(a["id"], title="No MFA", factor="compliance", severity="medium", confidence=0.6)
        s, ev = e.call("POST", "/api/v1/evidence", "analyst", {"finding_id": f1["id"], "source": "scan", "content": "banner dump", "confidence": 0.7, "observed_at": "2026-11-10T00:00:00Z"})
        self.assertEqual(s, 201)
        self.assertEqual(len(ev["content_hash"]), 64)
        self.assertEqual(e.call("POST", "/api/v1/evidence", "analyst", {"finding_id": f1["id"], "source": "scan", "confidence": 0.7, "observed_at": "2026-11-10T00:00:00Z"})[0], 422)  # needs content or hash
        self.assertEqual(e.call("GET", f"/api/v1/assessments/{a['id']}", "analyst")[1]["status"], "in_progress")
        # 4 intelligence (sample feed also loads CVE enrichment data)
        s, c = e.call("POST", "/api/v1/intelligence/collect", "analyst", {"source": "sample"})
        self.assertGreater(c["new_signals"], 5)
        intel = e.call("GET", f"/api/v1/vendors/{v['id']}/intelligence", "analyst")[1]["items"]
        self.assertGreaterEqual(len(intel), 2)
        # 5 RAG with citations
        s, rag = e.call("POST", "/api/v1/documents", "admin", {"title": "Patch SLA", "content": "Critical vulnerabilities with known exploitation must be patched within seven days."})
        self.assertEqual(s, 201)
        s, q = e.call("POST", "/api/v1/rag/query", "analyst", {"question": "patch deadline for exploited critical vulnerabilities"})
        self.assertEqual(q["status"], "ok")
        self.assertTrue(e.p.rag.citation_valid(q["passages"][0]["citation"]))
        # 6 run + explain
        s, run = e.call("POST", f"/api/v1/assessments/{a['id']}/run", "assessor")
        self.assertEqual(s, 200)
        r = run["result"]
        self.assertEqual(r["status"], "complete" if all(f["present"] for f in r["factors"]) else "partial")
        ids = set(r["evidence_ids"])
        self.assertTrue(any(i.startswith("kev:") for i in ids), "known-exploited CVE enrichment should add threat evidence")
        self.assertTrue(any(i.startswith("sig:") for i in ids), "correlated intelligence should appear as evidence")
        self.assertTrue(any(i.startswith("ast:") for i in ids), "asset exposure should appear as evidence")
        self.assertAlmostEqual(sum(f["contribution"] for f in r["factors"]), r["score"], delta=0.03)
        cve_item = next(x for x in e.call("GET", f"/api/v1/assessments/{a['id']}", "analyst")[1]["latest"]["snapshot"] if x["id"] == f"fnd:{f1['id']}")
        self.assertEqual(cve_item["severity"], "critical")        # CVSS 9.8 escalated the declared 'high'
        # replay verification
        s, ver = e.call("GET", f"/api/v1/assessments/{a['id']}/verify", "analyst")
        self.assertTrue(ver["ok"], ver)
        # 7 workflow lifecycle
        s, w = e.call("POST", "/api/v1/workflows", "analyst", {"assessment_id": a["id"], "finding_id": f1["id"], "title": "Patch RCE", "owner": "ops"})
        self.assertEqual(s, 201)
        self.assertEqual(e.call("PATCH", f"/api/v1/workflows/{w['id']}", "analyst", {"status": "done"})[0], 409)   # todo -> done not allowed
        self.assertEqual(e.call("PATCH", f"/api/v1/workflows/{w['id']}", "analyst", {"status": "doing", "owner": "sam"})[0], 200)
        hist = e.call("GET", f"/api/v1/workflows/{w['id']}", "analyst")[1]["history"]
        self.assertGreaterEqual(len(hist), 3)
        # remediation lowers the score and keeps history
        self.assertEqual(e.call("PATCH", f"/api/v1/findings/{f1['id']}", "analyst", {"status": "resolved"})[0], 200)
        self.assertEqual(e.call("PATCH", f"/api/v1/findings/{f1['id']}", "analyst", {"status": "accepted"})[0], 409)  # resolved -> accepted invalid
        s, run2 = e.call("POST", f"/api/v1/assessments/{a['id']}/run", "assessor")
        self.assertLess(run2["result"]["score"], r["score"])
        # 8 report with integrity proof, download
        s, rep = e.call("POST", "/api/v1/reports", "assessor", {"assessment_id": a["id"], "format": "markdown"}, headers={"X-Request-ID": "demo-trace-0001"})
        self.assertEqual(s, 201)
        s, h, body = e.call("GET", f"/api/v1/reports/{rep['id']}/download", "analyst", raw=True)
        text = body.decode()
        for needle in ("Integrity proof", "Result hash", "How the score was produced", "What would change the risk level", "Supporting guidance"):
            self.assertIn(needle, text)
        self.assertEqual(e.call("POST", "/api/v1/reports", "analyst", {"assessment_id": a["id"]})[0], 403)
        # 9 audit: correlated record exists and chain is intact
        s, aud = e.call("GET", "/api/v1/audit?correlation_id=demo-trace-0001", "admin")
        self.assertEqual([x["action"] for x in aud["items"]], ["report.generate"])
        self.assertTrue(e.call("GET", "/api/v1/audit/verify", "admin")[1]["ok"])

    def test_replay_detects_tampered_evidence_snapshot(self):
        e = seeded_env()
        aid = e.seed["assessment_id"]
        self.assertTrue(e.call("GET", f"/api/v1/assessments/{aid}/verify", "analyst")[1]["ok"])
        row = e.db.one("SELECT id, snapshot_json FROM assessment_runs WHERE assessment_id=?", (aid,))
        snap = json.loads(row["snapshot_json"])
        snap[0]["severity"] = "none"                                    # someone quietly softens an input
        e.db.execute("UPDATE assessment_runs SET snapshot_json=? WHERE id=?", (json.dumps(snap, sort_keys=True), row["id"]))
        v = e.call("GET", f"/api/v1/assessments/{aid}/verify", "analyst")[1]
        self.assertFalse(v["ok"])
        self.assertFalse(v["hash_match"])

    def test_replay_detects_tampered_stored_result(self):
        e = seeded_env()
        aid = e.seed["assessment_id"]
        e.db.execute("UPDATE assessment_runs SET result_hash=? WHERE assessment_id=?", ("0" * 64, aid))
        v = e.call("GET", f"/api/v1/assessments/{aid}/verify", "analyst")[1]
        self.assertFalse(v["ok"])
        self.assertFalse(v["ledger_entry_match"])                       # the ledger remembers the original hash

    def test_score_is_stable_across_reruns_with_same_inputs_and_clock(self):
        e = seeded_env()
        aid = e.seed["assessment_id"]
        r1 = e.call("POST", f"/api/v1/assessments/{aid}/run", "assessor")[1]
        r2 = e.call("POST", f"/api/v1/assessments/{aid}/run", "assessor")[1]
        self.assertEqual(r1["result_hash"], r2["result_hash"])

    def test_report_requires_a_run_and_archived_assessments_are_frozen(self):
        e = Env()
        v = e.vendor(); a = e.assessment(v["id"])
        self.assertEqual(e.call("POST", "/api/v1/reports", "assessor", {"assessment_id": a["id"]})[0], 409)
        s, b = e.call("POST", f"/api/v1/assessments/{a['id']}/run", "assessor")
        self.assertEqual((s, b["result"]["status"]), (200, "insufficient_evidence"))   # no evidence -> no score, not zero
        self.assertIsNone(b["result"]["score"])
        e.db.execute("UPDATE assessments SET status='archived' WHERE id=?", (a["id"],))
        self.assertEqual(e.call("POST", f"/api/v1/assessments/{a['id']}/run", "assessor")[0], 409)
        self.assertEqual(e.call("POST", f"/api/v1/assessments/{a['id']}/findings", "analyst", {"title": "t", "factor": "threat", "severity": "low", "source": "s", "confidence": 0.5, "observed_at": "2026-11-01T00:00:00Z"})[0], 409)

    def test_finding_asset_must_belong_to_same_vendor(self):
        e = Env()
        v1, v2 = e.vendor(), e.vendor(name="Other", domain="other.example")
        s, asset = e.call("POST", "/api/v1/assets", "assessor", {"vendor_id": v2["id"], "name": "x", "type": "host", "identifier": "other.example", "environment": "production", "exposure": "internal"})
        a = e.assessment(v1["id"])
        s, b = e.call("POST", f"/api/v1/assessments/{a['id']}/findings", "analyst", {"title": "t", "factor": "threat", "severity": "low", "source": "s", "confidence": 0.5, "observed_at": "2026-11-01T00:00:00Z", "asset_id": asset["id"]})
        self.assertEqual(s, 422)

    def test_health_endpoints(self):
        e = Env()
        self.assertEqual(e.call("GET", "/health/live")[1], {"status": "alive"})
        s, b = e.call("GET", "/health/ready")
        self.assertEqual((s, b["status"], b["database"], b["schema_version"]), (200, "ready", "ok", 2))
        e.db.close()
        self.assertEqual(e.call("GET", "/health/ready")[0], 503)

    def test_metrics_endpoint_requires_admin_and_reports_counts(self):
        e = Env()
        e.call("GET", "/api/v1/vendors", "analyst")
        self.assertEqual(e.call("GET", "/metrics", "analyst")[0], 403)
        s, h, body = e.call("GET", "/metrics", "admin", raw=True)
        self.assertEqual(s, 200)
        self.assertIn("http_requests_total", body.decode())


class LiveServerTests(unittest.TestCase):
    """Real sockets: static UI, security headers, login and an authenticated call."""

    @classmethod
    def setUpClass(cls):
        cls.e = Env()
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(cls.e.app))
        cls.port = cls.httpd.server_address[1]
        cls.t = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.t.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown(); cls.httpd.server_close()

    def req(self, path, method="GET", body=None, token=None):
        r = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", method=method, data=None if body is None else json.dumps(body).encode(),
                                   headers={"Content-Type": "application/json", **({"Authorization": "Bearer " + token} if token else {})})
        try:
            with urllib.request.urlopen(r, timeout=5) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers), exc.read()

    def test_ui_assets_and_headers(self):
        s, h, b = self.req("/")
        self.assertEqual(s, 200)
        self.assertIn(b"/app.js", b)
        self.assertIn("default-src 'self'", h["Content-Security-Policy"])
        self.assertEqual(self.req("/app.js")[0], 200)
        self.assertEqual(self.req("/app.css")[0], 200)
        self.assertEqual(self.req("/../etc/passwd")[0], 404)
        self.assertEqual(self.req("/cyberrisk/config.py")[0], 404)       # only the allow-listed assets are served
        self.assertNotIn("Python", h.get("Server", ""))

    def test_login_then_authenticated_api_call_over_socket(self):
        s, _, b = self.req("/api/v1/auth/login", "POST", {"email": "analyst@test.example", "password": PW["analyst"]})
        self.assertEqual(s, 200)
        token = json.loads(b)["access_token"]
        s, _, b = self.req("/api/v1/me", token=token)
        self.assertEqual(json.loads(b)["role"], "analyst")
        self.assertEqual(self.req("/api/v1/vendors")[0], 401)


if __name__ == "__main__":
    unittest.main()
