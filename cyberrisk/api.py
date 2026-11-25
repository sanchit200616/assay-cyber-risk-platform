"""HTTP boundary: routing, authentication, server-side authorisation, validation, rate limiting,
correlation IDs, security headers. No business rules and no SQL here."""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from . import schema
from .config import Settings
from .errors import AppError, Forbidden, Invalid, NotFound, RateLimited, Unauthorized
from .observability import METRICS, correlation_id, event, log, new_correlation_id
from .security import tokens
from .security.rbac import Principal, principal_for_role
from .security.ratelimit import RateLimiter
from .service import Platform

WEB = Path(__file__).resolve().parent / "web"
STATIC = {"/": ("index.html", "text/html; charset=utf-8"), "/index.html": ("index.html", "text/html; charset=utf-8"),
          "/app.js": ("app.js", "text/javascript; charset=utf-8"), "/app.css": ("app.css", "text/css; charset=utf-8")}
_CID = re.compile(r"^[A-Za-z0-9_.\-]{8,64}$")


@dataclass
class Raw:
    status: int
    content_type: str
    body: bytes
    headers: dict = field(default_factory=dict)


@dataclass
class Ctx:
    app: "App"
    p: Platform
    principal: Principal | None
    params: dict
    query: dict
    body: object
    headers: dict

    @property
    def actor(self) -> str:
        return self.principal.email if self.principal else "anonymous"

    def q(self, key, default=None):
        v = self.query.get(key)
        return v[0] if v else default

    def int(self, key, default, lo=0, hi=1000) -> int:
        try:
            v = int(self.q(key, default))
        except ValueError:
            raise Invalid(f"query parameter '{key}' must be an integer")
        if not lo <= v <= hi:
            raise Invalid(f"query parameter '{key}' must be between {lo} and {hi}")
        return v

    def flag(self, key) -> bool:
        return self.q(key, "").lower() in ("1", "true", "yes")


class App:
    def __init__(self, platform: Platform, settings: Settings, clock=time.monotonic):
        self.p, self.s = platform, settings
        self.rl_read = RateLimiter(settings.rate_limit_per_minute, clock=clock)
        self.rl_write = RateLimiter(max(1, settings.rate_limit_per_minute // 2), clock=clock)
        self.rl_login = RateLimiter(settings.login_limit_per_minute, clock=clock)
        self.routes: list = []
        self._register()

    # ----------------------------------------------------------------- routing table
    def route(self, method: str, pattern: str, perm: str | None, public: bool = False):
        rx = re.compile("^" + re.sub(r"\{(\w+)\}", r"(?P<\1>[A-Za-z0-9_\-]+)", pattern) + "$")

        def deco(fn):
            self.routes.append((method, rx, perm, public, fn))
            return fn
        return deco

    def _register(self):
        r, v1 = self.route, "/api/v1"
        P = self.p

        @r("GET", "/health/live", None, public=True)
        def live(c): return {"status": "alive"}

        @r("GET", "/health/ready", None, public=True)
        def ready(c):
            db_ok = P.db.ping()
            body = {"status": "ready" if db_ok else "degraded", "database": "ok" if db_ok else "unreachable",
                    "schema_version": P.db.schema_version() if db_ok else None, "environment": self.s.app_env,
                    "ephemeral_secret": self.s.secret_is_ephemeral}
            return (200 if db_ok else 503), body

        @r("GET", "/metrics", "metrics.read")
        def metrics(c): return Raw(200, "text/plain; version=0.0.4", METRICS.render().encode())

        @r("POST", f"{v1}/auth/login", None, public=True)
        def login(c):
            d = schema.validate(c.body, schema.LOGIN)
            ip = c.headers.get("x-client-ip", "?")
            ok, wait = self.rl_login.allow(f"{ip}:{d['email'].lower()}")
            if not ok:
                raise RateLimited(f"too many login attempts; retry in {int(wait) + 1}s")
            user = P.authenticate(d["email"], d["password"])
            if not user:
                P.ledger.append(d["email"][:80], "auth.login", "-", "denied")
                METRICS.inc("auth_failures_total")
                raise Unauthorized("invalid credentials")
            token = tokens.issue(self.s.secret_key, user["id"], user["role"], self.s.token_ttl_minutes * 60)
            P.ledger.append(user["email"], "auth.login", user["id"])
            return {"access_token": token, "token_type": "bearer", "expires_in": self.s.token_ttl_minutes * 60,
                    "user": {"id": user["id"], "email": user["email"], "role": user["role"]}}

        @r("GET", f"{v1}/me", None)
        def me(c): return {"id": c.principal.id, "email": c.principal.email, "role": c.principal.role,
                           "permissions": sorted(c.principal.permissions)}

        @r("GET", f"{v1}/dashboard", "dashboard.read")
        def dash(c): return P.dashboard()

        # vendors / assets
        @r("GET", f"{v1}/vendors", "vendors.read")
        def vendors(c): return {"items": P.list_vendors(c.q("q"), c.int("limit", 100), c.int("offset", 0))}

        @r("POST", f"{v1}/vendors", "vendors.write")
        def vendor_new(c): return 201, P.create_vendor(schema.validate(c.body, schema.VENDOR), c.actor)

        @r("GET", f"{v1}/vendors/{{id}}", "vendors.read")
        def vendor_get(c): return P.get_vendor(c.params["id"])

        @r("PATCH", f"{v1}/vendors/{{id}}", "vendors.write")
        def vendor_patch(c): return P.update_vendor(c.params["id"], schema.validate(c.body, schema.VENDOR_PATCH, partial=True), c.actor)

        @r("GET", f"{v1}/vendors/{{id}}/intelligence", "intel.read")
        def vendor_intel(c): return {"items": P.vendor_intel(c.params["id"])}

        @r("GET", f"{v1}/assets", "assets.read")
        def assets(c): return {"items": P.list_assets(c.q("vendor_id"))}

        @r("POST", f"{v1}/assets", "assets.write")
        def asset_new(c): return 201, P.create_asset(schema.validate(c.body, schema.ASSET), c.actor)

        # assessments
        @r("GET", f"{v1}/assessments", "assessments.read")
        def asm_list(c): return {"items": P.list_assessments(c.q("vendor_id"), c.q("status"))}

        @r("POST", f"{v1}/assessments", "assessments.write")
        def asm_new(c):
            d = schema.validate(c.body, schema.ASSESSMENT)
            return 201, P.create_assessment(d["vendor_id"], d["title"], c.actor)

        @r("GET", f"{v1}/assessments/{{id}}", "assessments.read")
        def asm_get(c): return P.get_assessment(c.params["id"])

        @r("POST", f"{v1}/assessments/{{id}}/run", "assessments.run")
        def asm_run(c):
            if c.flag("async"):
                job = P.enqueue("risk_assessment", {"assessment_id": c.params["id"], "actor": c.actor}, c.headers.get("idempotency-key"))
                return 202, job
            out = P.run_assessment(c.params["id"], c.actor)
            return {"run_id": out["run_id"], "result_hash": out["result_hash"], "ledger_seq": out["ledger_seq"], "result": out["result"]}

        @r("GET", f"{v1}/assessments/{{id}}/verify", "assessments.read")
        def asm_verify(c): return P.verify_run(c.params["id"], c.q("run_id"))

        @r("POST", f"{v1}/assessments/{{id}}/findings", "findings.write")
        def finding_new(c): return 201, P.add_finding(c.params["id"], schema.validate(c.body, schema.FINDING), c.actor)

        @r("PATCH", f"{v1}/findings/{{id}}", "findings.write")
        def finding_patch(c): return P.update_finding(c.params["id"], schema.validate(c.body, schema.FINDING_PATCH, partial=True), c.actor)

        @r("GET", f"{v1}/findings/{{id}}/evidence", "assessments.read")
        def evidence_list(c): return {"items": P.list_evidence(c.params["id"])}

        @r("POST", f"{v1}/evidence", "evidence.write")
        def evidence_new(c): return 201, P.add_evidence(schema.validate(c.body, schema.EVIDENCE), c.actor)

        # intelligence
        @r("POST", f"{v1}/intelligence/collect", "intel.collect")
        def collect(c):
            d = schema.validate(c.body, schema.COLLECT)
            if d["source"] == "inline" and not d.get("records"):
                raise Invalid("records are required for source 'inline'")
            if c.flag("async"):
                return 202, P.enqueue("intelligence_collect", {"source": d["source"], "records": d.get("records"), "actor": c.actor}, c.headers.get("idempotency-key"))
            return P.collect_intelligence(d["source"], d.get("records"), c.actor)

        @r("GET", f"{v1}/intelligence/signals", "intel.read")
        def signals(c): return {"items": P.list_indicators(c.q("q"), c.q("type"), c.int("limit", 100))}

        # documents / RAG
        @r("POST", f"{v1}/documents", "documents.write")
        def doc_new(c):
            d = schema.validate(c.body, schema.DOCUMENT)
            payload = {"title": d["title"], "content": d["content"], "source": d.get("source", f"upload:{c.actor}"), "media_type": d.get("media_type", "text/markdown")}
            if c.flag("async"):
                return 202, P.enqueue("rag_ingest", payload, c.headers.get("idempotency-key"))
            return 201, P.ingest_document(**payload)

        @r("GET", f"{v1}/documents", "rag.query")
        def doc_list(c):
            return {"items": [dict(zip(r.keys(), tuple(r))) for r in P.db.all(
                "SELECT d.id,d.title,d.source,d.media_type,d.size_bytes,d.synthetic,d.created_at,(SELECT COUNT(*) FROM chunks c WHERE c.document_id=d.id) chunks FROM documents d ORDER BY d.title")]}

        @r("POST", f"{v1}/rag/query", "rag.query")
        def rag_query(c):
            d = schema.validate(c.body, schema.RAGQ)
            return P.rag.query(d["question"], d.get("top_k", 4))

        # workflows
        @r("GET", f"{v1}/workflows", "workflows.read")
        def wf_list(c): return {"items": P.list_workflows(c.q("assessment_id"))}

        @r("POST", f"{v1}/workflows", "workflows.write")
        def wf_new(c): return 201, P.create_workflow(schema.validate(c.body, schema.WORKFLOW), c.actor)

        @r("PATCH", f"{v1}/workflows/{{id}}", "workflows.write")
        def wf_patch(c): return P.update_workflow(c.params["id"], schema.validate(c.body, schema.WORKFLOW_PATCH, partial=True), c.actor)

        @r("GET", f"{v1}/workflows/{{id}}", "workflows.read")
        def wf_get(c): return P.get_workflow(c.params["id"])

        # reports
        @r("GET", f"{v1}/reports", "reports.read")
        def rep_list(c): return {"items": P.list_reports(c.q("assessment_id"))}

        @r("POST", f"{v1}/reports", "reports.write")
        def rep_new(c):
            d = schema.validate(c.body, schema.REPORT)
            if c.flag("async"):
                return 202, P.enqueue("report_generate", {"assessment_id": d["assessment_id"], "format": d.get("format", "markdown"), "actor": c.actor}, c.headers.get("idempotency-key"))
            return 201, P.generate_report(d["assessment_id"], d.get("format", "markdown"), c.actor, d.get("run_id"))

        @r("GET", f"{v1}/reports/{{id}}", "reports.read")
        def rep_get(c): return P.get_report(c.params["id"], with_content=c.flag("content"))

        @r("GET", f"{v1}/reports/{{id}}/download", "reports.read")
        def rep_dl(c):
            rep = P.get_report(c.params["id"])
            ext, ctype = ("md", "text/markdown; charset=utf-8") if rep["format"] == "markdown" else ("html", "text/html; charset=utf-8")
            return Raw(200, ctype, rep["content"].encode(), {"Content-Disposition": f'attachment; filename="risk-report-{rep["id"]}.{ext}"',
                                                             "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox"})

        # jobs
        @r("GET", f"{v1}/jobs", "jobs.read")
        def jobs(c): return {"items": P.jobs.list(c.int("limit", 50)), "stats": P.jobs.stats()}

        @r("GET", f"{v1}/jobs/{{id}}", "jobs.read")
        def job_get(c):
            j = P.jobs.get(c.params["id"])
            if not j:
                raise NotFound("job not found")
            return j

        @r("POST", f"{v1}/jobs/run-pending", "jobs.run")
        def job_run(c):
            P.ledger.append(c.actor, "jobs.run_pending")
            return {"results": P.jobs.run_pending(P.handlers(), 25)}

        @r("POST", f"{v1}/jobs/{{id}}/retry", "jobs.run")
        def job_retry(c):
            j = P.jobs.retry(c.params["id"])
            if not j:
                raise NotFound("job not found")
            return j

        # admin
        @r("GET", f"{v1}/audit", "audit.read")
        def audit(c): return {"items": P.ledger.list(c.int("limit", 100), c.q("correlation_id")), "head": P.ledger.head()}

        @r("GET", f"{v1}/audit/verify", "audit.read")
        def audit_verify(c): return P.ledger.verify()

        @r("POST", f"{v1}/users", "users.manage")
        def user_new(c):
            d = schema.validate(c.body, schema.USER)
            return 201, P.create_user(d["email"], d["password"], d["role"], c.actor)

        @r("POST", f"{v1}/api-keys", "apikeys.manage")
        def key_new(c):
            d = schema.validate(c.body, schema.APIKEY)
            return 201, P.create_api_key(d["name"], d["scopes"], c.principal.id)

        @r("GET", f"{v1}/api-keys", "apikeys.manage")
        def key_list(c): return {"items": P.list_api_keys()}

        @r("DELETE", f"{v1}/api-keys/{{id}}", "apikeys.manage")
        def key_revoke(c): return P.revoke_api_key(c.params["id"], c.actor)

    # ----------------------------------------------------------------- request handling
    def _authenticate(self, headers: dict) -> Principal | None:
        auth = headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            try:
                claims = tokens.verify(self.s.secret_key, auth[7:].strip())
            except tokens.TokenError:
                raise Unauthorized("invalid or expired token")
            user = self.p.get_user(claims["sub"])  # re-check on every request: disabled users lose access immediately
            if not user or user["status"] != "active":
                raise Unauthorized("account is not active")
            return principal_for_role(user["id"], user["email"], user["role"])
        key = headers.get("x-api-key")
        if key:
            pr = self.p.authenticate_api_key(key)
            if not pr:
                raise Unauthorized("invalid or revoked API key")
            return pr
        return None

    def handle(self, method: str, raw_path: str, headers: dict | None = None, body: bytes = b"", client_ip: str = "-"):
        headers = {k.lower(): v for k, v in (headers or {}).items()}
        headers["x-client-ip"] = client_ip
        rid = headers.get("x-request-id", "")
        cid = rid if _CID.match(rid) else new_correlation_id()
        token = correlation_id.set(cid)
        start = time.perf_counter()
        status, route_label = 500, "unmatched"
        try:
            parts = urlsplit(raw_path)
            path, query = parts.path, parse_qs(parts.query)
            if method == "GET" and path in STATIC:
                fname, ctype = STATIC[path]
                status, route_label = 200, path
                return self._finish(200, {"Content-Type": ctype, "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"},
                                    (WEB / fname).read_bytes(), cid)
            handler = None
            path_known = False
            for m, rx, perm, public, fn in self.routes:
                mt = rx.match(path)
                if mt:
                    path_known = True
                    if m == method:
                        handler, params, need, is_public, route_label = fn, mt.groupdict(), perm, public, f"{m} {rx.pattern}"
                        break
            if handler is None:
                raise _MethodNotAllowed("method not allowed") if path_known else NotFound("route not found")
            principal = None if is_public and not headers.get("authorization") and not headers.get("x-api-key") else self._authenticate(headers)
            if not is_public and principal is None:
                raise Unauthorized("authentication required")
            who = principal.id if principal else f"ip:{client_ip}"
            ok, wait = (self.rl_read if method == "GET" else self.rl_write).allow(who)
            if not ok:
                METRICS.inc("rate_limited_total")
                raise RateLimited(f"rate limit exceeded; retry in {int(wait) + 1}s")
            if need and not principal.can(need):  # deny by default; frontend hiding is never relied upon
                self.p.ledger.append(principal.email, "authz.denied", f"{method} {path}", "denied", {"needs": need})
                METRICS.inc("authz_denied_total")
                raise Forbidden(f"missing permission '{need}'")
            data = None
            if method in ("POST", "PATCH", "PUT") and body:
                if len(body) > self.s.max_body_bytes:
                    raise _TooLarge("request body too large")
                try:
                    data = json.loads(body.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    raise Invalid("request body is not valid JSON")
            elif method in ("POST", "PATCH") and not body:
                data = {}
            out = handler(Ctx(self, self.p, principal, params, query, data, headers))
            if isinstance(out, Raw):
                status = out.status
                return self._finish(out.status, {"Content-Type": out.content_type, **out.headers}, out.body, cid)
            code, payload = out if isinstance(out, tuple) else (200, out)
            status = code
            return self._finish(code, {"Content-Type": "application/json"}, json.dumps(payload, default=str).encode(), cid)
        except AppError as exc:
            status = exc.status
            err = {"error": {"code": exc.code, "message": exc.message, "details": exc.details, "correlation_id": cid}}
            return self._finish(exc.status, {"Content-Type": "application/json"}, json.dumps(err).encode(), cid)
        except Exception:  # noqa: BLE001 - never leak internals to clients
            log.exception("unhandled error")
            status = 500
            err = {"error": {"code": "internal_error", "message": "unexpected server error", "correlation_id": cid}}
            return self._finish(500, {"Content-Type": "application/json"}, json.dumps(err).encode(), cid)
        finally:
            dur = time.perf_counter() - start
            METRICS.inc("http_requests_total", route=route_label, status=str(status))
            METRICS.observe("http_request", dur, route=route_label)
            event("http.request", method=method, path=raw_path.split("?")[0], status=status, duration_ms=round(dur * 1000, 2))
            correlation_id.reset(token)

    @staticmethod
    def _finish(status: int, headers: dict, body: bytes, cid: str):
        headers = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
                   "Referrer-Policy": "no-referrer", "X-Request-ID": cid, **headers}
        return status, headers, body


class _MethodNotAllowed(AppError):
    status, code = 405, "method_not_allowed"


class _TooLarge(AppError):
    status, code = 413, "payload_too_large"
